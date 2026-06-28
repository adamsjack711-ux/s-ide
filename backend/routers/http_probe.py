"""HTTP Probe — streaming common-path fuzz + method enum + header analysis.

WS  /ws/http-probe
    client -> server:
        {"url": "https://target.example.com",
         "wordlist": "small"|"medium",
         "max_concurrency": 16,           # optional
         "confirm": false}

    server -> client:
        {"type":"started",   "base", "host", "scheme", "methods_allowed":[...],
                              "wordlist_size", "headers": {...}}
        {"type":"finding",   "severity", "label", "detail"}
        {"type":"hit",       "path", "status", "length", "location"}
        {"type":"progress",  "done", "total", "hits"}
        {"type":"done",      "elapsed", "hits", "stopped"}
        {"type":"error",     "detail", "need_confirm"?}

The intent: surface common misconfigurations and exposed paths quickly. We
do HEAD by default to keep volume low; we GET on the first miss so we can
see WAF/redirect behaviour, and we GET for /robots.txt explicitly.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import ssl
import time
from typing import Any
from urllib.parse import urlparse, urlsplit

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import hids_notify
from lib.errors import ErrorCode, MhpError, ws_error
from lib import scope
from lib.mode import get_mode
from lib.target_policy import check_target
from lib.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["http-probe"])


# Common paths worth checking. Kept short — additions are cheap.
PATHS_SMALL = [
    "/", "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.env", "/.env.local", "/.env.production",
    "/wp-admin/", "/wp-login.php", "/wp-config.php",
    "/admin", "/admin/", "/administrator/", "/login", "/login/",
    "/phpmyadmin/", "/pma/", "/adminer.php",
    "/server-status", "/server-info", "/info.php", "/phpinfo.php",
    "/.well-known/security.txt",
    "/.DS_Store",
    "/swagger.json", "/swagger-ui/", "/openapi.json", "/api/", "/api/v1/",
    "/graphql", "/graphiql",
    "/jenkins/", "/grafana/", "/kibana/",
    "/.htaccess", "/.htpasswd",
    "/backup", "/backup/", "/backup.sql", "/backup.zip", "/dump.sql",
    "/config.json", "/config.yml", "/config.yaml",
]

PATHS_MEDIUM = PATHS_SMALL + [
    "/test", "/test/", "/dev/", "/staging/", "/old/", "/new/", "/tmp/",
    "/console", "/console/", "/manage", "/manager/html",
    "/.svn/entries", "/.hg/store", "/CVS/Root",
    "/.idea/", "/.vscode/",
    "/composer.json", "/composer.lock", "/package.json", "/yarn.lock",
    "/Dockerfile", "/docker-compose.yml",
    "/cgi-bin/", "/scripts/", "/uploads/", "/images/",
    "/static/", "/assets/", "/public/", "/files/", "/download/",
    "/api/swagger", "/api/docs", "/api/health", "/api/status",
    "/health", "/healthz", "/status", "/metrics", "/ping",
    "/users", "/users/", "/user/", "/profile", "/account",
    "/setup", "/setup/", "/install", "/install.php",
    "/.aws/credentials", "/.ssh/id_rsa", "/etc/passwd",  # never finds but signals path traversal probes
    "/web.config", "/global.asax",
    "/.gitlab-ci.yml", "/.travis.yml",
    "/sftp-config.json", "/sftpconfig.json",
]

INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 501, 502, 503}
DANGEROUS_PATHS_PREFIXES = (
    "/.git", "/.env", "/.aws/", "/.ssh/", "/etc/", "/.svn", "/.hg",
    "/.htpasswd", "/wp-config", "/dump", "/backup",
)


def _parse_url(raw: str) -> tuple[str, str, int, str]:
    """Return (scheme, host, port, base_path)."""
    u = urlsplit(raw if "://" in raw else "https://" + raw)
    scheme = (u.scheme or "https").lower()
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    base = u.path.rstrip("/") or ""
    return scheme, host, port, base


def _http_request(
    scheme: str, host: str, port: int, path: str, *, method: str = "HEAD",
    timeout: float = 4.0, follow_redirects: bool = False,
) -> tuple[int | None, dict[str, str], int, str]:
    """Sync HTTP request — used inside asyncio.to_thread. Returns (status, headers_lower, body_len, error)."""
    import http.client
    try:
        if scheme == "https":
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request(method, path or "/", headers={
                "Host": host,
                "User-Agent": "network-tools/0.1 (+local)",
                "Accept": "*/*",
                "Connection": "close",
            })
            resp = conn.getresponse()
            body = b""
            if method != "HEAD":
                try:
                    body = resp.read()
                except Exception:
                    body = b""
            headers = {k.lower(): v for k, v in resp.getheaders()}
            cl = int(headers.get("content-length", "0") or 0) or len(body)
            return resp.status, headers, cl, ""
        finally:
            conn.close()
    except Exception as exc:
        return None, {}, 0, str(exc)


@router.websocket("/ws/http-probe")
async def http_probe_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set(); return
        except WebSocketDisconnect:
            stop.set()
        except Exception:
            stop.set()

    try:
        init = await ws.receive_json()
        raw_url = str(init.get("url", "")).strip()
        wordlist_key = str(init.get("wordlist", "small"))
        try:
            concurrency = max(1, min(int(init.get("max_concurrency", 16)), 32))
        except (TypeError, ValueError):
            concurrency = 16
        confirm = bool(init.get("confirm", False))
        engagement_id = init.get("engagement_id") or None
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )

        # `validate_url` enforces length + http(s) scheme + valid host. If
        # the caller passed a bare hostname we tolerate it (legacy behaviour)
        # by prepending https:// and re-running.
        if raw_url and "://" not in raw_url:
            raw_url = "https://" + raw_url
        try:
            url = validate_url(raw_url, field="url")
        except MhpError as exc:
            await ws.send_json(ws_error(exc.code, exc.message))
            await ws.close(); return

        scheme, host, port, base = _parse_url(url)
        if not host:
            await ws.send_json(ws_error(
                ErrorCode.INVALID_URL,
                f"could not parse host from {url!r}",
            ))
            await ws.close(); return

        if not await scope.enforce_ws(ws, host, engagement_id, mode, confirm=confirm):
            return

        listener = asyncio.create_task(listen_for_stop())
        try:
            # Step 1 — OPTIONS for method enum + baseline headers
            status, headers, _, err = await asyncio.to_thread(
                _http_request, scheme, host, port, base + "/",
                method="OPTIONS", timeout=5.0,
            )
            methods: list[str] = []
            allow = headers.get("allow", "")
            if allow:
                methods = [m.strip().upper() for m in allow.split(",") if m.strip()]

            # If OPTIONS rejected, fall back to a GET / to learn headers
            base_headers = headers
            get_err = ""
            if status is None or status >= 500 or not headers:
                status_g, headers_g, _, get_err = await asyncio.to_thread(
                    _http_request, scheme, host, port, base + "/",
                    method="GET", timeout=5.0,
                )
                if headers_g:
                    base_headers = headers_g
                    status = status_g

            # If we still couldn't reach the target, bail before the path probe
            if status is None and not base_headers:
                detail = (err or get_err or "connection failed").splitlines()[0][:200]
                await ws.send_json(ws_error(
                    ErrorCode.UPSTREAM_FAILED,
                    f"could not reach {host}:{port} — {detail}",
                    target=host,
                ))
                return

            wordlist = PATHS_MEDIUM if wordlist_key == "medium" else PATHS_SMALL
            total = len(wordlist)

            # SPA / catch-all probe.
            #
            # Single-page apps (Juice Shop, modern React/Vue/Angular apps)
            # serve the same index.html for any path the client-side router
            # doesn't recognise. Without detecting this we report every
            # wordlist entry as "Sensitive path exposed" — 13 false-positive
            # highs on Juice Shop, observed 2026-06-13.
            #
            # Fix: request a path that cannot possibly exist on a real
            # backend. If that returns 200, record the (status, length)
            # signature; any subsequent hit matching that signature is the
            # SPA fallback, not a real exposure.
            bogus_path = f"/_mhp_probe_{secrets.token_hex(6)}"
            spa_status, spa_headers, spa_len, _ = await asyncio.to_thread(
                _http_request, scheme, host, port, base + bogus_path,
                method="HEAD", timeout=4.0,
            )
            spa_signature: tuple[int, int] | None = None
            if spa_status == 200 and spa_len > 0:
                spa_signature = (spa_status, spa_len)

            await ws.send_json({
                "type": "started",
                "base": f"{scheme}://{host}:{port}{base}",
                "host": host, "scheme": scheme,
                "methods_allowed": methods,
                "wordlist_size": total,
                "spa_fallback": (
                    {"status": spa_signature[0], "length": spa_signature[1]}
                    if spa_signature else None
                ),
                "headers": {k: base_headers.get(k, "") for k in (
                    "server", "x-powered-by", "strict-transport-security",
                    "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy",
                    "permissions-policy", "via",
                ) if base_headers.get(k)},
            })

            # Pre-emit header-based findings
            await _emit_security_findings(ws, base_headers, scheme)

            if spa_signature:
                await ws.send_json({
                    "type": "finding", "severity": "info",
                    "label": "Catch-all 200 response detected",
                    "detail": (
                        f"Bogus path {bogus_path} returned 200 "
                        f"({spa_signature[1]} bytes). Likely a single-page "
                        f"app — hits with the same size are flagged as "
                        f"spa-fallback and suppressed from sensitive-path "
                        f"findings."
                    ),
                })

            # Step 2 — concurrent path probe
            sem = asyncio.Semaphore(concurrency)
            done = 0
            hits = 0
            t0 = time.monotonic()

            async def probe(p: int, path: str) -> None:
                nonlocal done, hits
                if stop.is_set():
                    return
                full = (base + path) if not path.startswith("/") else path if not base else (base + path)
                async with sem:
                    if stop.is_set():
                        return
                    status, headers, length, err = await asyncio.to_thread(
                        _http_request, scheme, host, port, full,
                        method="HEAD", timeout=4.0,
                    )
                done += 1
                # A hit is "SPA fallback" if it matches the catch-all signature
                # we captured pre-loop. Allow a small slop (2% or 64 bytes) for
                # CSRF tokens / nonces that shift the body length slightly.
                is_spa_fallback = (
                    spa_signature is not None
                    and status == spa_signature[0]
                    and abs(length - spa_signature[1]) <= max(64, spa_signature[1] // 50)
                )
                if status is None:
                    pass
                elif status in INTERESTING_STATUSES:
                    hits += 1
                    location = headers.get("location", "")
                    await ws.send_json({
                        "type": "hit",
                        "path": full,
                        "status": status,
                        "length": length,
                        "location": location,
                        "spa_fallback": is_spa_fallback,
                    })
                    if (status == 200
                            and any(full.startswith(pre) for pre in DANGEROUS_PATHS_PREFIXES)
                            and not is_spa_fallback):
                        await ws.send_json({
                            "type": "finding", "severity": "high",
                            "label": "Sensitive path exposed",
                            "detail": f"{full} returned 200",
                        })
                        await hids_notify.notify(
                            "critical", "http-probe",
                            f"Sensitive path exposed — {host}{full}",
                            {"host": host, "path": full, "status": status},
                        )
                if done % 4 == 0 or done == total:
                    await ws.send_json({"type": "progress", "done": done,
                                        "total": total, "hits": hits})

            await asyncio.gather(*(probe(i, p) for i, p in enumerate(wordlist)),
                                 return_exceptions=True)

            elapsed = round(time.monotonic() - t0, 2)
            await ws.send_json({"type": "done", "elapsed": elapsed,
                                "hits": hits, "stopped": stop.is_set()})
            if not stop.is_set():
                await hids_notify.notify(
                    "info", "http-probe",
                    f"HTTP probe — {host}: {hits} hits / {total} paths",
                    {"host": host, "url": url, "hits": hits, "tried": total,
                     "elapsed_seconds": elapsed},
                )
        finally:
            listener.cancel()
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("http_probe_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during http probe",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass


async def _emit_security_findings(ws: WebSocket, headers: dict[str, str], scheme: str) -> None:
    """Emit header-based findings before the path probe starts."""
    checks: list[tuple[str, str, str, str]] = [
        ("strict-transport-security", "warn", "Missing HSTS",
         "Set Strict-Transport-Security on HTTPS responses"),
        ("x-content-type-options", "info", "Missing X-Content-Type-Options",
         "Should be 'nosniff'"),
        ("x-frame-options", "info", "Missing X-Frame-Options",
         "Or use frame-ancestors in CSP"),
        ("content-security-policy", "info", "Missing CSP",
         "Content-Security-Policy header not set"),
        ("referrer-policy", "info", "Missing Referrer-Policy",
         "Header not set"),
    ]
    for hdr, sev, label, detail in checks:
        if hdr not in headers:
            # HSTS only meaningful on HTTPS
            if hdr == "strict-transport-security" and scheme != "https":
                continue
            await ws.send_json({"type": "finding", "severity": sev,
                                "label": label, "detail": detail})
    server = headers.get("server", "")
    if server:
        await ws.send_json({"type": "finding", "severity": "info",
                            "label": f"Server header: {server}",
                            "detail": "Banner exposed (consider hiding in prod)"})
