"""Subdomain takeover detector.

For each candidate subdomain we:
  1. Resolve its CNAME chain.
  2. If the CNAME target matches a takeover-prone service, HTTP-probe the host
     and look for the service-specific "unclaimed" signature in the body.

Reference signature list: https://github.com/EdOverflow/can-i-take-over-xyz

REST  GET /takeover/check/{fqdn}?confirm=true&confirm_auth=true
WS    /ws/takeover-scan
      client -> server:
        {"subdomains": ["a.x.com", "b.x.com"], "confirm": false}
      server -> client:
        {"type":"started",  "count"}
        {"type":"result",   ...same shape as REST check}
        {"type":"progress", "done", "total", "hits"}
        {"type":"done",     "elapsed", "hits"}
        {"type":"error",    "detail", "need_confirm"?}

Verdicts per host:
  "vulnerable"   — CNAME matches signature AND body signature matched
  "dangling"     — CNAME matches signature, hostname unresolvable (likely vuln)
  "matched"      — CNAME matches signature, body did not match (likely owned)
  "no_cname"     — no CNAME, not interesting for takeover
  "clean"        — CNAME present, doesn't match any signature
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import subprocess
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect

from lib import audit_log, hids_notify, scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_engagement_id, get_mode
from lib.target_policy import check_target
from lib.validators import validate_hostname

logger = logging.getLogger(__name__)

router = APIRouter(tags=["takeover"], dependencies=[Depends(require_local_auth)])

import shutil as _shutil
DIG = _shutil.which("dig") or "/usr/bin/dig"


# (label, CNAME suffix list, body-signature list)
# Curated subset of can-i-take-over-xyz "vulnerable" entries.
SIGNATURES: list[tuple[str, list[str], list[str]]] = [
    ("S3 Bucket", ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
     ["NoSuchBucket", "The specified bucket does not exist"]),
    ("Heroku", ["herokuapp.com", "herokudns.com"],
     ["No such app", "There's nothing here, yet", "herokucdn.com/error-pages/no-such-app.html"]),
    ("GitHub Pages", ["github.io", "githubusercontent.com"],
     ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"]),
    ("Azure", ["cloudapp.net", "cloudapp.azure.com", "azurewebsites.net",
               "trafficmanager.net", "blob.core.windows.net"],
     ["404 Web Site not found", "Our services aren't available right now"]),
    ("Netlify", ["netlify.app", "netlify.com"],
     ["Not Found - Request ID:"]),
    ("Bitbucket", ["bitbucket.io"],
     ["Repository not found"]),
    ("Surge", ["surge.sh"],
     ["project not found"]),
    ("Tumblr", ["domains.tumblr.com"],
     ["Whatever you were looking for doesn't currently exist at this address"]),
    ("Shopify", ["myshopify.com"],
     ["Sorry, this shop is currently unavailable"]),
    ("Pantheon", ["pantheonsite.io"],
     ["The gods are wise, but do not know"]),
    ("Fastly", ["fastly.net"],
     ["Fastly error: unknown domain"]),
    ("Webflow", ["proxy-ssl.webflow.com", "proxy.webflow.com"],
     ["The page you are looking for doesn't exist or has been moved"]),
    ("Zendesk", ["zendesk.com"],
     ["Help Center Closed"]),
    ("Cargo", ["cargocollective.com"],
     ["404 Not Found"]),
    ("Unbounce", ["unbouncepages.com"],
     ["The requested URL was not found on this server"]),
    ("Vercel", ["vercel.app", "vercel.com", "now.sh"],
     ["The deployment could not be found on Vercel"]),
]


def _cname_chain(host: str) -> list[str]:
    """Follow CNAME records. Returns the chain (excluding host)."""
    try:
        r = subprocess.run(
            [DIG, "+short", "+time=2", "+tries=1", host, "CNAME"],
            capture_output=True, text=True, timeout=3.0,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    out = []
    for line in r.stdout.splitlines():
        target = line.strip().rstrip(".")
        if target:
            out.append(target)
    return out


def _resolves(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def _http_body(scheme: str, host: str, port: int, timeout: float = 5.0) -> str:
    import http.client
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout,
                context=ssl._create_unverified_context(),
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", "/", headers={
                "Host": host, "User-Agent": "network-tools/0.1 (+takeover)",
                "Accept": "*/*", "Connection": "close",
            })
            resp = conn.getresponse()
            return resp.read(64 * 1024).decode("utf-8", errors="replace")
        finally:
            conn.close()
    except Exception:
        return ""


def _match_signature(cname: str) -> tuple[str, list[str]] | None:
    cname_l = cname.lower()
    for label, suffixes, bodies in SIGNATURES:
        for sfx in suffixes:
            if cname_l.endswith("." + sfx) or cname_l == sfx or sfx in cname_l:
                return label, bodies
    return None


def _check_host(fqdn: str) -> dict[str, Any]:
    chain = _cname_chain(fqdn)
    base = {
        "fqdn": fqdn, "cname_chain": chain,
        "service": "", "signature_matched": False,
        "verdict": "no_cname",
        "evidence": "",
    }
    if not chain:
        return base

    last = chain[-1]
    match = _match_signature(last)
    if not match:
        base["verdict"] = "clean"
        return base

    label, bodies = match
    base["service"] = label

    # Is the CNAME target actually resolvable?
    if not _resolves(last):
        base["verdict"] = "dangling"
        base["evidence"] = f"CNAME → {last} does not resolve"
        return base

    # Fetch the body and look for the unclaimed signature
    for scheme, port in (("https", 443), ("http", 80)):
        body = _http_body(scheme, fqdn, port)
        if not body:
            continue
        for sig in bodies:
            if sig.lower() in body.lower():
                base["signature_matched"] = True
                base["verdict"] = "vulnerable"
                base["evidence"] = sig
                return base

    base["verdict"] = "matched"
    base["evidence"] = "CNAME pattern matched but no unclaimed signature in body"
    return base


# ── REST ──────────────────────────────────────────────────────────────────────

@router.get("/takeover/check/{fqdn}")
async def takeover_check(
    fqdn: str,
    request: Request,
    confirm: bool = Query(default=False),
    confirm_auth: bool = Query(default=False),
) -> dict[str, Any]:
    if not confirm_auth:
        raise HTTPException(
            status_code=403,
            detail="Confirm you have authorization to scan this subdomain.",
        )
    fqdn = validate_hostname(fqdn, field="fqdn", allow_ip=False)
    verdict, reason, _ = scope.enforce_rest(
        fqdn, get_engagement_id(request), get_mode(request), confirm=confirm,
    )

    res = await asyncio.to_thread(_check_host, fqdn)
    res["policy"] = {"verdict": verdict, "reason": reason}

    if res["verdict"] in ("vulnerable", "dangling"):
        await hids_notify.notify(
            "critical" if res["verdict"] == "vulnerable" else "warning",
            "takeover",
            f"Subdomain takeover {res['verdict']} — {fqdn} → {res['service'] or 'unknown service'}",
            {"fqdn": fqdn, "service": res["service"],
             "cname_chain": res["cname_chain"], "verdict": res["verdict"],
             "evidence": res["evidence"]},
        )
    return res


# ── WS bulk ───────────────────────────────────────────────────────────────────

@router.websocket("/ws/takeover-scan")
async def takeover_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()
    audit_id: str | None = None

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
        engagement_id = init.get("engagement_id") or None
        if not bool(init.get("confirm_auth", False)):
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Confirm you have authorization to scan these subdomains.",
            ))
            await ws.close(); return
        subs = init.get("subdomains") or []
        confirm = bool(init.get("confirm", False))

        if not isinstance(subs, list) or not subs:
            await ws.send_json(ws_error(
                ErrorCode.VALIDATION_ERROR,
                "subdomains list is required",
            ))
            await ws.close(); return
        if len(subs) > 500:
            await ws.send_json(ws_error(
                ErrorCode.PAYLOAD_TOO_LARGE,
                "max 500 subdomains per scan",
            ))
            await ws.close(); return

        # Policy check on the first sub's apex domain — assume all share an apex
        try:
            sample = validate_hostname(str(subs[0]), field="subdomains[0]", allow_ip=False)
        except MhpError as exc:
            await ws.send_json(ws_error(exc.code, exc.message))
            await ws.close(); return
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        if not await scope.enforce_ws(ws, sample, engagement_id, mode, confirm=confirm):
            return

        listener = asyncio.create_task(listen_for_stop())
        try:
            total = len(subs)
            try:
                audit_id = audit_log.start(
                    tool="takeover_scan",
                    target=sample,
                    argv=[f"subdomains={total}"],
                    engagement_id=engagement_id,
                )
            except Exception:
                logger.exception("audit_log.start failed (scan continues)")
            await ws.send_json({"type": "started", "count": total,
                                "audit_id": audit_id})

            done = 0
            hits = 0
            t0 = time.monotonic()
            sem = asyncio.Semaphore(8)

            async def probe(s: str) -> None:
                nonlocal done, hits
                if stop.is_set():
                    return
                fqdn = s.strip().lower().rstrip(".")
                if not fqdn:
                    done += 1; return
                async with sem:
                    if stop.is_set():
                        return
                    res = await asyncio.to_thread(_check_host, fqdn)
                done += 1
                await ws.send_json({"type": "result", **res})
                if res["verdict"] in ("vulnerable", "dangling"):
                    hits += 1
                    if res["verdict"] == "vulnerable":
                        await hids_notify.notify(
                            "critical", "takeover",
                            f"Subdomain takeover vulnerable — {fqdn} → {res['service']}",
                            {"fqdn": fqdn, "service": res["service"],
                             "cname_chain": res["cname_chain"],
                             "evidence": res["evidence"]},
                        )
                if done % 5 == 0 or done == total:
                    await ws.send_json({"type": "progress",
                                        "done": done, "total": total, "hits": hits})

            await asyncio.gather(*(probe(s) for s in subs), return_exceptions=True)

            elapsed = round(time.monotonic() - t0, 2)
            await ws.send_json({"type": "done", "elapsed": elapsed,
                                "hits": hits, "stopped": stop.is_set()})
            if audit_id:
                summary = f"{hits} vulnerable / {total} subdomains, {elapsed}s"
                try:
                    if stop.is_set():
                        audit_log.stopped(audit_id, summary=summary)
                    else:
                        audit_log.complete(audit_id, summary=summary)
                except Exception:
                    logger.exception("audit_log finalize failed")
            if not stop.is_set():
                sev = "warning" if hits else "info"
                await hids_notify.notify(
                    sev, "takeover",
                    f"Takeover scan — {total} subdomains, {hits} vulnerable",
                    {"checked": total, "vulnerable": hits, "elapsed_seconds": elapsed},
                )
        finally:
            listener.cancel()
    except WebSocketDisconnect:
        stop.set()
        if audit_id:
            try: audit_log.stopped(audit_id, summary="client disconnected")
            except Exception: pass
    except Exception as exc:
        logger.exception("takeover_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during takeover scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
