"""Port Scanner — WebSocket streaming endpoint.

Protocol:

    client -> server (once, on connect):
        {"target": "192.168.1.1", "ports": "1-1024",
         "timeout": 1.0, "threads": 100}

    server -> client:
        {"type": "started", "ip": "1.2.3.4", "target": "...", "total": 1024}
        {"type": "open",     "port": 22, "service": "SSH", "banner": "..."}
        {"type": "progress", "done": 256, "total": 1024}
        {"type": "done",     "elapsed": 5.2, "open_count": 5}
        {"type": "error",    "detail": "..."}

    client -> server (any time):
        {"action": "stop"}
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, hids_notify, scanner, scope
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_target

logger = logging.getLogger(__name__)

router = APIRouter(tags=["port-scanner"])


@router.websocket("/ws/port-scan")
async def port_scan_ws(ws: WebSocket) -> None:
    await ws.accept()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    scan_task: asyncio.Task | None = None

    async def listen_for_stop() -> None:
        """Background listener: drain inbound messages while scan runs."""
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set()
                    return
        except WebSocketDisconnect:
            stop.set()
        except Exception:
            stop.set()

    audit_id: str | None = None
    try:
        # Handshake message
        init: dict[str, Any] = await ws.receive_json()
        target  = str(init.get("target", "")).strip()
        ports_s = str(init.get("ports", "1-1024"))
        engagement_id = init.get("engagement_id") or None
        try:
            timeout = float(init.get("timeout", 1.0))
        except (TypeError, ValueError):
            timeout = 1.0
        try:
            n_threads = int(init.get("threads", 100))
        except (TypeError, ValueError):
            n_threads = 100

        try:
            target = validate_target(target, field="target")
        except MhpError as exc:
            await ws.send_json(ws_error(exc.code, exc.message))
            await ws.close()
            return

        # Scope check — combines target_policy (IP-class) + engagement scope,
        # gated by Lab/Engagement mode. Mode is resolved from the X-MHP-Mode
        # header / ?mode= query the frontend attaches via `openWs`; the
        # handshake `mode` field is honored as a final override for tests.
        # `confirm` lets the frontend re-send the handshake after the user
        # acknowledges a `warn` verdict; without it, we refuse to start.
        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        sc_verdict, sc_reason, sc_layers = scope.check_combined(
            target, engagement_id, mode,
        )
        await ws.send_json({
            "type": "scope", "target": target, "mode": mode,
            "verdict": sc_verdict, "reason": sc_reason, "layers": sc_layers,
        })
        if sc_verdict == "deny":
            await ws.send_json(ws_error(
                ErrorCode.TARGET_DENIED,
                f"scope check failed: {sc_reason}",
                target=target,
            ))
            await ws.close()
            return
        if sc_verdict == "warn" and not confirm:
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                sc_reason, target=target, need_confirm=True,
            ))
            await ws.close()
            return

        try:
            ports = scanner.parse_ports(ports_s)
        except ValueError as exc:
            await ws.send_json(ws_error(ErrorCode.INVALID_RANGE, str(exc)))
            await ws.close()
            return
        try:
            ip = scanner.resolve_host(target)
        except socket.gaierror as exc:
            await ws.send_json(ws_error(
                ErrorCode.RESOLVE_FAILED,
                f"cannot resolve '{target}': {exc}",
                target=target,
            ))
            await ws.close()
            return

        listener = asyncio.create_task(listen_for_stop())

        # Audit log: one row per scan invocation. Recorded after validation
        # so failures land as `error`, not `started`-and-then-orphaned.
        try:
            audit_id = audit_log.start(
                tool="port_scanner",
                target=f"{target} ({ip})",
                argv=["tcp-connect", f"--ports={ports_s}",
                      f"--threads={n_threads}", f"--timeout={timeout}"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (scan continues)")

        await ws.send_json({
            "type": "started",
            "target": target, "ip": ip,
            "total": len(ports),
            "threads": n_threads, "timeout": timeout,
            "audit_id": audit_id,
        })
        await asyncio.sleep(0)   # let the start event flush

        open_count = 0
        last_progress_at = 0.0

        def on_open(port: int, service: str, banner: str) -> None:
            nonlocal open_count
            open_count += 1
            asyncio.run_coroutine_threadsafe(
                ws.send_json({"type": "open", "port": port,
                              "service": service, "banner": banner}),
                loop,
            )

        def on_progress(done: int, total: int) -> None:
            nonlocal last_progress_at
            now = time.monotonic()
            # Throttle progress events to ~30/s to keep the WS pipe sane
            if done < total and now - last_progress_at < 0.033:
                return
            last_progress_at = now
            asyncio.run_coroutine_threadsafe(
                ws.send_json({"type": "progress", "done": done, "total": total}),
                loop,
            )

        def should_stop() -> bool:
            return stop.is_set()

        t0 = time.monotonic()
        scan_task = loop.run_in_executor(
            None,
            lambda: scanner.scan_stream(
                ip, ports, timeout, n_threads,
                on_open=on_open, on_progress=on_progress,
                should_stop=should_stop,
            ),
        )
        try:
            await scan_task
        finally:
            listener.cancel()

        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({
            "type": "done",
            "elapsed": elapsed,
            "open_count": open_count,
            "stopped": stop.is_set(),
        })
        if audit_id:
            summary = f"{open_count} open of {len(ports)} ports in {elapsed}s"
            try:
                if stop.is_set():
                    audit_log.stopped(audit_id, summary=summary)
                else:
                    audit_log.complete(audit_id, summary=summary)
            except Exception:
                logger.exception("audit_log finalize failed")
        if not stop.is_set():
            await hids_notify.notify(
                "info", "port-scan",
                f"Port scan complete — {open_count} open on {target}",
                {"target": target, "ip": ip,
                 "open_count": open_count,
                 "total_ports": len(ports),
                 "elapsed_seconds": elapsed},
            )
    except WebSocketDisconnect:
        stop.set()
        if audit_id:
            try: audit_log.stopped(audit_id, summary="client disconnected")
            except Exception: pass
    except Exception as exc:
        logger.exception("port_scan_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during port scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
