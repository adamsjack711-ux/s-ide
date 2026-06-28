"""Ping — wraps `ping` as a WebSocket stream.

Protocol:
    client -> server:
        {"target": "8.8.8.8", "count": 0, "interval": 1.0}   // count=0 means infinite
        {"action": "stop"}

    server -> client:
        {"type": "started",  "target": "..."}
        {"type": "line",     "text": "64 bytes from 8.8.8.8: ..."}
        {"type": "done",     "stopped": bool}
        {"type": "error",    "detail": "..."}
"""
from __future__ import annotations

import asyncio
import logging
import shlex
from typing import Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_target

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ping"], dependencies=[Depends(require_local_auth)])


def _build_cmd(target: str, count: int, interval: float) -> list[str]:
    cmd: list[str] = ["ping"]
    if count > 0:
        cmd += ["-c", str(count)]
    if interval and interval >= 0.1:
        cmd += ["-i", str(interval)]
    cmd.append(target)
    return cmd


@router.websocket("/ws/ping")
async def ping_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()
    proc: asyncio.subprocess.Process | None = None

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
        init: dict[str, Any] = await ws.receive_json()
        target  = str(init.get("target", "")).strip()
        engagement_id = init.get("engagement_id") or None
        try:
            target = validate_target(target, field="target")
        except MhpError as exc:
            await ws.send_json(ws_error(exc.code, exc.message))
            await ws.close(); return
        try:
            count    = int(init.get("count", 0))
            interval = float(init.get("interval", 1.0))
        except (TypeError, ValueError):
            await ws.send_json(ws_error(
                ErrorCode.VALIDATION_ERROR,
                "count/interval must be numeric",
            ))
            await ws.close(); return

        # Scope check — combines target_policy (IP-class) + engagement scope,
        # gated by Lab/Engagement mode. Mode reads from the X-MHP-Mode header /
        # ?mode= query; the handshake `mode` field is honored as a final
        # override for tests. `confirm` lets the client re-send the handshake
        # after the user acknowledges a `warn` verdict.
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
            await ws.close(); return
        if sc_verdict == "warn" and not confirm:
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                sc_reason, target=target, need_confirm=True,
            ))
            await ws.close(); return

        listener = asyncio.create_task(listen_for_stop())
        cmd = _build_cmd(target, count, interval)
        await ws.send_json({"type": "started", "target": target,
                            "cmd": " ".join(shlex.quote(c) for c in cmd)})

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError:
            await ws.send_json(ws_error(ErrorCode.TOOL_MISSING, "ping not found"))
            return

        try:
            assert proc.stdout is not None
            while not stop.is_set():
                line = await proc.stdout.readline()
                if not line:
                    break
                await ws.send_json({"type": "line",
                                    "text": line.decode("utf-8", "replace").rstrip()})
        except Exception:
            pass
        finally:
            listener.cancel()
            if proc and proc.returncode is None:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except Exception:
                    try: proc.kill()
                    except Exception: pass

        await ws.send_json({"type": "done", "stopped": stop.is_set()})
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("ping_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during ping",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
