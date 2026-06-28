"""Preset / Playbook router.

Endpoints:
  GET    /presets              — list built-in + user presets
  GET    /presets/{id}         — full preset definition
  POST   /presets              — save a user preset
  DELETE /presets/{id}         — delete a user preset (built-ins cannot be deleted)
  GET    /presets/_meta/tools  — tools the engine knows how to invoke
  WS     /ws/preset-run        — execute a preset, streaming step+finding events
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from lib import preset_engine, scope
from lib.errors import ErrorCode, ws_error
from lib.mode import get_mode

logger = logging.getLogger(__name__)

router = APIRouter(tags=["presets"])


# ─────────────────────────────────────────────────────────────────────────────
# CRUD
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/presets")
def list_presets() -> dict[str, Any]:
    return {"presets": preset_engine.list_presets(),
            "tools":   preset_engine.known_tools()}


@router.get("/presets/_meta/tools")
def supported_tools() -> dict[str, Any]:
    return {"tools": preset_engine.known_tools()}


@router.get("/presets/{pid}")
def get_preset(pid: str) -> dict[str, Any]:
    p = preset_engine.get_preset(pid)
    if not p:
        raise HTTPException(404, f"preset {pid!r} not found")
    # Strip internal fields before returning to the client
    return {k: v for k, v in p.items() if not k.startswith("_")}


class SavePresetBody(BaseModel):
    id: str | None = None
    name: str
    description: str = ""
    target_type: str = "domain"
    steps: list[dict[str, Any]]


@router.post("/presets")
def save_preset(body: SavePresetBody) -> dict[str, Any]:
    try:
        out = preset_engine.save_preset(body.model_dump(exclude_none=True))
    except preset_engine.PresetError as e:
        raise HTTPException(400, str(e))
    return out


@router.delete("/presets/{pid}")
def delete_preset(pid: str) -> dict[str, bool]:
    # Built-ins are read-only — refuse rather than silently ignore.
    p = preset_engine.get_preset(pid)
    if p and p.get("_builtin"):
        raise HTTPException(403, "built-in presets cannot be deleted")
    ok = preset_engine.delete_preset(pid)
    if not ok:
        raise HTTPException(404, f"preset {pid!r} not found")
    return {"deleted": True}


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket runner
# ─────────────────────────────────────────────────────────────────────────────

@router.websocket("/ws/preset-run")
async def preset_run_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if not isinstance(msg, dict):
                    continue
                action = msg.get("action")
                if action == "stop":
                    # Push to pending_action too so a paused phase resumes
                    # cleanly with a stop verdict, then trip the stop event.
                    try: pending_action.put_nowait("stop")
                    except Exception: pass
                    stop.set()
                    return
                if action == "continue":
                    try: pending_action.put_nowait("continue")
                    except Exception: pass
        except WebSocketDisconnect:
            try: pending_action.put_nowait("stop")
            except Exception: pass
            stop.set()
        except Exception:
            try: pending_action.put_nowait("stop")
            except Exception: pass
            stop.set()

    listener: asyncio.Task | None = None
    # For v2 stop_on_critical: when the engine pauses, we await a JSON
    # control message from the client ("continue" or "stop") and forward
    # the decision back to the engine via wait_action.
    pending_action: asyncio.Queue[str] = asyncio.Queue()

    async def wait_action() -> str:
        # Block until the stop-listener receives an explicit action.
        try:
            return await pending_action.get()
        except Exception:
            return "stop"

    try:
        init = await ws.receive_json()
        preset_id = str(init.get("preset", "")).strip()
        target = str(init.get("target", "")).strip()
        authorized = bool(init.get("authorized", False))

        # Mode comes from the same X-MHP-Mode header / ?mode= query the rest
        # of the app uses; the handshake `mode` field is an override for tests.
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = (
            "engagement" if init_mode == "engagement"
            else "lab" if init_mode == "lab"
            else get_mode(ws)
        )

        if not preset_id:
            await ws.send_json(ws_error(ErrorCode.BAD_REQUEST, "preset id required"))
            return
        # Local-target bundles (posture audits, persistence enumeration) don't
        # need a target — the engine handles the requirement check itself.
        preset = preset_engine.get_preset(preset_id)
        target_type = (preset or {}).get("target_type", "domain")
        if target_type != "local" and not target:
            await ws.send_json(ws_error(ErrorCode.BAD_REQUEST, "target required"))
            return
        if not authorized:
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "authorization checkbox required: pass `authorized: true`",
            ))
            return

        # Top-level scope check on the playbook target. Each child tool
        # invoked by the engine also runs its own check (same helper),
        # but failing fast here saves the user a partial run + per-step
        # error spam. Local-target playbooks (posture audits) skip the
        # target match and just require an engagement under Engagement mode.
        engagement_id = init.get("engagement_id") or None
        confirm = bool(init.get("confirm", False))
        if target_type == "local":
            try:
                scope.enforce_engagement_present(engagement_id, mode)
            except Exception as exc:
                await ws.send_json(ws_error(
                    ErrorCode.TARGET_DENIED,
                    getattr(exc, "message", str(exc)),
                ))
                return
        else:
            if not await scope.enforce_ws(ws, target, engagement_id, mode, confirm=confirm):
                return

        listener = asyncio.create_task(listen_for_stop())

        async def emit(ev: dict[str, Any]) -> None:
            try:
                await ws.send_json(ev)
            except Exception:
                # Client gone — flip stop so the engine winds down gracefully.
                stop.set()

        await preset_engine.run_preset(
            preset_id, target, emit, stop,
            mode=mode, wait_action=wait_action,
        )
    except WebSocketDisconnect:
        stop.set()
    except Exception as exc:
        logger.exception("preset run failed")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                f"Preset run failed ({type(exc).__name__})",
            ))
        except Exception:
            pass
    finally:
        if listener and not listener.done():
            listener.cancel()
            try:
                await listener
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await ws.close()
        except Exception:
            pass
