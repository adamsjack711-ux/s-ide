"""Training labs — Docker-backed vulnerable apps to practice against.

The frontend Labs page polls these endpoints to drive the lab lifecycle
(build → start → stop). Long-running ``docker build`` is fired as a
background task and the UI polls ``/labs/{id}/status`` for the log tail.

All endpoints are gated by ``require_local_auth`` because they shell out
to ``docker`` (which is privileged on most setups).
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from lib import (
    audit_log,
    engagements as engagements_lib,
    labs as labs_lib,
    targets as targets_lib,
)
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError, ws_error

logger = logging.getLogger(__name__)

router = APIRouter(tags=["labs"], dependencies=[Depends(require_local_auth)])


def _require_lab(lab_id: str) -> None:
    if labs_lib.get_lab_def(lab_id) is None:
        raise MhpError(f"unknown lab: {lab_id}", code=ErrorCode.NOT_FOUND, status_code=404)


@router.get("/labs")
async def list_labs() -> dict[str, Any]:
    """List available labs along with a top-level docker availability flag.

    The UI uses ``docker_available`` to show an install hint when Docker is
    missing entirely, vs ``docker_running`` to show a "start Docker Desktop"
    hint when the binary exists but the daemon is down.
    """
    runtime = await labs_lib.detect_runtime()
    return {
        "labs":             labs_lib.list_labs(),
        "docker_available": labs_lib.docker_available(),
        "docker_running":   runtime["running"],
        "runtime":          runtime,
    }


@router.get("/labs/catalog")
async def labs_catalog() -> dict[str, Any]:
    """Full catalog — every defined lab tagged with its enabled state.

    Drives the "+ Add Lab" drawer. The main grid still hits ``/labs``
    which only returns enabled labs.
    """
    return {"labs": labs_lib.list_catalog()}


class LabEnableBody(BaseModel):
    enabled: bool = Field(...)


@router.post("/labs/{lab_id}/enable")
async def lab_enable(lab_id: str) -> dict[str, Any]:
    """Mark a lab as enabled so it appears in the main grid."""
    _require_lab(lab_id)
    labs_lib.set_enabled(lab_id, True)
    return {"id": lab_id, "enabled": True}


@router.post("/labs/{lab_id}/disable")
async def lab_disable(lab_id: str) -> dict[str, Any]:
    """Hide a lab from the main grid. Does not stop or delete anything."""
    _require_lab(lab_id)
    labs_lib.set_enabled(lab_id, False)
    return {"id": lab_id, "enabled": False}


@router.get("/labs/preflight")
async def lab_preflight() -> dict[str, Any]:
    """State-specific runtime check for the Labs Colima popup.

    Re-scans the Homebrew bin dirs on every call so the user can install
    colima and click Re-check without restarting the app. See
    ``labs_lib.preflight`` for the state taxonomy.
    """
    return await labs_lib.preflight()


@router.get("/labs/runtime/status")
async def runtime_status() -> dict[str, Any]:
    """Slim, banner-friendly view of ``preflight()`` for the app-shell banner.

    Same underlying state machine, but pre-computes the two booleans the
    UI banner switches on so the renderer never has to map the four states
    itself. Returned shape::

        {
          "state":         "ok" | "binary_missing" | "daemon_stopped" | "socket_unreachable",
          "needs_install": bool,   # state == binary_missing
          "needs_start":   bool,   # state in {daemon_stopped, socket_unreachable}
          "colima_path":   str | None,
          "docker_path":   str | None,
        }
    """
    pre = await labs_lib.preflight()
    state = pre.get("state", "binary_missing")
    return {
        "state":         state,
        "needs_install": state == "binary_missing",
        "needs_start":   state in {"daemon_stopped", "socket_unreachable"},
        "colima_path":   pre.get("colima_path"),
        "docker_path":   pre.get("docker_path"),
    }


@router.get("/labs/{lab_id}/status")
async def lab_status(lab_id: str) -> dict[str, Any]:
    _require_lab(lab_id)
    return await labs_lib.get_status(lab_id)


@router.post("/labs/{lab_id}/build")
async def lab_build(lab_id: str) -> dict[str, Any]:
    _require_lab(lab_id)
    result = await labs_lib.start_build(lab_id)
    if result.get("status") == "error":
        raise MhpError(result.get("error") or "build failed to start",
                       code=ErrorCode.TOOL_FAILED, status_code=503)
    return result


@router.post("/labs/{lab_id}/start")
async def lab_start(lab_id: str) -> dict[str, Any]:
    _require_lab(lab_id)
    result = await labs_lib.start_lab(lab_id)
    if result.get("status") == "error":
        raise MhpError(result.get("error") or "lab failed to start",
                       code=ErrorCode.TOOL_FAILED, status_code=503)
    _register_lab_targets(lab_id)
    return result


@router.post("/labs/{lab_id}/stop")
async def lab_stop(lab_id: str) -> dict[str, Any]:
    _require_lab(lab_id)
    result = await labs_lib.stop_lab(lab_id)
    if result.get("status") == "error":
        raise MhpError(result.get("error") or "lab failed to stop",
                       code=ErrorCode.TOOL_FAILED, status_code=503)
    targets_lib.hide_lab_targets(lab_id)
    return result


class LabAttachBody(BaseModel):
    """Attach a running lab to an engagement.

    The frontend posts ``engagement_id`` from its active-engagement state.
    """
    engagement_id: str = Field(..., min_length=1, max_length=64)


@router.post("/labs/{lab_id}/attach")
async def lab_attach(lab_id: str, body: LabAttachBody) -> dict[str, Any]:
    """Bind a running lab to an engagement.

    Effects (all idempotent):

      * Upserts one ``targets`` row per published port for the lab, bound to
        the engagement via ``engagement_id`` (cascade-deletes with it). The
        global lab target rows the auto-register hook creates on lab-start
        are left alone — this is a *parallel* binding, not a move.

      * Appends the lab's primary URL (``http://127.0.0.1:<host_port>``,
        falling back to ``primary_url``) to the engagement's ``scope`` list
        if not already present. The report header reads scope, so the lab's
        URL surfaces in the engagement export with no extra wiring.

      * Records the action in ``audit_log`` as
        ``tool="lab-attach", target=<lab_id>, engagement_id=<eid>`` so the
        engagement's append-only trust anchor knows when (and what) the
        operator attached.

    Returns ``{attached, targets_added, scope_entries_added, scope}``. Both
    counts are 0 on a re-attach that finds nothing new — the response is
    still 200 OK because the result state matches the request.
    """
    _require_lab(lab_id)
    lab = labs_lib.get_lab_def(lab_id)
    # _require_lab guarantees the def exists; satisfy the type checker.
    assert lab is not None

    eng = engagements_lib.get_engagement(body.engagement_id)
    if eng is None:
        raise MhpError(
            "engagement not found",
            code=ErrorCode.NOT_FOUND,
            status_code=404,
            extra={"engagement_id": body.engagement_id},
        )

    # Liveness check. Single-container labs need state="running". Compose
    # stacks are accepted on "running" OR "partial" — the LabCard also
    # treats partial as live because the sidecar might be the service that
    # IS up, and attach-to-engagement is the moment to capture that.
    status = await labs_lib.get_status(lab_id)
    container_state = (status.get("container") or {}).get("state")
    if lab.kind == "compose":
        comp_state = (status.get("compose") or {}).get("state")
        running = comp_state in ("running", "partial")
    else:
        running = container_state == "running"
    if not running:
        raise MhpError(
            f"lab '{lab_id}' is not running — start it first",
            code=ErrorCode.CONFLICT,
            status_code=409,
            extra={"container_state": container_state},
        )

    # Audit boundary: start the row early so a partial failure (e.g. DB
    # write hiccup mid-loop) still lands a "started" entry the operator
    # can reconcile against.
    aid = audit_log.start(
        tool="lab-attach",
        target=lab_id,
        argv=[lab_id, body.engagement_id],
        engagement_id=body.engagement_id,
    )
    try:
        # ── Targets ──
        # Upsert one row per published port. We probe ``find_by_meta`` first
        # so the response counter distinguishes "fresh insert" from "refresh
        # of an existing row" — we can't lean on ``added_at == last_seen_at``
        # because ``_now()`` is one-second precision and a re-attach inside
        # the same second would still match.
        targets_added = 0
        if not lab.port_map:
            # vulhub-net-style: no published ports. Emit one placeholder so
            # the Targets page can group the sidecar exec pathway under the
            # engagement too.
            pre_exists = targets_lib.find_by_meta(
                lab.id, host_port=0, engagement_id=body.engagement_id,
            ) is not None
            targets_lib.upsert_lab_target(
                lab_id=lab.id, lab_name=lab.name,
                host_port=0, container_port=0, primary_url="",
                engagement_id=body.engagement_id,
            )
            if not pre_exists:
                targets_added += 1
        else:
            for cport, hport in lab.port_map.items():
                pre_exists = targets_lib.find_by_meta(
                    lab.id, host_port=hport, engagement_id=body.engagement_id,
                ) is not None
                targets_lib.upsert_lab_target(
                    lab_id=lab.id, lab_name=lab.name,
                    host_port=hport, container_port=cport,
                    primary_url=lab.primary_url,
                    engagement_id=body.engagement_id,
                )
                if not pre_exists:
                    targets_added += 1

        # ── Scope ──
        # Append the lab's primary URL (or a synthesized 127.0.0.1:<port>
        # when ``primary_url`` isn't set) if not already present. Dedupe is
        # done in-process: scope is a list[str] without an index.
        new_entry = lab.primary_url or (
            f"http://127.0.0.1:{next(iter(lab.port_map.values()))}"
            if lab.port_map else ""
        )
        scope: list[str] = list(eng.get("scope") or [])
        scope_entries_added = 0
        if new_entry and new_entry not in scope:
            scope.append(new_entry)
            scope_entries_added += 1
            engagements_lib.update_engagement(body.engagement_id, {"scope": scope})

        audit_log.complete(
            aid,
            summary=(
                f"{lab.name} → {eng.get('name', body.engagement_id)} "
                f"(targets +{targets_added}, scope +{scope_entries_added})"
            ),
        )
        return {
            "attached":             True,
            "lab_id":               lab_id,
            "engagement_id":        body.engagement_id,
            "targets_added":        targets_added,
            "scope_entries_added":  scope_entries_added,
            "scope_entry":          new_entry,
            "scope":                scope,
        }
    except Exception as exc:
        audit_log.error(aid, f"{type(exc).__name__}: {exc}")
        raise


def _register_lab_targets(lab_id: str) -> None:
    """Upsert one target per published port_map entry.

    Compose labs with no published ports (vulhub-net) get one zero-port
    placeholder so the Targets page can still surface the sidecar exec
    pathway as a known target. Failures are swallowed — auto-register
    shouldn't break the lab start flow if the DB write hiccups.
    """
    lab = labs_lib.get_lab_def(lab_id)
    if lab is None:
        return
    try:
        if not lab.port_map:
            targets_lib.upsert_lab_target(
                lab_id=lab.id, lab_name=lab.name,
                host_port=0, container_port=0,
                primary_url="",
            )
            return
        for cport, hport in lab.port_map.items():
            targets_lib.upsert_lab_target(
                lab_id=lab.id, lab_name=lab.name,
                host_port=hport, container_port=cport,
                primary_url=lab.primary_url,
            )
    except Exception as exc:
        logger.warning("lab target auto-register failed for %s: %s", lab_id, exc)


class SidecarExecBody(BaseModel):
    cmd: str = Field(..., min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9_\-]+$")
    args: list[str] = Field(default_factory=list, max_length=32)
    timeout: float = Field(default=120, ge=1, le=600)


@router.post("/labs/{lab_id}/sidecar/exec")
async def lab_sidecar_exec(lab_id: str, body: SidecarExecBody) -> dict[str, Any]:
    """Run a whitelisted command inside the lab's scanner sidecar.

    The sidecar joins the lab's docker bridge so it can reach internal IPs
    that the macOS host can't. Used by the Labs UI's "Scan from inside the
    network" panel and (eventually) the Network Audit page.
    """
    _require_lab(lab_id)
    result = await labs_lib.sidecar_exec(lab_id, body.cmd, body.args, body.timeout)
    if result.get("rc", 1) < 0:
        # rc == -1 from our helper means validation / setup error — not a
        # tool-failed result. Surface it as 400 so the UI shows the reason.
        raise MhpError(result.get("stderr") or "sidecar exec failed",
                       code=ErrorCode.BAD_REQUEST, status_code=400)
    return result


# ── Runtime installer (one-click colima setup) ─────────────────────────────
#
# Streaming WS endpoint that drives the "Install & start colima" banner.
# We deliberately:
#
#   * NEVER auto-run anything — the client must connect explicitly via the
#     banner button. The router dependency `require_local_auth` already
#     gates the upgrade.
#   * NEVER run as root. `brew install` is run as the current user; on a
#     Homebrew-managed Mac the user already owns /opt/homebrew. `colima
#     start` likewise runs as the current user — colima spins up its own
#     Lima VM and does NOT need sudo on a normal setup.
#   * Refuse to bootstrap Homebrew itself. If `brew` isn't on PATH we send
#     a BREW_MISSING frame with the official install one-liner and close;
#     the user has to run that manually (paste into Terminal).
#
# Honours the stop-signal convention from `port_scanner.py`: a mid-stream
# `{"action":"stop"}` terminates the child and emits a final `done` frame.

_BREW_INSTALL_CMD = (
    '/bin/bash -c "$(curl -fsSL '
    'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
)
# Same search path labs_lib._live_which() uses — the Electron sidecar can
# launch with a stripped PATH, so we always probe these explicit dirs.
_BREW_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")


def _which_brew() -> str | None:
    import os as _os
    current = (_os.environ.get("PATH") or "").split(_os.pathsep)
    search  = list(dict.fromkeys([*current, *_BREW_BIN_DIRS]))
    return shutil.which("brew", path=_os.pathsep.join(search))


async def _stream_subprocess(
    ws: WebSocket,
    cmd: list[str],
    stop: asyncio.Event,
) -> tuple[int, asyncio.subprocess.Process | None]:
    """Spawn ``cmd``, stream each stdout line as a `log` frame, return rc.

    stderr is merged into stdout so we don't fight readline-ordering. If
    `stop` is set mid-stream the process is terminated and rc is reported
    as ``-signal`` (asyncio's convention).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            # `brew install` is interactive-ish — TERM=dumb keeps output
            # readable in the WS log pane. Strip env additions otherwise.
            env={
                "TERM": "dumb",
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": __import__("os").environ.get("HOME", ""),
                # NONINTERACTIVE makes brew skip the "press any key to
                # continue" gates that would otherwise stall the stream.
                "NONINTERACTIVE": "1",
            },
        )
    except FileNotFoundError as exc:
        await ws.send_json({
            "type": "log", "stream": "stderr",
            "line": f"failed to spawn {cmd[0]}: {exc}",
        })
        return 127, None
    assert proc.stdout is not None
    try:
        while not stop.is_set():
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").rstrip()
            await ws.send_json({"type": "log", "stream": "stdout", "line": text})
    finally:
        if proc.returncode is None:
            if stop.is_set():
                try: proc.terminate()
                except Exception: pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except Exception:
                    try: proc.kill()
                    except Exception: pass
            else:
                # Process exited on its own — just collect rc.
                try: await proc.wait()
                except Exception: pass
    return (proc.returncode if proc.returncode is not None else -1), proc


@router.websocket("/ws/labs/runtime/install")
async def runtime_install_ws(ws: WebSocket) -> None:
    """One-click installer for the colima container runtime.

    Protocol:

        server -> client:
            {"type": "started", "steps": ["..."]}
            {"type": "log",     "stream": "stdout", "line": "..."}
            {"type": "error",   "code": "BREW_MISSING", "message": "...",
                                "install_command": "..."}
            {"type": "done",    "state": "<final>", "ok": bool,
                                "stopped": bool}

        client -> server (any time):
            {"action": "stop"}
    """
    await ws.accept()
    stop = asyncio.Event()
    aid: str | None = None

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

    listener = asyncio.create_task(listen_for_stop())
    try:
        # ── Platform guard ──
        # colima only ships via Homebrew on macOS/Linux. On Windows the
        # banner self-hides; if we still get here, refuse cleanly so the
        # client never thinks the installer ran.
        if sys.platform == "win32":
            await ws.send_json(ws_error(
                ErrorCode.UNSUPPORTED,
                "colima is not available on Windows. Install Docker Desktop "
                "or WSL2 instead.",
            ))
            return

        brew_path = _which_brew()
        if not brew_path:
            await ws.send_json({
                "type":            "error",
                "code":            "BREW_MISSING",
                "message":         "Homebrew is required to install colima. "
                                   "Install Homebrew first, then click "
                                   "Install & start colima again.",
                "install_command": _BREW_INSTALL_CMD,
                "url":             "https://brew.sh",
            })
            return

        # ── Probe what's already installed ──
        # We re-check here (and at the end) so the WS log makes it obvious
        # to the user that we're not blindly reinstalling things.
        pre = await labs_lib.preflight()
        steps: list[str] = []
        if pre.get("state") == "binary_missing":
            steps.append("brew install colima docker")
        elif not pre.get("colima_path"):
            # docker is installed but colima isn't — install colima alone.
            steps.append("brew install colima")
        if pre.get("state") != "ok":
            steps.append("colima start")
        if not steps:
            await ws.send_json({"type": "log", "stream": "stdout",
                                "line": "Runtime is already healthy — nothing to do."})
            await ws.send_json({
                "type": "done", "state": pre.get("state", "ok"),
                "ok": True, "stopped": False,
            })
            return

        await ws.send_json({"type": "started", "steps": steps,
                            "brew_path": brew_path})

        # Audit-log the install attempt. Best-effort.
        try:
            aid = audit_log.start(
                tool="runtime-install",
                target="colima",
                argv=steps,
            )
        except Exception:
            logger.exception("audit_log.start failed (install continues)")

        # ── Step 1: brew install (skip components that already exist) ──
        install_args: list[str] = []
        if not pre.get("colima_path"):
            install_args.append("colima")
        if not pre.get("docker_path"):
            install_args.append("docker")
        if install_args and not stop.is_set():
            cmd = [brew_path, "install", *install_args]
            await ws.send_json({"type": "log", "stream": "stdout",
                                "line": f"$ {' '.join(cmd)}"})
            rc, _ = await _stream_subprocess(ws, cmd, stop)
            if stop.is_set():
                await ws.send_json({"type": "done", "state": "binary_missing",
                                    "ok": False, "stopped": True})
                if aid:
                    try: audit_log.stopped(aid, summary="user cancelled brew install")
                    except Exception: pass
                return
            if rc != 0:
                await ws.send_json({"type": "log", "stream": "stderr",
                                    "line": f"brew install exited with rc={rc}"})
                final = await labs_lib.preflight()
                await ws.send_json({
                    "type": "done", "state": final.get("state", "binary_missing"),
                    "ok": False, "stopped": False,
                })
                if aid:
                    try: audit_log.error(aid, f"brew install rc={rc}")
                    except Exception: pass
                return
        else:
            await ws.send_json({"type": "log", "stream": "stdout",
                                "line": "Skipping brew install — colima and docker already present."})

        # ── Step 2: colima start ──
        # Re-resolve colima after the install. Use labs_lib's live PATH
        # helper so a freshly-linked /opt/homebrew/bin/colima is found
        # without needing to restart the sidecar.
        colima_path = labs_lib._live_which("colima")
        if not colima_path:
            await ws.send_json({"type": "log", "stream": "stderr",
                                "line": "colima binary still not on PATH after install."})
            await ws.send_json({"type": "done", "state": "binary_missing",
                                "ok": False, "stopped": False})
            if aid:
                try: audit_log.error(aid, "colima missing after install")
                except Exception: pass
            return

        if not stop.is_set():
            cmd = [colima_path, "start"]
            await ws.send_json({"type": "log", "stream": "stdout",
                                "line": f"$ {' '.join(cmd)}"})
            rc, _ = await _stream_subprocess(ws, cmd, stop)
            if stop.is_set():
                final = await labs_lib.preflight()
                await ws.send_json({
                    "type": "done", "state": final.get("state", "daemon_stopped"),
                    "ok": False, "stopped": True,
                })
                if aid:
                    try: audit_log.stopped(aid, summary="user cancelled colima start")
                    except Exception: pass
                return
            if rc != 0:
                await ws.send_json({"type": "log", "stream": "stderr",
                                    "line": f"colima start exited with rc={rc}"})

        # ── Verify ──
        final = await labs_lib.preflight()
        final_state = final.get("state", "binary_missing")
        ok = final_state == "ok"
        await ws.send_json({"type": "done", "state": final_state,
                            "ok": ok, "stopped": False})
        if aid:
            try:
                summary = f"final state: {final_state}"
                if ok: audit_log.complete(aid, summary=summary)
                else:  audit_log.error(aid, summary)
            except Exception:
                logger.exception("audit_log finalize failed")

    except WebSocketDisconnect:
        stop.set()
        if aid:
            try: audit_log.stopped(aid, summary="client disconnected")
            except Exception: pass
    except Exception as exc:
        logger.exception("runtime_install_ws unhandled exception")
        if aid:
            try: audit_log.error(aid, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL, "internal error during runtime install",
            ))
        except Exception:
            pass
    finally:
        listener.cancel()
        try:
            await ws.close()
        except Exception:
            pass
