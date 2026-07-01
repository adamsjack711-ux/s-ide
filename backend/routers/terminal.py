"""Terminal — single-shot command execution.

Not a real shell — runs one command per request, returns stdout/stderr.
Real PTY support (xterm.js + ptyprocess) is a follow-up.

# SECURITY: This endpoint executes arbitrary shell commands on the host.
# It is protected by:
#   1. localhost-only binding (127.0.0.1) — enforced in main.py
#   2. X-MHP-Token header auth (rotated each launch) — see lib/auth.py
#   3. explicit opt-in — command execution is refused with 403 until the
#      operator turns the host terminal on (POST /terminal/enable). The
#      enable/disable event and every executed command are written to the
#      hash-chained audit log.
# Never expose port 8765 to a network interface.
# This endpoint is intentionally NOT a PTY — no interactive
# commands, no sudo, no persistent shell state.
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from lib import audit_log, scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.platform_util import IS_WINDOWS, app_data_dir

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/terminal", tags=["terminal"], dependencies=[Depends(require_local_auth)])

# Maximum output bytes we return — protect the websocket from a 100MB cat.
MAX_OUTPUT = 256 * 1024

# ── Explicit opt-in for raw host execution ──────────────────────────────────
# The terminal shells out to arbitrary host commands, so it is OFF until the
# operator consciously enables it (persisted across launches; every enable /
# disable is audited). Loopback + token still apply; this adds a deliberate,
# logged opt-in on top so a bare engagement doesn't silently grant host RCE.
_enable_lock = threading.Lock()
_ENABLE_STORE = app_data_dir() / "terminal_enabled.json"


def _load_enabled() -> bool:
    try:
        return bool(json.loads(_ENABLE_STORE.read_text()).get("enabled", False))
    except (OSError, ValueError):
        return False


_enabled = _load_enabled()


def host_terminal_enabled() -> bool:
    with _enable_lock:
        return _enabled


def _set_enabled(on: bool) -> None:
    global _enabled
    with _enable_lock:
        _enabled = on
        try:
            _ENABLE_STORE.parent.mkdir(parents=True, exist_ok=True)
            _ENABLE_STORE.write_text(json.dumps({"enabled": on}))
        except OSError:
            pass  # non-fatal: holds for this session regardless


class EnableRequest(BaseModel):
    enabled: bool


@router.get("/status")
def terminal_status() -> dict[str, bool]:
    return {"enabled": host_terminal_enabled()}


@router.post("/enable")
def terminal_enable(req: EnableRequest, request: Request) -> dict[str, bool]:
    with audit_log.action(
        tool="terminal",
        target="host-terminal",
        argv=["terminal", "enable" if req.enabled else "disable"],
        engagement_id=get_engagement_id(request),
        mode=get_mode(request),
    ) as act:
        _set_enabled(req.enabled)
        act.summary = f"host terminal {'enabled' if req.enabled else 'disabled'}"
    return {"enabled": host_terminal_enabled()}


class ExecRequest(BaseModel):
    command: str
    cwd: str | None = None


class ExecResponse(BaseModel):
    cwd: str
    cmd: str
    returncode: int
    stdout: str
    stderr: str
    truncated: bool


@router.post("/exec", response_model=ExecResponse)
def exec_cmd(req: ExecRequest, request: Request) -> ExecResponse:
    # Arbitrary shell-out — we can't parse the command for targets, so just
    # require an active engagement under Engagement mode. Lab mode passes through.
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    cmd = req.command.strip()
    if not cmd:
        raise HTTPException(status_code=400, detail="empty command")

    cwd = req.cwd or str(Path.home())
    if not Path(cwd).is_dir():
        raise HTTPException(status_code=400, detail=f"not a directory: {cwd}")

    # Built-in `cd <dir>` — return the new cwd
    if cmd == "cd" or cmd.startswith("cd "):
        target = cmd[3:].strip() or str(Path.home())
        target = os.path.expanduser(target)
        if not os.path.isabs(target):
            target = os.path.join(cwd, target)
        target = os.path.normpath(target)
        if not Path(target).is_dir():
            return ExecResponse(cwd=cwd, cmd=cmd, returncode=1, stdout="",
                                stderr=f"cd: no such directory: {target}",
                                truncated=False)
        return ExecResponse(cwd=target, cmd=cmd, returncode=0,
                            stdout="", stderr="", truncated=False)

    # Explicit opt-in gate: real host execution is refused until the operator
    # enables the host terminal. `cd`/`clear` above never reach here, so a
    # disabled terminal can still navigate but cannot run a program.
    if not host_terminal_enabled():
        raise HTTPException(
            status_code=403,
            detail="host terminal is disabled — enable it in the Terminal "
                   "panel (explicit opt-in; every command is audited)",
        )

    # shlex with posix=True mangles Windows paths like `C:\Users\…` by treating
    # backslashes as escape characters. Use posix=False on Windows.
    try:
        parts = shlex.split(cmd, posix=not IS_WINDOWS)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"parse error: {exc}")

    # Every executed command is written to the hash-chained audit log (argv +
    # cwd + outcome), so raw host execution is never silent.
    with audit_log.action(
        tool="terminal",
        target=cwd,
        argv=parts,
        engagement_id=get_engagement_id(request),
        mode=get_mode(request),
    ) as act:
        try:
            r = subprocess.run(parts, capture_output=True, text=True,
                               cwd=cwd, timeout=20)
        except FileNotFoundError:
            raise MhpError(
                f"command not found: {parts[0]}",
                code=ErrorCode.TOOL_MISSING,
                status_code=404,
            )
        except subprocess.TimeoutExpired:
            raise MhpError(
                "command timed out (20s)",
                code=ErrorCode.TIMEOUT,
                status_code=504,
            )
        act.summary = f"exit {r.returncode}"

    out, err = r.stdout, r.stderr
    truncated = False
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT]; truncated = True
    if len(err) > MAX_OUTPUT:
        err = err[:MAX_OUTPUT]; truncated = True

    return ExecResponse(cwd=cwd, cmd=cmd, returncode=r.returncode,
                        stdout=out, stderr=err, truncated=truncated)


@router.get("/cwd")
def default_cwd() -> dict[str, Any]:
    return {"cwd": str(Path.home())}
