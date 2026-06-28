"""Package manager — Homebrew on macOS, apt/dnf/pacman on Linux.

Endpoint paths still say `/brew/...` for backwards compat with the existing
frontend page. The actual backend dispatches to whatever package manager is
available on the host. The `/brew/status` response includes `manager` so the
UI can show "apt" / "dnf" / "pacman" / "brew" appropriately.

Linux mutating ops (install / uninstall / upgrade) run through pkexec when
present, falling back to sudo -A (SUDO_ASKPASS). Read-only ops (search,
list installed) don't escalate.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, ws_error
from lib.mode import get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(tags=["packages"], dependencies=[Depends(require_local_auth)])

IS_DARWIN = sys.platform == "darwin"

# Resolved at import. Each backend bundles the read commands (which run as the
# backend user) separately from the mutate command (which we may need to
# escalate for on Linux).
_BREW = shutil.which("brew") or ("/opt/homebrew/bin/brew" if IS_DARWIN else "")


def _detect_manager() -> tuple[str, str | None]:
    """Return (manager_name, binary_path). manager ∈ {brew, apt, dnf, pacman, none}."""
    if IS_DARWIN:
        if _BREW and shutil.which(_BREW):
            return ("brew", _BREW)
        return ("brew", _BREW)  # report brew on Mac even if missing — UI prompts install
    # Order matters: prefer `apt` over `apt-get` because apt has the `list`/
    # `search` subcommands we use for read-only ops; apt-get only handles
    # install/remove. Mutate ops are wrapped via _action_args below.
    for name in ("apt", "apt-get", "dnf", "yum", "pacman"):
        p = shutil.which(name)
        if p:
            key = {"apt-get": "apt", "yum": "dnf"}.get(name, name)
            return (key, p)
    return ("none", None)


@router.get("/brew/status")
def status() -> dict[str, Any]:
    mgr, path = _detect_manager()
    return {
        "available": bool(path) and bool(shutil.which(path)),
        "manager":   mgr,
        "path":      path or "",
    }


def _privilege_wrap(cmd: list[str]) -> list[str]:
    """Wrap an apt/dnf/pacman command with pkexec or sudo -A so it can install
    without prompting on stdin. Returns the wrapped command (or the original
    if no helper is available — caller will see a sudo permission error)."""
    if IS_DARWIN:
        return cmd  # brew runs as the user
    for helper in ("pkexec", "sudo"):
        h = shutil.which(helper)
        if not h:
            continue
        if helper == "sudo":
            return [h, "-A", "-n", *cmd]
        return [h, *cmd]
    return cmd


async def _run_capture(args: list[str], timeout: int = 60) -> tuple[int, str]:
    """Read-only: run package manager without elevation."""
    mgr, path = _detect_manager()
    if not path:
        raise HTTPException(status_code=503, detail=f"no package manager available")
    proc = await asyncio.create_subprocess_exec(
        path, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait()
        raise HTTPException(status_code=504, detail="package manager timed out")
    return proc.returncode or 0, out.decode("utf-8", "replace")


def _search_args(mgr: str, q: str) -> list[str]:
    return {
        "brew":   ["search", q],
        "apt":    ["search", q],                  # apt search (modern apt)
        "dnf":    ["search", q],
        "pacman": ["-Ss", q],
    }.get(mgr, ["search", q])


def _installed_args(mgr: str) -> list[str]:
    return {
        "brew":   ["list", "--formula"],
        "apt":    ["list", "--installed"],
        "dnf":    ["list", "--installed"],
        "pacman": ["-Q"],
    }.get(mgr, ["list", "--installed"])


def _action_args(mgr: str, action: str, name: str) -> list[str]:
    """Convert (install|uninstall|upgrade, name) into per-manager argv."""
    if mgr == "brew":
        return [action, name]
    if mgr == "apt":
        return {
            "install":   ["install", "-y", name],
            "uninstall": ["remove",  "-y", name],
            "upgrade":   ["install", "-y", "--only-upgrade", name],
        }[action]
    if mgr == "dnf":
        return {
            "install":   ["install", "-y", name],
            "uninstall": ["remove",  "-y", name],
            "upgrade":   ["upgrade", "-y", name],
        }[action]
    if mgr == "pacman":
        return {
            "install":   ["-S", "--noconfirm", name],
            "uninstall": ["-R", "--noconfirm", name],
            "upgrade":   ["-S", "--noconfirm", name],  # same on pacman
        }[action]
    raise HTTPException(status_code=503, detail=f"unknown manager: {mgr}")


# ── HTTP endpoints ───────────────────────────────────────────────────────────

@router.get("/brew/search")
async def search(q: str) -> dict[str, Any]:
    mgr, path = _detect_manager()
    if not path:
        raise HTTPException(status_code=503, detail="no package manager available")
    q = q.strip()
    if not q or len(q) > 64 or any(c in q for c in " ;|&`$\n"):
        raise HTTPException(status_code=400, detail="bad query")
    rc, output = await _run_capture(_search_args(mgr, q), timeout=30)

    formulae: list[str] = []
    casks: list[str] = []   # only populated on brew

    if mgr == "brew":
        bucket: list[str] | None = None
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("==>"):
                tag = line.lower()
                bucket = formulae if "formulae" in tag else (casks if "casks" in tag else None)
                continue
            if bucket is not None and not line.startswith("If you"):
                bucket.extend(line.split())
    elif mgr == "apt":
        for line in output.splitlines():
            # `apt search` lines: "pkgname/repo version arch [installed]\n  description"
            if "/" in line and not line.startswith(" "):
                formulae.append(line.split("/", 1)[0])
    elif mgr == "dnf":
        for line in output.splitlines():
            # `dnf search` lines: "pkgname.arch : description"
            if " : " in line and "." in line:
                formulae.append(line.split(".", 1)[0].split()[0])
    elif mgr == "pacman":
        for line in output.splitlines():
            # `pacman -Ss` lines: "repo/pkgname version" then description on next
            if "/" in line and not line.startswith("    "):
                try:
                    formulae.append(line.split("/", 1)[1].split()[0])
                except (IndexError, ValueError):
                    pass

    return {"rc": rc, "manager": mgr,
            "formulae": formulae[:60], "casks": casks[:60]}


@router.get("/brew/installed")
async def installed() -> dict[str, Any]:
    mgr, path = _detect_manager()
    if not path:
        raise HTTPException(status_code=503, detail="no package manager available")
    rc, out = await _run_capture(_installed_args(mgr), timeout=20)

    formulae: list[str] = []
    casks: list[str] = []

    if mgr == "brew":
        formulae = [ln.strip() for ln in out.splitlines() if ln.strip()]
        rc2, out2 = await _run_capture(["list", "--cask"], timeout=20)
        casks = [ln.strip() for ln in out2.splitlines() if ln.strip()]
        rc = rc or rc2
    elif mgr == "apt":
        # "pkgname/repo version arch [installed,...]"
        for line in out.splitlines():
            line = line.strip()
            if "/" in line and "installed" in line.lower():
                formulae.append(line.split("/", 1)[0])
    elif mgr == "dnf":
        # "pkgname.arch  version  @repo"
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("Installed Packages") or line.startswith("Last metadata"):
                continue
            parts = line.split()
            if parts and "." in parts[0]:
                formulae.append(parts[0].rsplit(".", 1)[0])
    elif mgr == "pacman":
        # "pkgname version"
        for line in out.splitlines():
            parts = line.strip().split()
            if parts:
                formulae.append(parts[0])

    return {"rc": rc, "manager": mgr, "formulae": formulae, "casks": casks}


# ── WS install/uninstall/upgrade ─────────────────────────────────────────────

@router.websocket("/ws/brew-exec")
async def brew_exec(ws: WebSocket) -> None:
    """Stream output of an install/uninstall/upgrade.

    Handshake:  {"action": "install"|"uninstall"|"upgrade", "name": "foo", "cask": false}
    The `cask` field is honoured on macOS brew only; ignored on Linux.
    """
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
        mgr, path = _detect_manager()
        if not path:
            await ws.send_json(ws_error(
                ErrorCode.TOOL_MISSING,
                "no package manager available",
            ))
            await ws.close(); return

        init = await ws.receive_json()

        # Install/uninstall/upgrade is a state-changing local action — no remote
        # target, but should attach to an engagement record under Engagement mode.
        engagement_id = init.get("engagement_id") or get_engagement_id(ws)
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        if not await scope.enforce_engagement_present_ws(ws, engagement_id, mode):
            stop.set()
            return

        action = str(init.get("action", "")).strip()
        name   = str(init.get("name", "")).strip()
        cask   = bool(init.get("cask", False))
        if action not in ("install", "uninstall", "upgrade"):
            await ws.send_json(ws_error(
                ErrorCode.BAD_REQUEST,
                "action must be install, uninstall, or upgrade",
            ))
            await ws.close(); return
        if (not name or len(name) > 64
                or name.startswith("-")
                or any(c in name for c in " ;|&`$\n")):
            await ws.send_json(ws_error(
                ErrorCode.BAD_REQUEST,
                "package name is invalid",
            ))
            await ws.close(); return

        if mgr == "brew":
            # `--` terminates option parsing so even a hypothetical leading-dash
            # name (already rejected above) couldn't reach brew as a flag.
            args = [action] + (["--cask"] if cask else []) + ["--", name]
            cmd = [path, *args]
        else:
            args = _action_args(mgr, action, name)
            cmd = _privilege_wrap([path, *args])

        listener = asyncio.create_task(listen_for_stop())
        await ws.send_json({"type": "started",
                            "manager": mgr,
                            "cmd": " ".join(cmd)})

        # apt/dnf often output color codes — strip via TERM=dumb to keep the
        # WS stream readable in the UI.
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env={"TERM": "dumb", "DEBIAN_FRONTEND": "noninteractive",
                 "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        try:
            assert proc.stdout is not None
            while not stop.is_set():
                line = await proc.stdout.readline()
                if not line:
                    break
                await ws.send_json({"type": "line",
                                    "text": line.decode("utf-8", "replace").rstrip()})
        finally:
            listener.cancel()
            if proc and proc.returncode is None:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except Exception:
                    try: proc.kill()
                    except Exception: pass

        rc = proc.returncode if proc else -1
        await ws.send_json({"type": "done", "rc": rc, "stopped": stop.is_set()})
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("brew_exec unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during package operation",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
