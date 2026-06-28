"""Systemd unit viewer (Linux-only).

  GET  /systemd/units              → list services with state
  GET  /systemd/unit/{name}        → full status + ExecStart + recent journal
  GET  /systemd/journal/{name}     → just journalctl tail for a unit

All read-only — no privilege escalation. `systemctl status` and `journalctl
-u <unit>` both work for the unit's invoker user on most setups; failed-unit
details may require root depending on PolicyKit policy.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from lib import scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode

router = APIRouter(tags=["systemd"], dependencies=[Depends(require_local_auth)])

IS_LINUX = sys.platform.startswith("linux")


def _require_linux() -> None:
    if not IS_LINUX:
        raise HTTPException(501, "systemd is Linux-only")


def _systemctl() -> str:
    """Resolve systemctl binary path or raise."""
    p = shutil.which("systemctl")
    if not p:
        raise HTTPException(503, "systemctl not found — not a systemd system?")
    return p


def _journalctl() -> str | None:
    return shutil.which("journalctl")


def _safe_unit_name(name: str) -> str:
    """Permit only letters, digits, ., -, _, @, : — block path traversal &
    shell metacharacters before passing to systemctl/journalctl. The first
    character is restricted to [A-Za-z0-9_] so the unit name can't pose as
    a CLI flag (e.g. `-h`, `-H host`)."""
    if not name or len(name) > 200:
        raise HTTPException(400, "bad unit name")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._@:\-]*", name):
        raise HTTPException(400, "unit name contains forbidden characters")
    return name


@router.get("/systemd/units")
def list_units(request: Request, state: str = "all", type: str = "service") -> dict[str, Any]:
    """List units. `state` ∈ {all,enabled,active,failed,running}. `type` ∈
    {service,timer,socket,target,mount,path,slice}.
    """
    _require_linux()
    # Local inspection — no remote target. Engagement mode requires an
    # active engagement so the audit log can attribute the action.
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    sctl = _systemctl()

    valid_states = {"all", "enabled", "active", "failed", "running",
                    "static", "disabled", "masked"}
    valid_types  = {"service", "timer", "socket", "target",
                    "mount", "path", "slice", "device"}
    if state not in valid_states:
        raise HTTPException(400, f"bad state, allowed: {sorted(valid_states)}")
    if type not in valid_types:
        raise HTTPException(400, f"bad type, allowed: {sorted(valid_types)}")

    # Try `list-units` first (live state — what an admin actually sees on a
    # running system). If the systemd manager isn't reachable (e.g. inside a
    # container without systemd PID 1, or on a sysvinit/openrc box), fall
    # back to `list-unit-files` which only reads files from disk.
    args = [sctl, "list-units", f"--type={type}", "--no-legend",
            "--no-pager", "--plain", "--all"]
    if state in ("active", "failed"):
        args.append(f"--state={state}")
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "systemctl list-units timed out")

    manager_ok = r.returncode == 0 and "not been booted with systemd" not in r.stderr

    units: list[dict[str, Any]] = []

    if manager_ok:
        for line in r.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            unit, load, active, sub = parts[:4]
            desc = parts[4] if len(parts) > 4 else ""
            units.append({
                "name":   unit,
                "load":   load,         # loaded / not-found / error / masked
                "active": active,       # active / inactive / failed / activating
                "sub":    sub,          # running / dead / exited / failed
                "description": desc,
            })
    else:
        # Fallback: list-unit-files (file-based, no manager needed). The shape
        # only gives unit name + UnitFileState — we surface that as `sub` and
        # mark `active` as "unknown" so the UI shows what's available.
        try:
            rf = subprocess.run(
                [sctl, "list-unit-files", f"--type={type}", "--no-legend",
                 "--no-pager", "--all"],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "systemctl list-unit-files timed out")
        for line in rf.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            units.append({
                "name":   parts[0],
                "load":   "file",
                "active": "unknown",     # manager not running — can't tell
                "sub":    parts[1],      # enabled / disabled / static / masked / alias
                "description": "",
            })

    # For enabled/disabled filter we need list-unit-files since list-units
    # doesn't report that. Cross-reference if requested.
    if state in ("enabled", "disabled", "static", "masked"):
        try:
            rf = subprocess.run(
                [sctl, "list-unit-files", f"--type={type}", "--no-legend",
                 "--no-pager", f"--state={state}"],
                capture_output=True, text=True, timeout=10,
            )
            enabled_names = set()
            for line in rf.stdout.splitlines():
                p = line.split()
                if p:
                    enabled_names.add(p[0])
            units = [u for u in units if u["name"] in enabled_names]
        except subprocess.TimeoutExpired:
            pass

    # Sort: failed first (loud), then active, then by name
    sev = {"failed": 0, "active": 1, "activating": 2, "inactive": 3}
    units.sort(key=lambda u: (sev.get(u["active"], 9), u["name"]))
    return {"count": len(units), "type": type, "state": state, "units": units}


@router.get("/systemd/unit/{name}")
def show_unit(name: str, request: Request) -> dict[str, Any]:
    """Detailed status for a single unit. Combines `systemctl show` (structured
    properties) and `systemctl status` (human + recent log tail)."""
    _require_linux()
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    name = _safe_unit_name(name)
    sctl = _systemctl()

    try:
        show = subprocess.run(
            [sctl, "show", name, "--no-pager",
             "--property=Id,Description,LoadState,ActiveState,SubState,"
             "UnitFileState,ExecStart,Restart,RestartSec,User,Group,"
             "FragmentPath,Documentation,MainPID"],
            capture_output=True, text=True, timeout=6,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "systemctl show timed out")

    props: dict[str, str] = {}
    for line in show.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v

    if not props.get("Id"):
        # `systemctl show` will produce empty props for nonexistent units.
        raise HTTPException(404, f"unit not found: {name}")

    try:
        status = subprocess.run(
            [sctl, "status", name, "--no-pager", "--lines=0"],
            capture_output=True, text=True, timeout=6,
        )
    except subprocess.TimeoutExpired:
        status = None

    return {
        "name":        props.get("Id", name),
        "description": props.get("Description", ""),
        "load_state":  props.get("LoadState", ""),
        "active_state": props.get("ActiveState", ""),
        "sub_state":   props.get("SubState", ""),
        "file_state":  props.get("UnitFileState", ""),
        "exec_start":  props.get("ExecStart", ""),
        "restart":     props.get("Restart", ""),
        "restart_sec": props.get("RestartSec", ""),
        "user":        props.get("User", ""),
        "group":       props.get("Group", ""),
        "fragment_path": props.get("FragmentPath", ""),
        "documentation": props.get("Documentation", ""),
        "main_pid":    props.get("MainPID", "0"),
        "status_raw":  status.stdout.strip() if status else "",
    }


@router.get("/systemd/journal/{name}")
def journal_tail(name: str, request: Request, lines: int = 200) -> dict[str, Any]:
    """Tail the journal for a unit. `lines` capped at 1000 to keep the
    response bounded."""
    _require_linux()
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    name = _safe_unit_name(name)
    jctl = _journalctl()
    if not jctl:
        raise HTTPException(503, "journalctl not available")

    lines = max(1, min(int(lines), 1000))
    try:
        r = subprocess.run(
            [jctl, "-u", name, "--no-pager", "--output=short-iso",
             f"--lines={lines}"],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "journalctl timed out")

    # rc 1 here usually means no entries / unit unknown — not an error.
    return {
        "name":  name,
        "lines": [ln for ln in r.stdout.splitlines() if ln.strip()],
        "rc":    r.returncode,
    }
