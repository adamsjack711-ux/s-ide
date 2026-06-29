"""Nmap — full-surface scanner with NSE, multi-target, and live streaming.

REST:
    GET  /nmap/status                  — binary path, version, scripts dir,
                                          sudoers state for passwordless privileged scans
    POST /nmap/install                 — install one-time passwordless sudoers entry
    POST /nmap/revoke                  — remove the sudoers entry (admin prompt)
    GET  /nmap/scripts                 — NSE catalog [{name, categories}]
    GET  /nmap/script-help?name=...    — `nmap --script-help <name>` text
    GET  /nmap/policy?target=...       — target policy verdict for a single target

WS (`/ws/nmap`):
    client -> server:
        {"opts": { ...NmapOptions... }, "confirm": false}
        {"action": "stop"}

    server -> client:
        {"type": "policy", "verdicts": [{target, verdict, reason}, ...]}
        {"type": "started",  "cmd": "...", "argv": [...], "xml_path": "..."}
        {"type": "line",     "text": "..."}
        {"type": "progress", "pct": 12.3, "hosts_done": 2, "hosts_up": 1}
        {"type": "stderr",   "text": "..."}
        {"type": "done",     "rc": 0, "stopped": false, "report": {...}}
        {"type": "error",    "detail": "...", "need_confirm": bool}
"""
from __future__ import annotations

import asyncio
import getpass
import logging
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from lib import audit_log, hids_notify, nmap_runner, nmap_scripts, scope, target_policy
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import MAX_TARGET_LEN, validate_target

logger = logging.getLogger(__name__)

router = APIRouter(tags=["nmap"], dependencies=[Depends(require_local_auth)])

SUDOERS_PATH = "/etc/sudoers.d/network-tools-nmap"
SUDOERS_VERSION = "v2-argv-restricted"

# Flag tokens the app never passes to nmap. The app legitimately uses
# `--script <names>` (from a curated, app-controlled list) and `-oX <tmp>`
# (XML output to a process-private tempfile), so those CAN'T be denied here.
# The remaining defense against `--script /tmp/evil.nse` lives in
# `lib/nmap_runner._build_argv`, which rejects dangerous tokens in the
# free-form `extra_args` field before the argv is constructed.
#
# These ones are sudoers-deniable because the app never builds them:
#   -iL          read targets from a file (info disclosure / DoS as root)
#   -oN -oG -oA  text/grep/all-formats output (arbitrary file write as root)
#   --datadir    redirect script search dir (turns curated --script unsafe)
#   --interactive deprecated, shell access
_NMAP_DENY_FLAGS = ("-iL", "-oN", "-oG", "-oA", "--datadir", "--interactive")


def _build_sudoers_content(user: str, binary: str) -> str:
    """Build the argv-restricted sudoers entry. See module docstring."""
    lines = [
        f"# s-ide nmap sudoers — {SUDOERS_VERSION}",
        f"# Allows {binary} with the flag set the app builds, including",
        f"# `--script <curated>` and `-oX <tmpfile>` (both used by the runner).",
        f"# Denies {', '.join(_NMAP_DENY_FLAGS)} (flags the app never uses).",
        f"# Note: this entry does not protect against `--script /path/to/evil.nse`",
        f"# — that defense is in lib/nmap_runner.build_argv's extra_args check.",
        f"{user} ALL=(root) NOPASSWD: {binary}, \\",
    ]
    # sudoers requires literal spaces in command patterns to be backslash-
    # escaped (double-quotes aren't a valid quoting form). The `\ *\ ` pattern
    # matches only the flag as a standalone argv token (preceded by a space).
    deny_lines = [f"    !{binary}\\ *\\ {flag}*" for flag in _NMAP_DENY_FLAGS]
    lines.append(", \\\n".join(deny_lines))
    lines.append("")
    return "\n".join(lines)


def _detect_install_version(binary: str) -> str:
    """Return 'v2', 'v1', or 'none' (see tcpdump.py for the same pattern)."""
    if not _is_passwordless(binary):
        return "none"
    try:
        r = subprocess.run(["sudo", "-n", "-l"],
                           capture_output=True, text=True, timeout=3)
    except Exception:
        return "v1"
    if r.returncode != 0:
        return "v1"
    if binary not in r.stdout:
        return "none"
    return "v2" if "--datadir*" in r.stdout else "v1"


def _resolved_binary() -> str:
    b = nmap_runner.find_nmap()
    if not b:
        raise MhpError(
            "nmap binary not found",
            code=ErrorCode.TOOL_MISSING,
            status_code=503,
        )
    return b


def _is_passwordless(binary: str) -> bool:
    try:
        r = subprocess.run(
            ["sudo", "-n", binary, "--version"],
            capture_output=True, timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


@router.get("/nmap/status")
def status() -> dict[str, Any]:
    binary = nmap_runner.find_nmap()
    if not binary:
        return {
            "available": False, "binary": "", "version": "",
            "scripts_dir": "", "scripts_count": 0,
            "passwordless": False, "sudoers_path": SUDOERS_PATH,
            "user": getpass.getuser(),
        }
    sdir = nmap_runner.scripts_dir(binary) or ""
    scount = 0
    if sdir:
        try:
            scount = sum(1 for _ in Path(sdir).glob("*.nse"))
        except Exception:
            scount = 0
    install_version = _detect_install_version(binary)
    return {
        "available": True,
        "binary": binary,
        "version": nmap_runner.nmap_version(binary),
        "scripts_dir": sdir,
        "scripts_count": scount,
        "passwordless":   install_version != "none",
        "install_version": install_version,
        "needs_upgrade":  install_version == "v1",
        "sudoers_version": SUDOERS_VERSION,
        "sudoers_path":   SUDOERS_PATH,
        "user":           getpass.getuser(),
    }


class PreviewBody(BaseModel):
    # Same `opts` dict the /ws/nmap handshake sends. Validated through the
    # shared options_from_dict + build_argv path, so the preview is the exact
    # argv a run would spawn — minus the spawn.
    opts: dict[str, Any] = Field(default_factory=dict)


@router.post("/nmap/preview")
def preview(body: PreviewBody) -> dict[str, Any]:
    """Dry-run: return the exact argv (and shell-quoted command) a scan with
    these options would execute, without running anything. The same
    validation that guards a real run applies here, so an unsafe `extra_args`
    or malformed option is rejected with the reason *before* the user commits.
    """
    try:
        opts = nmap_runner.options_from_dict(body.opts)
    except (TypeError, ValueError) as e:
        raise MhpError(f"invalid options: {e}",
                       code=ErrorCode.VALIDATION_ERROR, status_code=400)
    if not opts.targets:
        raise MhpError("at least one target is required",
                       code=ErrorCode.INVALID_TARGET, status_code=400)

    # Resolve the binary if installed; fall back to a bare "nmap" so the
    # preview still renders on a host without nmap (the run path enforces
    # presence separately).
    binary = nmap_runner.find_nmap() or "nmap"
    try:
        preview = nmap_runner.preview_argv(opts, binary)
    except ValueError as e:
        raise MhpError(str(e), code=ErrorCode.VALIDATION_ERROR, status_code=400)

    return {**preview, "nmap_found": nmap_runner.find_nmap() is not None}


@router.post("/nmap/install")
def install_sudoers() -> dict[str, Any]:
    """Drop a `<user> ALL=(root) NOPASSWD: <nmap>` entry.

    Uses the OS-native admin prompt: osascript on macOS, pkexec (polkit) on
    Linux. Returns whether the install succeeded.
    """
    binary = _resolved_binary()
    if _detect_install_version(binary) == "v2":
        return {"installed": True, "already": True, "version": "v2"}

    # Refuse to grant NOPASSWD sudo to a user-writable binary path.
    # On a typical macOS dev box `find_nmap()` returns /opt/homebrew/bin/nmap,
    # which the current user can overwrite — and `sudo -n nmap` from that
    # path is then root-RCE the first time the user clicks "Quick scan".
    if not nmap_runner.nmap_path_is_safe_for_sudo():
        raise MhpError(
            f"refusing to install: {binary} is in a user-writable directory. "
            "Sudoers install requires nmap from a root-owned dir (a distro "
            "package), not Homebrew/.local. SYN/UDP/OS scans without sudo "
            "fall back to TCP-connect (non-privileged).",
            code="PRECONDITION_FAILED",
            status_code=412,
            extra={"resolved_path": binary},
        )

    user = getpass.getuser()
    tmp = Path(tempfile.gettempdir()) / "_nt_nmap_sudoers"
    tmp.write_text(_build_sudoers_content(user, binary))

    if sys.platform == "darwin":
        install_cmd = (
            f"/usr/sbin/visudo -cf {shlex.quote(str(tmp))} && "
            f"/bin/mv {shlex.quote(str(tmp))} {shlex.quote(SUDOERS_PATH)} && "
            f"/usr/sbin/chown root:wheel {shlex.quote(SUDOERS_PATH)} && "
            f"/bin/chmod 0440 {shlex.quote(SUDOERS_PATH)}"
        )
        script = f'do shell script "{install_cmd}" with administrator privileges'
        try:
            r = subprocess.run(["osascript", "-e", script],
                               capture_output=True, text=True, timeout=120)
        except Exception:
            logger.exception("nmap sudoers install via osascript failed")
            raise MhpError(
                "install failed — see server log",
                code=ErrorCode.TOOL_FAILED, status_code=500,
            )
        if r.returncode != 0:
            err = (r.stderr or "").strip()
            if "-128" in err or "canceled" in err.lower() or "cancelled" in err.lower():
                raise HTTPException(status_code=400, detail="install cancelled by user")
            raise HTTPException(status_code=500, detail=err or "install failed")
        return {"installed": _is_passwordless(binary)}

    if sys.platform.startswith("linux"):
        pkexec = shutil.which("pkexec")
        if not pkexec:
            raise HTTPException(
                status_code=501,
                detail=("pkexec not installed. Install policykit-1 (Debian/Ubuntu) "
                        "or polkit (RHEL/Arch), or add a sudoers entry manually: "
                        f"echo '{user} ALL=(root) NOPASSWD: {binary}' "
                        f"| sudo tee {SUDOERS_PATH} && "
                        f"sudo chmod 0440 {SUDOERS_PATH}"),
            )
        visudo = shutil.which("visudo") or "/usr/sbin/visudo"
        install_cmd = (
            f"{shlex.quote(visudo)} -cf {shlex.quote(str(tmp))} && "
            f"/bin/mv {shlex.quote(str(tmp))} {shlex.quote(SUDOERS_PATH)} && "
            f"/bin/chown root:root {shlex.quote(SUDOERS_PATH)} && "
            f"/bin/chmod 0440 {shlex.quote(SUDOERS_PATH)}"
        )
        try:
            r = subprocess.run(
                [pkexec, "/bin/sh", "-c", install_cmd],
                capture_output=True, text=True, timeout=120,
            )
        except Exception:
            logger.exception("nmap sudoers install via pkexec failed")
            raise MhpError(
                "install failed — see server log",
                code=ErrorCode.TOOL_FAILED, status_code=500,
            )
        if r.returncode != 0:
            err = ((r.stdout or "") + (r.stderr or "")).strip()
            if r.returncode in (126, 127):
                raise HTTPException(status_code=400,
                                    detail="install cancelled or no polkit agent available")
            raise HTTPException(status_code=500, detail=err or "install failed")
        return {"installed": _is_passwordless(binary)}

    raise HTTPException(status_code=501,
                        detail="passwordless install not supported on this platform")


@router.post("/nmap/revoke")
def revoke_sudoers() -> dict[str, Any]:
    """Remove the passwordless sudoers drop-in.

    Counterpart to /nmap/install — same osascript / pkexec flow. Idempotent.
    """
    binary = nmap_runner.find_nmap()
    if not binary or not _is_passwordless(binary):
        return {"installed": False, "already": True}

    revoke_cmd = f"/bin/rm -f {shlex.quote(SUDOERS_PATH)}"

    if sys.platform == "darwin":
        script = f'do shell script "{revoke_cmd}" with administrator privileges'
        try:
            r = subprocess.run(["osascript", "-e", script],
                               capture_output=True, text=True, timeout=120)
        except Exception:
            logger.exception("nmap sudoers revoke via osascript failed")
            raise MhpError(
                "revoke failed — see server log",
                code=ErrorCode.TOOL_FAILED, status_code=500,
            )
        if r.returncode != 0:
            err = (r.stderr or "").strip()
            if "-128" in err or "canceled" in err.lower() or "cancelled" in err.lower():
                raise HTTPException(status_code=400,
                                    detail="revoke cancelled by user")
            raise HTTPException(status_code=500, detail=err or "revoke failed")
        _audit_revoke()
        return {"installed": _is_passwordless(binary)}

    if sys.platform.startswith("linux"):
        pkexec = shutil.which("pkexec")
        if not pkexec:
            raise HTTPException(
                status_code=501,
                detail=("pkexec not installed. Remove the sudoers entry manually: "
                        f"sudo rm {SUDOERS_PATH}"),
            )
        try:
            r = subprocess.run(
                [pkexec, "/bin/sh", "-c", revoke_cmd],
                capture_output=True, text=True, timeout=120,
            )
        except Exception:
            logger.exception("nmap sudoers revoke via pkexec failed")
            raise MhpError(
                "revoke failed — see server log",
                code=ErrorCode.TOOL_FAILED, status_code=500,
            )
        if r.returncode != 0:
            err = ((r.stdout or "") + (r.stderr or "")).strip()
            if r.returncode in (126, 127):
                raise HTTPException(
                    status_code=400,
                    detail="revoke cancelled or no polkit agent available",
                )
            raise HTTPException(status_code=500, detail=err or "revoke failed")
        _audit_revoke()
        return {"installed": _is_passwordless(binary)}

    raise HTTPException(status_code=501,
                        detail="passwordless revoke not supported on this platform")


def _audit_revoke() -> None:
    try:
        aid = audit_log.start(
            tool="sudoers-revoke", target="nmap", argv=[SUDOERS_PATH],
        )
        audit_log.complete(aid, summary=f"removed {SUDOERS_PATH}")
    except Exception:
        logger.exception("audit_log write failed for nmap sudoers-revoke")


@router.get("/nmap/scripts")
def scripts() -> dict[str, Any]:
    """Return the full NSE script catalog, grouped by category + risk.

    The result is cached in-memory (see `lib/nmap_scripts.py`) — parsing
    `script.db`'s ~600 entries on every page load is wasteful.
    """
    cat = nmap_scripts.load_catalog()
    if not cat.get("available"):
        raise HTTPException(status_code=503, detail="nmap scripts dir not found")
    # Preserve the legacy `[(name, count), ...]` shape for older clients.
    legacy_categories = sorted(
        ((name, len(scripts)) for name, scripts in cat["categories"].items()),
        key=lambda p: p[0],
    )
    return {
        "count":          cat["count"],
        "scripts_dir":    cat["scripts_dir"],
        "scripts":        cat["scripts"],
        "categories":     legacy_categories,
        "category_index": cat["categories"],
        "risk_groups":    cat["risk_groups"],
    }


@router.get("/nmap/scripts/{category}")
def scripts_by_category(category: str) -> dict[str, Any]:
    """Filter the NSE catalog to a single category."""
    cat = nmap_scripts.load_catalog()
    if not cat.get("available"):
        raise HTTPException(status_code=503, detail="nmap scripts dir not found")
    names = set(cat["categories"].get(category, []))
    if not names:
        # Empty list rather than 404 — frontend can render a "no scripts in
        # this category" hint without an error toast.
        return {"category": category, "count": 0, "scripts": []}
    scripts_list = [s for s in cat["scripts"] if s["name"] in names]
    return {
        "category": category,
        "count":    len(scripts_list),
        "scripts":  scripts_list,
    }


@router.get("/nmap/script-presets")
def script_presets() -> dict[str, Any]:
    """Return the curated NSE script presets."""
    return nmap_scripts.list_presets()


@router.get("/nmap/script-help")
def script_help_endpoint(name: str = Query(..., min_length=1, max_length=200)) -> dict[str, Any]:
    binary = _resolved_binary()
    text = nmap_runner.script_help(binary, name)
    return {"name": name, "help": text}


@router.get("/nmap/policy")
def policy_one(target: str) -> dict[str, Any]:
    verdict, reason = target_policy.check_target(target)
    return {"target": target, "verdict": verdict, "reason": reason}


@router.websocket("/ws/nmap")
async def nmap_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()

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
        raw_opts = dict(init.get("opts") or {})
        confirm  = bool(init.get("confirm", False))

        # ── Script-picker handshake fields ──────────────────────────────────
        # Top-level convenience fields make the script-picker UI a thin
        # wrapper: it doesn't need to know how to translate a preset into
        # NmapOptions, it just names what the user picked.
        #
        #   {"preset": "quick_vuln"}                # expand to preset recipe
        #   {"scripts": ["http-title", "ssl-*"]}    # raw --script entries
        #   {"script_args": "user=admin"}           # --script-args
        #   {"ports": "80,443"}                     # port_spec override
        preset_id = (init.get("preset") or "").strip() or None
        extra_scripts = list(init.get("scripts") or [])
        script_args   = str(init.get("script_args") or "").strip()
        ports_override = str(init.get("ports") or "").strip()
        if preset_id:
            preset = nmap_scripts.get_preset(preset_id)
            if not preset:
                await ws.send_json(ws_error(
                    ErrorCode.VALIDATION_ERROR,
                    f"unknown preset: {preset_id}",
                ))
                await ws.close(); return
            # Preset's categories/scripts merge into anything already on opts.
            raw_opts.setdefault("nse_categories", [])
            raw_opts.setdefault("nse_scripts", [])
            raw_opts["nse_categories"] = sorted(
                set(raw_opts["nse_categories"]) | set(preset.get("categories", []))
            )
            raw_opts["nse_scripts"] = sorted(
                set(raw_opts["nse_scripts"]) | set(preset.get("scripts", []))
            )
            if preset.get("service_version"):
                raw_opts["service_version"] = True
            if preset.get("os_detect"):
                raw_opts["os_detect"] = True
            if preset.get("traceroute"):
                raw_opts["traceroute"] = True
            preset_ports = preset.get("ports", "")
            if preset_ports and not raw_opts.get("port_spec"):
                raw_opts["port_spec"] = preset_ports
        if extra_scripts:
            merged = set(raw_opts.get("nse_scripts") or []) | {
                str(s).strip() for s in extra_scripts if str(s).strip()
            }
            raw_opts["nse_scripts"] = sorted(merged)
        if script_args:
            existing = (raw_opts.get("nse_args") or "").strip()
            raw_opts["nse_args"] = f"{existing} {script_args}".strip() if existing else script_args
        if ports_override:
            raw_opts["port_spec"] = ports_override

        binary = nmap_runner.find_nmap()
        if not binary:
            await ws.send_json(ws_error(
                ErrorCode.TOOL_MISSING,
                "nmap binary not found on this system",
            ))
            await ws.close(); return

        # Build options object (defaults are sensible). Shared with the
        # /nmap/preview dry-run so the two never diverge.
        try:
            opts = nmap_runner.options_from_dict(raw_opts)
        except (TypeError, ValueError) as e:
            await ws.send_json(ws_error(
                ErrorCode.VALIDATION_ERROR,
                f"invalid options: {e}",
            ))
            await ws.close(); return

        if not opts.targets:
            await ws.send_json(ws_error(
                ErrorCode.INVALID_TARGET,
                "at least one target is required",
            ))
            await ws.close(); return

        # Per-target format validation. Accept CIDR + plain host/IP — the
        # CIDR/range expansion is handled in `nmap_runner`, so we only need
        # to ensure each entry strips cleanly and isn't pathologically long.
        normalised: list[str] = []
        for t in opts.targets[:256]:  # hard cap on target count
            if not isinstance(t, str):
                continue
            s = t.strip()
            if not s:
                continue
            if len(s) > MAX_TARGET_LEN:
                await ws.send_json(ws_error(
                    ErrorCode.INVALID_TARGET,
                    f"target too long (max {MAX_TARGET_LEN} chars)",
                ))
                await ws.close(); return
            # Accept CIDR (e.g. 10.0.0.0/24) and ranges (e.g. 10.0.0.1-50)
            # without per-character validation — nmap_runner handles those.
            # Bare hosts get full validation.
            if "/" in s or "-" in s or "," in s:
                normalised.append(s)
            else:
                try:
                    normalised.append(validate_target(s, field="target"))
                except MhpError as exc:
                    await ws.send_json(ws_error(exc.code, exc.message))
                    await ws.close(); return
        opts.targets = normalised
        if not opts.targets:
            await ws.send_json(ws_error(
                ErrorCode.INVALID_TARGET,
                "no valid targets after normalisation",
            ))
            await ws.close(); return

        # Target policy + engagement-scope gate. Each expanded target gets
        # the combined verdict (policy IP-class layer ∪ engagement scope),
        # honoring Lab/Engagement mode. A single `deny` anywhere fails the
        # whole batch; `warn` requires the user to re-submit with confirm.
        engagement_id = init.get("engagement_id") or None
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        verdicts: list[dict[str, str]] = []
        any_warn = False
        for t in nmap_runner.expand_for_policy(opts.targets):
            v, r, layers = scope.check_combined(t, engagement_id, mode)
            verdicts.append({"target": t, "verdict": v, "reason": r,
                             "layers": layers})
            if v == "deny":
                await ws.send_json({"type": "policy", "verdicts": verdicts,
                                    "mode": mode})
                await ws.send_json(ws_error(
                    ErrorCode.TARGET_DENIED,
                    f"target denied: {t} ({r})",
                    target=t,
                ))
                await ws.close(); return
            if v == "warn":
                any_warn = True
        await ws.send_json({"type": "policy", "verdicts": verdicts,
                            "mode": mode})
        if any_warn and not confirm:
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "one or more targets require confirmation",
                need_confirm=True,
            ))
            await ws.close(); return

        # Safety hard gate (ACTIVE run): every non-lab target needs a covering
        # authorization attestation. A single uncovered external target refuses
        # the whole batch; each allowed target is appended to the audit ledger
        # with its provenance + attestation id. Lab-class targets pass freely.
        from lib import safety
        for t in nmap_runner.expand_for_policy(opts.targets):
            prov = safety.provenance(t)
            try:
                attestation_id = safety.require_active_allowed(t, engagement_id)
            except Exception as exc:
                detail = getattr(exc, "detail", None) or str(exc)
                await ws.send_json(ws_error(
                    ErrorCode.TARGET_DENIED, str(detail), target=t,
                ))
                await ws.close(); return
            safety.audit_active(
                action="nmap", target=t, provenance=prov,
                params={"engagement_id": engagement_id},
                attestation_id=attestation_id,
            )

        # Privileged scan check
        if nmap_runner.needs_privileged(opts):
            opts.use_sudo = True
            if not _is_passwordless(binary):
                await ws.send_json(ws_error(
                    ErrorCode.FORBIDDEN,
                    "this scan type needs root (SYN/UDP/OS/stealth). "
                    "Install passwordless sudo first.",
                ))
                await ws.close(); return

        listener = asyncio.create_task(listen_for_stop())

        async def emit(ev: dict[str, Any]) -> None:
            try:
                await ws.send_json(ev)
            except Exception:
                pass

        result = await nmap_runner.run_scan(
            opts, binary, emit, lambda: stop.is_set(),
        )

        listener.cancel()

        # HIDS notify on success
        rep = result.get("report")
        if rep and not result.get("stopped") and result.get("rc") == 0:
            try:
                open_ports = sum(
                    1 for h in rep.get("hosts", [])
                    for p in h.get("ports", []) if p.get("state") == "open"
                )
                await hids_notify.notify(
                    "info", "nmap",
                    f"Nmap scan complete — {rep.get('hosts_up', 0)} up, {open_ports} open ports",
                    {"targets": opts.targets,
                     "hosts_total": rep.get("hosts_total", 0),
                     "hosts_up":    rep.get("hosts_up", 0),
                     "open_ports":  open_ports,
                     "elapsed":     rep.get("elapsed", 0)},
                )
            except Exception:
                pass

    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("nmap_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during nmap scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
