"""TCPDump — passwordless sudo check + capture stream.

REST:
    GET  /tcpdump/status       — {passwordless: bool, sudoers_path: str}
    POST /tcpdump/install      — install one-time passwordless sudoers entry
                                  (shows native macOS password dialog once)
    POST /tcpdump/revoke       — remove the sudoers entry (admin prompt)
    GET  /tcpdump/interfaces   — list available interface names

WS (`/ws/tcpdump`):
    client -> server:
        {"iface": "en0", "filter": "tcp port 80", "count": 0,
         "verbose": false, "resolve": false}
        {"action": "stop"}

    server -> server:
        {"type": "started",  "iface": ..., "cmd": ...}
        {"type": "line",     "text": "..."}
        {"type": "stopped",  "captured": 42}
        {"type": "error",    "detail": "..."}
"""
from __future__ import annotations

import asyncio
import getpass
import logging
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from lib import audit_log
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError, ws_error
from lib.platform_util import require_unix

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tcpdump"], dependencies=[Depends(require_local_auth)])

# Interface names: alnum + underscore + dot + colon + hyphen, max 32 chars.
# Covers en0/wlan0/eth0.1/veth-foo and "any"; rejects anything with shell-meta.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")

_TCPDUMP_HINT = ("tcpdump wraps the libpcap-based tcpdump binary on macOS/Linux. "
                 "Windows would need npcap + windump (separate install) — "
                 "native port pending.")

SUDOERS_PATH = "/etc/sudoers.d/network-tools-tcpdump"
SUDOERS_VERSION = "v2-argv-restricted"

# Resolve once at import. We deliberately PREFER the SIP/root-protected
# system paths over `shutil.which` because the latter typically returns
# `/opt/homebrew/bin/tcpdump` on a developer Mac — a directory the current
# user can write. Giving `NOPASSWD` sudo to a user-writable binary is
# trivially-bypassable root code execution: swap the binary, run any sudo
# tcpdump call, get root.
#
# Apple ships tcpdump at /usr/sbin/tcpdump (SIP-protected). On Debian/Ubuntu
# it's /usr/sbin/tcpdump; on Arch sometimes /usr/bin/tcpdump. All three live
# in dirs owned by root with mode 0755 (no world-write, no user-write).
import shutil as _shutil


def _is_root_owned_dir(directory: str) -> bool:
    """True iff the directory exists, is owned by root, not world-writable,
    not group-writable, and not owned by the current non-root user."""
    try:
        st = os.stat(directory)
    except (FileNotFoundError, PermissionError):
        return False
    if st.st_uid != 0:
        return False
    if st.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
        return False
    return True


def _resolve_tcpdump() -> str:
    """Pick a non-user-writable absolute path; fall back to `which` only if
    no system path qualifies (so error paths still produce a sensible value).
    """
    for path in ("/usr/sbin/tcpdump", "/usr/bin/tcpdump"):
        if os.path.isfile(path) and _is_root_owned_dir(os.path.dirname(path)):
            return path
    return _shutil.which("tcpdump") or "/usr/sbin/tcpdump"


TCPDUMP = _resolve_tcpdump()


# Flag tokens the app never passes to tcpdump. Each lets an attacker who can
# call `sudo tcpdump` with a custom argv pivot to root code execution or
# arbitrary file I/O — see `tcpdump(1)` for the full semantics:
#   -z / --postrotate-command  runs a command on each output rotate (as root)
#   -w                          writes the pcap (arbitrary file write as root)
#   -r                          reads a pcap file (info disclosure as root)
#   -W / -G                     rotation control (chains with -z)
#   -Z                          changes the post-init privilege-drop user
# The deny patterns use a leading space so they only match standalone flag
# tokens; the WS handler rejects leading-dash BPF tokens upstream so a BPF
# term can never reach sudo as a flag.
#
# Known residual: combined-short-flag forms like `-lz cmd` (which tcpdump's
# getopt parses as `-l -z cmd`) are NOT caught by these patterns — the `-z`
# substring lacks a preceding space. Defending requires this entry to be
# combined with the upstream WS-handler input validation in install_capture/
# `bpf_tokens` (already in place). An attacker who can construct argv
# directly already has local code execution and the sudoers entry is moot.
_TCPDUMP_DENY_FLAGS = ("-z", "-w", "-r", "-W", "-G", "-Z",
                       "--postrotate-command")


def _build_sudoers_content(user: str, binary: str) -> str:
    """Build the argv-restricted sudoers entry. See module docstring."""
    lines = [
        f"# s-ide tcpdump sudoers — {SUDOERS_VERSION}",
        f"# Allows {binary} with the flags the app uses (-l -n -v -c -i + BPF)",
        f"# and denies {', '.join(_TCPDUMP_DENY_FLAGS)} (root code-exec vectors).",
        f"# Re-run the Install Permission button from the UI to upgrade an",
        f"# older install. See routers/tcpdump.py for the full threat model.",
        f"{user} ALL=(root) NOPASSWD: {binary}, \\",
    ]
    # sudoers requires literal spaces in command patterns to be backslash-
    # escaped; double-quotes are not a valid quoting form for patterns. The
    # `\ *\ ` between the binary path and the deny flag ensures the pattern
    # only matches the flag as a standalone argv token (preceded by a space),
    # not as a substring inside a benign BPF term like `host my-z-thing.com`.
    deny_lines = [f"    !{binary}\\ *\\ {flag}*" for flag in _TCPDUMP_DENY_FLAGS]
    lines.append(", \\\n".join(deny_lines))
    lines.append("")
    return "\n".join(lines)


def _is_passwordless() -> bool:
    try:
        r = subprocess.run(
            ["sudo", "-n", TCPDUMP, "--version"],
            capture_output=True, timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


def _detect_install_version() -> str:
    """Return 'v2' if an argv-restricted entry is installed, 'v1' if a
    legacy unrestricted entry is installed, or 'none' otherwise.

    Inspects ``sudo -n -l`` (which prints the calling user's sudoers rules
    without reading /etc/sudoers.d directly). v2 entries contain the
    deny-pattern substring `-z*`; v1 entries don't.
    """
    if not _is_passwordless():
        return "none"
    try:
        r = subprocess.run(["sudo", "-n", "-l"],
                           capture_output=True, text=True, timeout=3)
    except Exception:
        return "v1"
    if r.returncode != 0:
        return "v1"
    if TCPDUMP not in r.stdout:
        return "none"
    return "v2" if "-z*" in r.stdout else "v1"


@router.get("/tcpdump/status")
def status() -> dict[str, Any]:
    require_unix(_TCPDUMP_HINT)
    version = _detect_install_version()
    return {
        "passwordless":   version != "none",
        "install_version": version,
        "needs_upgrade":  version == "v1",
        "sudoers_version": SUDOERS_VERSION,
        "sudoers_path":   SUDOERS_PATH,
        "user":           getpass.getuser(),
    }


_IFACE_SKIP_PREFIXES = (
    # macOS pseudo-interfaces / tunnels
    "utun", "ipsec", "stf", "gif",
    # Linux tunnel / encapsulation interfaces from iproute2
    "tunl", "gre", "erspan", "ip6tnl", "sit", "ip_vti", "ip6_vti",
)


@router.get("/tcpdump/interfaces")
def interfaces() -> dict[str, list[str]]:
    require_unix(_TCPDUMP_HINT)
    names: list[str] = []

    # On Linux prefer `ip -o link show up`. iproute2 is universally present
    # on modern distros, while net-tools (ifconfig) is increasingly absent.
    ip_bin = _shutil.which("ip")
    if ip_bin and sys.platform.startswith("linux"):
        try:
            r = subprocess.run([ip_bin, "-o", "link", "show", "up"],
                               capture_output=True, text=True, timeout=4)
            # Line shape: "11: eth0@if103: <BROADCAST,...>" — capture up to the
            # first ':' or '@' so veth pair names come back clean.
            names = [m.group(1) for m in re.finditer(
                r"^\d+:\s+([^:@\s]+)[:@]", r.stdout, re.MULTILINE)]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not names:
        try:
            out = subprocess.run(["ifconfig"], capture_output=True,
                                 text=True, timeout=4).stdout
            names = re.findall(r"^(\w+):", out, re.MULTILINE)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"interfaces": ["any"]}

    keep = ["any"] + [n for n in names if not n.startswith(_IFACE_SKIP_PREFIXES)]
    return {"interfaces": keep}


@router.post("/tcpdump/install")
def install_sudoers() -> dict[str, Any]:
    """Drop a `<user> ALL=(root) NOPASSWD: <tcpdump>` entry.

    Shows the OS-native admin prompt: osascript on macOS, pkexec (polkit) on
    Linux. Returns whether the install succeeded.
    """
    # Only short-circuit if the *current* (v2) entry is already in place.
    # A legacy v1 install must be upgraded — fall through to the install flow,
    # which overwrites the file atomically via `mv`.
    if _detect_install_version() == "v2":
        return {"installed": True, "already": True, "version": "v2"}

    # Refuse to grant NOPASSWD sudo to a user-writable binary path.
    # A binary in /opt/homebrew or /usr/local/bin can be swapped by the
    # current user; combined with the sudoers entry that's a root-RCE.
    if not _is_root_owned_dir(os.path.dirname(TCPDUMP)):
        raise MhpError(
            f"refusing to install: {TCPDUMP} is in a user-writable directory. "
            "Install Apple's system tcpdump (/usr/sbin/tcpdump) or a distro "
            "package, not Homebrew.",
            code="PRECONDITION_FAILED",
            status_code=412,
            extra={"resolved_path": TCPDUMP},
        )

    user = getpass.getuser()
    tmp = Path(tempfile.gettempdir()) / "_nt_tcpdump_sudoers"
    tmp.write_text(_build_sudoers_content(user, TCPDUMP))

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
            logger.exception("tcpdump sudoers install via osascript failed")
            raise MhpError(
                "sudoers install failed",
                code=ErrorCode.INTERNAL,
                status_code=500,
            )
        if r.returncode != 0:
            err = (r.stderr or "").strip()
            if "-128" in err or "canceled" in err.lower() or "cancelled" in err.lower():
                raise HTTPException(status_code=400,
                                    detail="install cancelled by user")
            raise HTTPException(status_code=500, detail=err or "install failed")
        return {"installed": _is_passwordless()}

    if sys.platform.startswith("linux"):
        pkexec = _shutil.which("pkexec")
        if not pkexec:
            raise HTTPException(
                status_code=501,
                detail=("pkexec not installed. Install policykit-1 (Debian/Ubuntu) "
                        "or polkit (RHEL/Arch), or add a sudoers entry manually: "
                        f"echo '{user} ALL=(root) NOPASSWD: {TCPDUMP}' "
                        f"| sudo tee {SUDOERS_PATH} && "
                        f"sudo chmod 0440 {SUDOERS_PATH}"),
            )
        visudo = _shutil.which("visudo") or "/usr/sbin/visudo"
        install_cmd = (
            f"{shlex.quote(visudo)} -cf {shlex.quote(str(tmp))} && "
            f"/bin/mv {shlex.quote(str(tmp))} {shlex.quote(SUDOERS_PATH)} && "
            # Linux's superuser group is `root`, not Mac's `wheel`.
            f"/bin/chown root:root {shlex.quote(SUDOERS_PATH)} && "
            f"/bin/chmod 0440 {shlex.quote(SUDOERS_PATH)}"
        )
        try:
            r = subprocess.run(
                [pkexec, "/bin/sh", "-c", install_cmd],
                capture_output=True, text=True, timeout=120,
            )
        except Exception:
            logger.exception("tcpdump sudoers install via pkexec failed")
            raise MhpError(
                "sudoers install failed",
                code=ErrorCode.INTERNAL,
                status_code=500,
            )
        if r.returncode != 0:
            err = ((r.stdout or "") + (r.stderr or "")).strip()
            # pkexec: 126 = auth failed / dismissed, 127 = no agent
            if r.returncode in (126, 127):
                raise HTTPException(status_code=400,
                                    detail="install cancelled or no polkit agent available")
            raise HTTPException(status_code=500, detail=err or "install failed")
        return {"installed": _is_passwordless()}

    raise HTTPException(status_code=501,
                        detail="passwordless install not supported on this platform")


@router.post("/tcpdump/revoke")
def revoke_sudoers() -> dict[str, Any]:
    """Remove the passwordless sudoers drop-in.

    Counterpart to /tcpdump/install — same osascript / pkexec flow, so the
    user sees the OS-native admin prompt before any privileged action.
    Idempotent: a missing file is treated as success.
    """
    if not _is_passwordless():
        return {"installed": False, "already": True}

    # `rm -f` so the command succeeds if a concurrent run already removed
    # the file; the post-condition check below is what we trust.
    revoke_cmd = f"/bin/rm -f {shlex.quote(SUDOERS_PATH)}"

    if sys.platform == "darwin":
        script = f'do shell script "{revoke_cmd}" with administrator privileges'
        try:
            r = subprocess.run(["osascript", "-e", script],
                               capture_output=True, text=True, timeout=120)
        except Exception:
            logger.exception("tcpdump sudoers revoke via osascript failed")
            raise MhpError(
                "sudoers revoke failed",
                code=ErrorCode.INTERNAL,
                status_code=500,
            )
        if r.returncode != 0:
            err = (r.stderr or "").strip()
            if "-128" in err or "canceled" in err.lower() or "cancelled" in err.lower():
                raise HTTPException(status_code=400,
                                    detail="revoke cancelled by user")
            raise HTTPException(status_code=500, detail=err or "revoke failed")
        _audit_revoke()
        return {"installed": _is_passwordless()}

    if sys.platform.startswith("linux"):
        pkexec = _shutil.which("pkexec")
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
            logger.exception("tcpdump sudoers revoke via pkexec failed")
            raise MhpError(
                "sudoers revoke failed",
                code=ErrorCode.INTERNAL,
                status_code=500,
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
        return {"installed": _is_passwordless()}

    raise HTTPException(status_code=501,
                        detail="passwordless revoke not supported on this platform")


def _audit_revoke() -> None:
    # Best-effort: audit failure shouldn't surface as a revoke failure.
    try:
        aid = audit_log.start(
            tool="sudoers-revoke", target="tcpdump", argv=[SUDOERS_PATH],
        )
        audit_log.complete(aid, summary=f"removed {SUDOERS_PATH}")
    except Exception:
        logger.exception("audit_log write failed for tcpdump sudoers-revoke")


@router.websocket("/ws/tcpdump")
async def tcpdump_ws(ws: WebSocket) -> None:
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
        iface     = str(init.get("iface", "any")).strip() or "any"
        bpf       = str(init.get("filter", "")).strip()
        count_raw = init.get("count")
        verbose   = bool(init.get("verbose", False))
        resolve   = bool(init.get("resolve", False))

        if not _IFACE_RE.match(iface):
            await ws.send_json(ws_error(
                ErrorCode.VALIDATION_ERROR,
                "invalid interface name",
            ))
            await ws.close(); return

        count = 0
        if count_raw not in (None, ""):
            try:
                count = max(0, int(count_raw))
            except (TypeError, ValueError):
                count = 0

        if not _is_passwordless():
            await ws.send_json(ws_error(
                ErrorCode.FORBIDDEN,
                "passwordless sudo for tcpdump is not configured. "
                "Use the Install Permission button first.",
            ))
            await ws.close(); return

        flags: list[str] = ["-l"]
        if not resolve: flags.append("-n")
        if verbose:     flags.append("-v")
        if count > 0:   flags += ["-c", str(count)]
        flags += ["-i", iface]
        # Disallow shell-meta in filter — should be a BPF expression
        if bpf:
            if any(c in bpf for c in ("`", "$", "&", "|", ";", "\n")):
                await ws.send_json(ws_error(
                    ErrorCode.VALIDATION_ERROR,
                    "filter contains forbidden characters",
                ))
                await ws.close(); return
            bpf_tokens = shlex.split(bpf)
            # Reject `-`-prefixed tokens: tcpdump treats them as options, not
            # BPF terms — a filter like "-Z root" would alter privilege handling.
            if any(t.startswith("-") for t in bpf_tokens):
                await ws.send_json(ws_error(
                    ErrorCode.VALIDATION_ERROR,
                    "filter token may not start with '-'",
                ))
                await ws.close(); return
            flags += bpf_tokens

        cmd = ["sudo", "-n", TCPDUMP, *flags]
        listener = asyncio.create_task(listen_for_stop())
        await ws.send_json({"type": "started", "iface": iface,
                            "cmd": " ".join(shlex.quote(c) for c in cmd)})

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception:
            logger.exception("tcpdump subprocess spawn failed")
            await ws.send_json(ws_error(
                ErrorCode.TOOL_FAILED,
                "failed to start tcpdump",
            ))
            return

        captured = 0
        try:
            assert proc.stdout is not None
            while not stop.is_set():
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip()
                # Skip tcpdump's own "listening on ..." kind of leader lines
                # by counting only lines that look like packet records (have
                # a timestamp). Loose heuristic but adequate.
                if re.match(r"^\d\d:\d\d:\d\d\.", text):
                    captured += 1
                await ws.send_json({"type": "line", "text": text})
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

        await ws.send_json({"type": "stopped", "captured": captured})
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("tcpdump_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during capture",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
