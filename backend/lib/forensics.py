"""Shared helpers for forensics features (persistence + process inspector)."""
from __future__ import annotations

import plistlib
import re
import shutil
import subprocess
from pathlib import Path

_CODESIGN = shutil.which("codesign")

# Substrings in a codesign authority line that mark the binary as Apple-shipped.
_APPLE_AUTHORITIES = (
    "apple root ca",
    "software signing",
    "apple mac os application signing",
    "developer id installer: apple",
)

# Cache codesign results keyed by file identity. The key includes mtime, size,
# and inode so any modification to the binary invalidates the entry naturally.
# Plateaus at the set of installed binaries on the machine.
_codesign_cache: dict[tuple, dict[str, str]] = {}


def _file_identity(p: Path) -> tuple | None:
    try:
        st = p.stat()
    except OSError:
        return None
    return (str(p), st.st_mtime_ns, st.st_size, st.st_ino)


def codesign_check(path: str | Path) -> dict[str, str]:
    """Return {status, team, authority} for a binary.

    status ∈ {"apple", "developer-id", "ad-hoc", "unsigned", "invalid", "missing"}
    """
    p = Path(path)
    key = _file_identity(p)
    if key is None:
        return {"status": "missing", "team": "", "authority": ""}

    cached = _codesign_cache.get(key)
    if cached is not None:
        return cached

    # codesign is macOS-only — return empty status on Linux/Windows so callers
    # treat it like an un-flagged process rather than crashing.
    if _CODESIGN is None:
        return {"status": "", "team": "", "authority": ""}

    # codesign on very large binaries (Docker.app's com.docker.backend,
    # Electron helper bundles) can blow past 8s. Cache the empty result so
    # one slow binary doesn't 500 every /processes/list call.
    try:
        verify = subprocess.run(
            [_CODESIGN, "--verify", "--no-strict", str(p)],
            capture_output=True, text=True, timeout=8,
        )
        valid = verify.returncode == 0

        show = subprocess.run(
            [_CODESIGN, "-dvv", str(p)],
            capture_output=True, text=True, timeout=8,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        result = {"status": "", "team": "", "authority": ""}
        _codesign_cache[key] = result
        return result
    raw = (show.stdout + show.stderr).strip()
    if "code object is not signed" in raw.lower():
        result = {"status": "unsigned", "team": "", "authority": ""}
        _codesign_cache[key] = result
        return result

    authorities = re.findall(r"Authority=(.+)", raw)
    team = ""
    tm = re.search(r"TeamIdentifier=(\S+)", raw)
    if tm and tm.group(1) != "not":
        team = tm.group(1)

    primary = authorities[0] if authorities else ""
    lo = primary.lower()
    if not valid:
        status = "invalid"
    elif any(k in lo for k in _APPLE_AUTHORITIES):
        status = "apple"
    elif "developer id application" in lo or "developer id installer" in lo:
        status = "developer-id"
    elif primary == "" or "ad hoc" in lo:
        status = "ad-hoc"
    else:
        status = "developer-id"   # signed but non-Apple — treat as devid-class

    result = {"status": status, "team": team, "authority": primary}
    _codesign_cache[key] = result
    return result


# ── plist helpers ──────────────────────────────────────────────────────────────

def load_plist(path: Path) -> dict | None:
    try:
        with path.open("rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return None


def plist_program(data: dict) -> str:
    """Extract the executable a launchd plist points at."""
    p = data.get("Program")
    if isinstance(p, str):
        return p
    args = data.get("ProgramArguments")
    if isinstance(args, list) and args:
        return str(args[0])
    return ""


# ── path heuristics ────────────────────────────────────────────────────────────

SUSPICIOUS_DIR_PREFIXES = (
    # macOS
    "/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/",
    "/Users/Shared/",
    # Linux
    "/dev/shm/", "/run/user/", "/run/lock/",
)


def is_suspicious_path(path: str) -> bool:
    return any(path.startswith(p) for p in SUSPICIOUS_DIR_PREFIXES)


# ── Linux package provenance ──────────────────────────────────────────────────
# Map the result onto the existing sign_status vocabulary so the frontend can
# render it without changes: "apple" = trusted (package owns it), "developer-id"
# = locally installed in a standard prefix, "unsigned" = unowned non-standard,
# "invalid" = world-writable, "missing" = file doesn't exist on disk.

_DPKG    = shutil.which("dpkg")
_RPM     = shutil.which("rpm")
_PACMAN  = shutil.which("pacman")

# Cache provenance by file identity (same shape used by codesign_check).
_pkg_cache: dict[tuple, dict[str, str]] = {}

_TRUSTED_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/",
    "/usr/local/bin/", "/usr/local/sbin/", "/opt/",
)

_SHELL_BUILTINS = frozenset({
    "cd", "exec", "source", ".", "eval", "set", "unset", "export",
    "if", "for", "while", "until", "case", "function",
    "true", "false", "echo", "exit", "return", ":",
})


def linux_pkg_owner(path: str | Path) -> dict[str, str]:
    """Return {status, team, authority} for a Linux executable.

    `team` is the owning package (or ""), `authority` is the package manager
    name. Status uses the same vocabulary as `codesign_check` so existing
    severity classification + frontend tint code work unchanged.
    """
    # Shell built-ins (cron's `cd / && run-parts …` pattern) aren't real
    # binaries on disk — return developer-id (info severity) so we don't
    # spam HIGH alerts on every hourly cron line.
    spath = str(path)
    if "/" not in spath and spath in _SHELL_BUILTINS:
        return {"status": "developer-id", "team": "", "authority": "shell"}

    p = Path(path)
    key = _file_identity(p)
    if key is None:
        return {"status": "missing", "team": "", "authority": ""}

    cached = _pkg_cache.get(key)
    if cached is not None:
        return cached

    # World-writable file = anyone can swap the binary out → high severity.
    try:
        mode = p.stat().st_mode
        if mode & 0o002:
            result = {"status": "invalid", "team": "", "authority": "world-writable"}
            _pkg_cache[key] = result
            return result
    except OSError:
        pass

    target = str(p.resolve()) if p.exists() else str(p)

    # Try each available package manager. We accept the first that claims the
    # file — multi-PM systems (e.g. dnf + flatpak) are rare and the answer is
    # the same shape either way.
    if _DPKG:
        r = subprocess.run([_DPKG, "-S", target],
                           capture_output=True, text=True, timeout=4)
        if r.returncode == 0 and r.stdout:
            # "openssh-server: /usr/sbin/sshd"
            pkg = r.stdout.split(":", 1)[0].strip()
            result = {"status": "apple", "team": pkg, "authority": "dpkg"}
            _pkg_cache[key] = result
            return result
    if _RPM:
        r = subprocess.run([_RPM, "-qf", target],
                           capture_output=True, text=True, timeout=4)
        if r.returncode == 0 and r.stdout and "not owned by" not in r.stdout:
            pkg = r.stdout.strip().splitlines()[0]
            result = {"status": "apple", "team": pkg, "authority": "rpm"}
            _pkg_cache[key] = result
            return result
    if _PACMAN:
        r = subprocess.run([_PACMAN, "-Qo", target],
                           capture_output=True, text=True, timeout=4)
        if r.returncode == 0 and "is owned by" in r.stdout:
            # "/usr/bin/sshd is owned by openssh 9.7p1-1"
            try:
                pkg = r.stdout.split("is owned by", 1)[1].strip().split()[0]
            except IndexError:
                pkg = ""
            result = {"status": "apple", "team": pkg, "authority": "pacman"}
            _pkg_cache[key] = result
            return result

    # Not owned by any package manager. Distinguish trusted-prefix from random.
    if any(target.startswith(pfx) for pfx in _TRUSTED_PREFIXES):
        status = "developer-id"
    else:
        status = "unsigned"
    result = {"status": status, "team": "", "authority": "local"}
    _pkg_cache[key] = result
    return result
