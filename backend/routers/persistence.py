"""Persistence audit — scan auto-start locations on macOS, Linux, or Windows.

REST: GET /persistence/audit  → structured report of every persistence entry,
each enriched with target-binary integrity (codesign on macOS, package
provenance on Linux, file-existence + Authenticode hint on Windows).

The response shape is the same on all platforms; the `sign_status` field uses
the same vocabulary (apple / developer-id / unsigned / invalid / missing) so
the frontend renders identically. On Windows we repurpose tokens: "apple" ≈
"signed by Microsoft", "developer-id" ≈ Authenticode-signed by a third party.
"""
from __future__ import annotations

import configparser
import csv
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from lib import forensics
from lib.auth import require_local_auth
from lib.platform_util import IS_DARWIN, IS_LINUX, IS_WINDOWS

logger = logging.getLogger(__name__)

router = APIRouter(tags=["forensics"], dependencies=[Depends(require_local_auth)])


# ── Mac persistence locations ─────────────────────────────────────────────────
# We skip /System/Library/* — those are Apple-managed and would be overwhelming.
MAC_PERSISTENCE_LOCATIONS: list[tuple[str, Path]] = [
    ("User LaunchAgents",   Path.home() / "Library" / "LaunchAgents"),
    ("Global LaunchAgents", Path("/Library/LaunchAgents")),
    ("LaunchDaemons",       Path("/Library/LaunchDaemons")),
    ("StartupItems",        Path("/Library/StartupItems")),
]


class PersistenceEntry(BaseModel):
    source: str            # category label (e.g. "LaunchDaemons" or "Systemd System")
    plist: str             # path to the source file (kept name for FE compat)
    label: str             # unit name / launchd Label
    program: str           # resolved executable path
    run_at_load: bool      # autostarts on boot/login
    keep_alive: bool       # auto-restarts on exit
    start_interval: int | None = None
    sign_status: str       # apple / developer-id / ad-hoc / unsigned / invalid / missing
    sign_team: str = ""    # codesign team OR Linux package name
    sign_authority: str = ""  # codesign authority OR package manager
    suspicious_path: bool = False
    severity: str          # "info" | "warn" | "high"


def _classify(sign_status: str, suspicious: bool) -> str:
    if sign_status in ("missing", "invalid"):
        return "high"
    if suspicious:
        return "high"
    if sign_status in ("unsigned", "ad-hoc"):
        return "warn"
    return "info"


# ── Mac scanner (unchanged behaviour) ─────────────────────────────────────────

def _audit_mac() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    for source, base in MAC_PERSISTENCE_LOCATIONS:
        if not base.exists() or not base.is_dir():
            continue
        for path in sorted(base.glob("*.plist")):
            data = forensics.load_plist(path)
            if not data:
                continue
            program = forensics.plist_program(data)
            sign = (forensics.codesign_check(program) if program
                    else {"status": "missing", "team": "", "authority": ""})
            sus  = bool(program) and forensics.is_suspicious_path(program)
            entries.append(PersistenceEntry(
                source=source,
                plist=str(path),
                label=str(data.get("Label", path.stem)),
                program=program,
                run_at_load=bool(data.get("RunAtLoad", False)),
                keep_alive=bool(data.get("KeepAlive", False) if not isinstance(
                    data.get("KeepAlive"), dict) else True),
                start_interval=(data.get("StartInterval") if isinstance(
                    data.get("StartInterval"), int) else None),
                sign_status=sign["status"],
                sign_team=sign["team"],
                sign_authority=sign["authority"],
                suspicious_path=sus,
                severity=_classify(sign["status"], sus),
            ))
    return entries


# ── Linux scanner ─────────────────────────────────────────────────────────────

LINUX_SYSTEMD_SYSTEM_DIRS = [
    Path("/etc/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
]
LINUX_SYSTEMD_USER_DIRS = [
    Path.home() / ".config" / "systemd" / "user",
    Path("/etc/systemd/user"),
    Path("/usr/lib/systemd/user"),
]
LINUX_CRON_FILES = [
    Path("/etc/crontab"),
]
LINUX_CRON_DROPIN_DIRS = [
    Path("/etc/cron.d"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
]
LINUX_AUTOSTART_DIRS = [
    (Path.home() / ".config" / "autostart", "XDG Autostart (user)"),
    (Path("/etc/xdg/autostart"),            "XDG Autostart (system)"),
]


def _systemd_enabled(scope: str) -> set[str]:
    """Return the set of unit basenames enabled in the given scope.

    scope: "system" or "user". Falls back to an empty set if systemctl is
    unavailable or the user-bus isn't reachable (common in headless sessions).
    """
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return set()
    cmd = [systemctl]
    if scope == "user":
        cmd.append("--user")
    cmd += ["list-unit-files", "--no-legend", "--no-pager", "--state=enabled,static,alias"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
    except Exception:
        return set()
    out: set[str] = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts:
            out.add(parts[0])
    return out


def _parse_unit(path: Path) -> dict[str, str]:
    """Parse a systemd unit file into a flat dict {section.key: value}.

    systemd allows multiple ExecStart= lines; we keep the first one (good
    enough for the program target). configparser also lets multiple values
    coexist by appending.
    """
    cp = configparser.ConfigParser(interpolation=None, strict=False,
                                   inline_comment_prefixes=("#", ";"))
    cp.optionxform = str
    try:
        cp.read(path, encoding="utf-8")
    except Exception:
        return {}
    out: dict[str, str] = {}
    for section in cp.sections():
        for k, v in cp.items(section):
            # If a key repeats, configparser joins with \n — take the first line.
            out[f"{section}.{k}"] = v.split("\n", 1)[0].strip()
    return out


_EXEC_PREFIX_FLAGS = "-@:+!"   # systemd ExecStart= prefix characters


def _resolve_exec(execline: str) -> str:
    """Pull the binary path out of an ExecStart= value, stripping prefix flags.

    If the resulting first token isn't an absolute path, try `shutil.which()`
    so common bare names like `systemctl`, `udevadm`, `kmod` resolve to their
    real location instead of being misclassified as missing binaries.
    """
    s = execline.strip()
    while s and s[0] in _EXEC_PREFIX_FLAGS:
        s = s[1:].strip()
    if not s:
        return ""
    token = s.split()[0]
    if token.startswith("/"):
        return token
    resolved = shutil.which(token)
    return resolved if resolved else token


def _parse_oncalendar(spec: str) -> int | None:
    """Best-effort: convert common OnCalendar= specs to seconds. Returns None
    when the spec isn't a simple interval we recognise."""
    s = spec.strip().lower()
    if s in ("hourly", "*-*-* *:00:00"):
        return 3600
    if s in ("daily", "*-*-* 00:00:00"):
        return 86400
    if s == "weekly":
        return 7 * 86400
    if s == "monthly":
        return 30 * 86400
    return None


def _scan_systemd(dirs: list[Path], scope: str, source_label: str) -> list[PersistenceEntry]:
    enabled = _systemd_enabled(scope)
    seen: set[str] = set()
    entries: list[PersistenceEntry] = []
    for base in dirs:
        if not base.exists() or not base.is_dir():
            continue
        for path in sorted(list(base.glob("*.service")) + list(base.glob("*.timer"))):
            name = path.name
            if name in seen:                 # earlier dir wins (etc > usr/lib > lib)
                continue
            seen.add(name)

            # Skip generated/symlinked instance units (foo@.service) — the @
            # template itself never runs; its instantiations show up enabled.
            if "@" in name and not name.endswith("@.service"):
                pass  # instances are interesting, keep
            elif name.endswith("@.service"):
                continue

            fields = _parse_unit(path)
            execstart = fields.get("Service.ExecStart", "")
            program = _resolve_exec(execstart) if execstart else ""

            # Timer units have OnCalendar= / OnBootSec=; resolve their target
            # via the matching .service if present.
            interval: int | None = None
            if path.suffix == ".timer":
                cal = fields.get("Timer.OnCalendar", "")
                if cal:
                    interval = _parse_oncalendar(cal)
                # Best-effort: timers usually drive same-name services.
                if not program:
                    svc = path.with_suffix(".service")
                    if svc.exists():
                        program = _resolve_exec(_parse_unit(svc).get("Service.ExecStart", ""))

            restart = fields.get("Service.Restart", "no").lower()
            keep_alive = restart in ("always", "on-failure", "on-abnormal",
                                     "on-watchdog", "on-abort")
            run_at_load = name in enabled

            # No ExecStart resolved — could be a unit driven by ExecStartPre
            # only, a non-executable target wrapper, or an alias. Don't flag
            # as "missing binary" — that produces HIGH false-positives.
            if program:
                sign = forensics.linux_pkg_owner(program)
                sus = forensics.is_suspicious_path(program)
            else:
                sign = {"status": "", "team": "", "authority": "no-exec"}
                sus = False

            label = fields.get("Unit.Description") or path.stem
            entries.append(PersistenceEntry(
                source=source_label,
                plist=str(path),
                label=label,
                program=program,
                run_at_load=run_at_load,
                keep_alive=keep_alive,
                start_interval=interval,
                sign_status=sign["status"],
                sign_team=sign["team"],
                sign_authority=sign["authority"],
                suspicious_path=sus,
                severity=_classify(sign["status"], sus),
            ))
    return entries


_CRON_LINE_RE = re.compile(
    r"^\s*([^#@\s][^\s]*\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+[^\s]+)\s+(?:(\w+)\s+)?(.+)$"
)
_CRON_AT_RE = re.compile(r"^\s*(@\w+)\s+(?:(\w+)\s+)?(.+)$")


def _scan_cron_file(path: Path, source_label: str,
                    has_user_field: bool) -> list[PersistenceEntry]:
    """Parse a crontab-style file. /etc/crontab and /etc/cron.d/* have a user
    field; per-user crontabs don't."""
    entries: list[PersistenceEntry] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return entries

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" in line.split(None, 1)[0]:
            # skip blanks, comments, and FOO=bar env lines
            continue

        schedule = ""
        cmd = ""
        if line.startswith("@"):
            m = _CRON_AT_RE.match(line)
            if not m:
                continue
            schedule = m.group(1)
            cmd = m.group(3) if has_user_field else " ".join(filter(None, [m.group(2), m.group(3)]))
        else:
            m = _CRON_LINE_RE.match(line)
            if not m:
                continue
            schedule = m.group(1)
            cmd = m.group(3) if has_user_field else " ".join(filter(None, [m.group(2), m.group(3)]))

        program = cmd.split()[0] if cmd else ""
        if program and not program.startswith("/"):
            resolved = shutil.which(program)
            if resolved:
                program = resolved

        interval = {
            "@hourly":  3600,
            "@daily":   86400,
            "@midnight":86400,
            "@weekly":  7 * 86400,
            "@monthly": 30 * 86400,
            "@yearly":  365 * 86400,
            "@annually":365 * 86400,
            "@reboot":  None,
        }.get(schedule)

        sign = (forensics.linux_pkg_owner(program) if program
                else {"status": "missing", "team": "", "authority": ""})
        sus = bool(program) and forensics.is_suspicious_path(program)

        entries.append(PersistenceEntry(
            source=source_label,
            plist=f"{path}:{lineno}",
            label=f"cron · {schedule}",
            program=program,
            run_at_load=(schedule == "@reboot"),
            keep_alive=False,
            start_interval=interval,
            sign_status=sign["status"],
            sign_team=sign["team"],
            sign_authority=sign["authority"],
            suspicious_path=sus,
            severity=_classify(sign["status"], sus),
        ))
    return entries


def _scan_cron_dropin_dir(path: Path, source_label: str) -> list[PersistenceEntry]:
    """For /etc/cron.hourly etc. — each executable file in the dir runs."""
    entries: list[PersistenceEntry] = []
    if not path.exists() or not path.is_dir():
        return entries
    interval = {
        "cron.hourly":  3600,
        "cron.daily":   86400,
        "cron.weekly":  7 * 86400,
        "cron.monthly": 30 * 86400,
    }.get(path.name)
    for f in sorted(path.iterdir()):
        if not f.is_file():
            continue
        # Skip placeholder/readme files.
        if f.name in ("0anacron", ".placeholder", "README"):
            continue
        program = str(f)
        sign = forensics.linux_pkg_owner(program)
        sus = forensics.is_suspicious_path(program)
        entries.append(PersistenceEntry(
            source=source_label,
            plist=str(f),
            label=f.name,
            program=program,
            run_at_load=False,
            keep_alive=False,
            start_interval=interval,
            sign_status=sign["status"],
            sign_team=sign["team"],
            sign_authority=sign["authority"],
            suspicious_path=sus,
            severity=_classify(sign["status"], sus),
        ))
    return entries


def _scan_user_crontab() -> list[PersistenceEntry]:
    crontab = shutil.which("crontab")
    if not crontab:
        return []
    try:
        r = subprocess.run([crontab, "-l"], capture_output=True, text=True, timeout=4)
    except Exception:
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    # Reuse the file parser by writing to /dev/stdin-style buffer — easiest is
    # to materialise a temp Path-like object. Keep it simple: write to a tmp
    # file and parse, then delete. Tiny — fine.
    import tempfile
    user = os.environ.get("USER", "user")
    with tempfile.NamedTemporaryFile("w", suffix=".cron", delete=False) as fh:
        fh.write(r.stdout)
        tmp = Path(fh.name)
    try:
        out = _scan_cron_file(tmp, f"Cron (user {user})", has_user_field=False)
    finally:
        try: tmp.unlink()
        except Exception: pass
    return out


def _scan_autostart(base: Path, source_label: str) -> list[PersistenceEntry]:
    """Parse .desktop entries. Skip Hidden=true and X-GNOME-Autostart-enabled=false."""
    entries: list[PersistenceEntry] = []
    if not base.exists() or not base.is_dir():
        return entries
    for path in sorted(base.glob("*.desktop")):
        cp = configparser.ConfigParser(interpolation=None, strict=False,
                                       inline_comment_prefixes=("#",))
        cp.optionxform = str
        try:
            cp.read(path, encoding="utf-8")
        except Exception:
            continue
        if "Desktop Entry" not in cp:
            continue
        sect = cp["Desktop Entry"]
        if sect.get("Hidden", "false").lower() == "true":
            continue
        if sect.get("X-GNOME-Autostart-enabled", "true").lower() == "false":
            continue
        exec_line = sect.get("Exec", "")
        program = _resolve_exec(exec_line) if exec_line else ""
        if program and not program.startswith("/"):
            resolved = shutil.which(program)
            if resolved:
                program = resolved
        sign = (forensics.linux_pkg_owner(program) if program
                else {"status": "missing", "team": "", "authority": ""})
        sus = bool(program) and forensics.is_suspicious_path(program)
        entries.append(PersistenceEntry(
            source=source_label,
            plist=str(path),
            label=sect.get("Name", path.stem),
            program=program,
            run_at_load=True,
            keep_alive=False,
            sign_status=sign["status"],
            sign_team=sign["team"],
            sign_authority=sign["authority"],
            suspicious_path=sus,
            severity=_classify(sign["status"], sus),
        ))
    return entries


def _scan_rc_local() -> list[PersistenceEntry]:
    rc = Path("/etc/rc.local")
    if not rc.exists() or not rc.is_file():
        return []
    # rc.local is a shell script. We surface it as a single entry pointing at
    # the file itself — flag if world-writable or contains a /tmp invocation.
    try:
        st = rc.stat()
    except OSError:
        return []
    program = "/etc/rc.local"
    sign = forensics.linux_pkg_owner(program)
    sus = False
    try:
        body = rc.read_text(encoding="utf-8", errors="replace")
        sus = any(p in body for p in ("/tmp/", "/var/tmp/", "/dev/shm/"))
    except Exception:
        pass
    # World-writable rc.local → high.
    if st.st_mode & 0o002:
        sign = {"status": "invalid", "team": "", "authority": "world-writable"}
    return [PersistenceEntry(
        source="rc.local",
        plist=program,
        label="rc.local",
        program=program,
        run_at_load=True,
        keep_alive=False,
        sign_status=sign["status"],
        sign_team=sign["team"],
        sign_authority=sign["authority"],
        suspicious_path=sus,
        severity=_classify(sign["status"], sus),
    )]


def _audit_linux() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    entries += _scan_systemd(LINUX_SYSTEMD_SYSTEM_DIRS, "system", "Systemd (system)")
    entries += _scan_systemd(LINUX_SYSTEMD_USER_DIRS,   "user",   "Systemd (user)")
    for cron_file in LINUX_CRON_FILES:
        if cron_file.exists():
            entries += _scan_cron_file(cron_file, "Cron (/etc/crontab)", has_user_field=True)
    for d in LINUX_CRON_DROPIN_DIRS:
        if d.name == "cron.d":
            for f in sorted(d.glob("*")):
                if f.is_file():
                    entries += _scan_cron_file(f, "Cron (/etc/cron.d)", has_user_field=True)
        else:
            entries += _scan_cron_dropin_dir(d, f"Cron ({d.name})")
    entries += _scan_user_crontab()
    for base, label in LINUX_AUTOSTART_DIRS:
        entries += _scan_autostart(base, label)
    entries += _scan_rc_local()
    return entries


# ── public endpoint ───────────────────────────────────────────────────────────

# ── Windows scanner ──────────────────────────────────────────────────────────
# Three persistence vectors covered here:
#   1. Registry Run/RunOnce keys (HKLM + HKCU, plus the 32-bit Wow6432Node view)
#   2. Startup folders (per-user and all-users)
#   3. Scheduled Tasks (schtasks /Query)
# Services left for a future pass — they're noisier and most aren't "persistence"
# in the forensic sense.

# (hive_name, root_const, subkey) — populated lazily on Windows only because
# `winreg` does not exist on non-Windows interpreters.
def _windows_run_keys() -> list[tuple[str, Any, str]]:
    import winreg  # type: ignore[import-not-found]
    return [
        ("HKLM Run",         winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM RunOnce",     winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM Run (Wow64)", winreg.HKEY_LOCAL_MACHINE,
         r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU Run",         winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU RunOnce",     winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]


_WIN_SUS_PATH_PREFIXES = (
    # %TEMP% / %TMP% — both per-user and system
    "appdata\\local\\temp\\",
    "windows\\temp\\",
    # Public-writable share — common dropper location
    "users\\public\\",
    # Recycle-bin / volume-shadow tricks
    "$recycle.bin\\",
)


def _win_is_suspicious(program: str) -> bool:
    if not program:
        return False
    p = program.lower().replace("/", "\\")
    return any(prefix in p for prefix in _WIN_SUS_PATH_PREFIXES)


def _win_unquote_command(value: str) -> str:
    """Extract the executable path from a registry RunOnce command string.

    Windows RunOnce values often look like:  "C:\\Path\\To\\app.exe" --flag arg
    We want just the path so we can stat it. Returns "" if we can't parse.
    """
    v = value.strip()
    if not v:
        return ""
    # Strip "!" prefix (RunOnce "delete on success" marker) and "*" prefix
    # ("run even in safe mode").
    while v[:1] in ("!", "*"):
        v = v[1:].strip()
    if v.startswith('"'):
        end = v.find('"', 1)
        return v[1:end] if end > 0 else v[1:]
    return v.split()[0] if v else ""


def _win_expand(program: str) -> str:
    """Expand %SystemRoot% / %ProgramFiles% / etc in a path string.

    Registry Run values often contain unexpanded environment variables
    (`%windir%\\AzureArcSetup\\...`); Path.is_file() against those strings
    returns False even when the file exists, which used to misclassify
    every env-var entry as 'missing'. Expand once at scan time so both the
    heuristic and the Authenticode batch see real paths.
    """
    if not program:
        return ""
    return os.path.expandvars(program)


def _win_sign_status(program: str) -> dict[str, str]:
    """Best-effort signature read for a Windows file. Path-heuristic only —
    `_audit_windows()` overwrites this with real Authenticode results where
    available, so this only kicks in when PowerShell is unavailable or
    Get-AuthenticodeSignature times out.

    Returns the same {status, team, authority} shape as the Mac/Linux
    sign-check helpers so the rest of the audit machinery is unchanged.
    """
    if not program:
        return {"status": "missing", "team": "", "authority": ""}
    expanded = _win_expand(program)
    try:
        exists = Path(expanded).is_file()
    except OSError:
        exists = False
    if not exists:
        return {"status": "missing", "team": "", "authority": ""}
    sysroot = os.environ.get("SystemRoot") or r"C:\Windows"
    progf = os.environ.get("ProgramFiles") or r"C:\Program Files"
    progf86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    low = expanded.lower()
    if low.startswith(sysroot.lower()):
        return {"status": "apple", "team": "Microsoft", "authority": "SystemRoot"}
    if low.startswith(progf.lower()) or low.startswith(progf86.lower()):
        return {"status": "developer-id", "team": "", "authority": "Program Files"}
    return {"status": "unsigned", "team": "", "authority": ""}


# ── Authenticode batch (single PowerShell session for N paths) ───────────────

def _parse_subject(subject: str) -> tuple[str, str]:
    """Pull (CN, O) out of an X.500 subject string like
    `CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`.
    Splits on top-level commas only — values containing literal commas are
    rare in code-signing certs but we still handle the common case.
    """
    cn = org = ""
    for raw in subject.split(","):
        part = raw.strip()
        up = part.upper()
        if up.startswith("CN="):
            cn = part[3:].strip()
        elif up.startswith("O="):
            org = part[2:].strip()
    return cn, org


def _authenticode_batch(paths: list[str], timeout: float = 30.0) -> dict[str, dict[str, str]]:
    """Run Get-AuthenticodeSignature on a batch of paths in a single
    PowerShell session. Returns `{path: {status, team, authority}}`.

    Status mapping into the cross-platform vocabulary:
      * Status=Valid + Microsoft publisher → "apple" (trusted system signer)
      * Status=Valid + other publisher     → "developer-id"
      * Status=NotSigned                   → "unsigned"
      * Status=HashMismatch / NotTrusted / etc → "invalid"

    Returns `{}` on any error (PowerShell missing, timeout, JSON parse fail)
    so the caller falls back to the path heuristic. We pre-filter `paths` to
    existing files — Get-AuthenticodeSignature on a non-existent path emits
    a non-fatal error to stderr but skips the entry, which messes up the
    output-to-input alignment.
    """
    if not paths:
        return {}
    # Dedupe + filter to actually-existing files.
    existing = sorted({p for p in paths if p and Path(p).is_file()})
    if not existing:
        return {}

    quoted = ["'" + p.replace("'", "''") + "'" for p in existing]
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$ProgressPreference='SilentlyContinue';"
        "$paths = @(" + ",".join(quoted) + ");"
        "Get-AuthenticodeSignature -LiteralPath $paths | "
        "Select-Object @{N='Path';E={$_.Path}}, "
                     "@{N='Status';E={[string]$_.Status}}, "
                     "@{N='Subject';E={if ($_.SignerCertificate) { $_.SignerCertificate.Subject } else { '' }}} | "
        "ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    try:
        data = json.loads(r.stdout)
    except Exception:                                  # noqa: BLE001
        return {}
    if isinstance(data, dict):
        data = [data]

    out: dict[str, dict[str, str]] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("Path", "") or "")
        if not path:
            continue
        status_str = str(entry.get("Status", "") or "").strip()
        subject = str(entry.get("Subject", "") or "")
        cn, org = _parse_subject(subject)

        if status_str == "Valid":
            is_microsoft = "microsoft" in cn.lower() or "microsoft" in org.lower()
            if is_microsoft:
                out[path] = {"status": "apple",
                             "team": org or cn or "Microsoft",
                             "authority": "Authenticode"}
            else:
                out[path] = {"status": "developer-id",
                             "team": cn or org or "",
                             "authority": "Authenticode"}
        elif status_str == "NotSigned":
            out[path] = {"status": "unsigned", "team": "", "authority": ""}
        elif status_str in ("HashMismatch", "NotTrusted", "UnknownError",
                            "Incompatible", "NotSupportedFileFormat"):
            out[path] = {"status": "invalid", "team": "", "authority": status_str}
        else:
            # Unknown status — be conservative, mark unsigned
            out[path] = {"status": "unsigned", "team": "", "authority": status_str}
    return out


def _scan_windows_run_keys() -> list[PersistenceEntry]:
    import winreg  # type: ignore[import-not-found]
    entries: list[PersistenceEntry] = []
    for label, hive, subkey in _windows_run_keys():
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    name, value, _vtype = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                program = _win_expand(_win_unquote_command(str(value)))
                sign = _win_sign_status(program)
                sus = _win_is_suspicious(program)
                entries.append(PersistenceEntry(
                    source=label,
                    plist=f"{label}\\{name}",
                    label=str(name),
                    program=program,
                    run_at_load=True,
                    keep_alive=False,
                    sign_status=sign["status"],
                    sign_team=sign["team"],
                    sign_authority=sign["authority"],
                    suspicious_path=sus,
                    severity=_classify(sign["status"], sus),
                ))
        finally:
            winreg.CloseKey(key)
    return entries


def _scan_windows_startup_folders() -> list[PersistenceEntry]:
    candidates: list[tuple[str, Path]] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(("Startup (user)",
                           Path(appdata) / "Microsoft" / "Windows" / "Start Menu" /
                           "Programs" / "Startup"))
    programdata = os.environ.get("ProgramData") or r"C:\ProgramData"
    candidates.append(("Startup (all users)",
                       Path(programdata) / "Microsoft" / "Windows" / "Start Menu" /
                       "Programs" / "StartUp"))

    entries: list[PersistenceEntry] = []
    for label, base in candidates:
        if not base.exists() or not base.is_dir():
            continue
        for path in sorted(base.iterdir()):
            if not path.is_file():
                continue
            # .lnk shortcuts dominate but .bat / .exe also valid. We can't
            # cheaply parse .lnk targets from stdlib, so we surface the
            # shortcut path itself and let the user resolve it.
            program = str(path)
            sign = _win_sign_status(program)
            sus = _win_is_suspicious(program)
            entries.append(PersistenceEntry(
                source=label,
                plist=str(path),
                label=path.name,
                program=program,
                run_at_load=True,
                keep_alive=False,
                sign_status=sign["status"],
                sign_team=sign["team"],
                sign_authority=sign["authority"],
                suspicious_path=sus,
                severity=_classify(sign["status"], sus),
            ))
    return entries


def _scan_windows_scheduled_tasks() -> list[PersistenceEntry]:
    """Parse `schtasks /Query /FO CSV /V` output.

    Verbose CSV is the only stable cross-version format. We filter to tasks
    that are *enabled* and have a real "Task To Run" target — disabled and
    folder-marker rows produce garbage entries otherwise.
    """
    schtasks = shutil.which("schtasks") or r"C:\Windows\System32\schtasks.exe"
    try:
        r = subprocess.run(
            [schtasks, "/Query", "/FO", "CSV", "/V", "/NH"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception:
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []

    # schtasks emits one CSV per row, no header (we passed /NH).
    # Columns (Win10/11 default):
    #   0 HostName, 1 TaskName, 2 NextRunTime, 3 Status, 4 LogonMode,
    #   5 LastRunTime, 6 LastResult, 7 Author, 8 TaskToRun, 9 StartIn,
    #   10 Comment, 11 ScheduledTaskState, 12 IdleTime, 13 PowerManagement,
    #   14 RunAsUser, 15 DeleteWhenDone, 16 ScheduleType, 17 StartTime,
    #   18 StartDate, 19 EndDate, 20 Days, 21 Months, 22 RepeatEvery,
    #   23 RepeatUntilTime, 24 RepeatUntilDuration, 25 RepeatStop, 26 Idle
    entries: list[PersistenceEntry] = []
    reader = csv.reader(io.StringIO(r.stdout))
    for row in reader:
        if len(row) < 12:
            continue
        task_name = row[1].strip()
        task_to_run = row[8].strip()
        state = row[11].strip()
        if not task_name or task_name.lower() == "taskname":
            continue
        if state.lower() == "disabled":
            continue
        # "TaskName" header rows reappear between hosts on some Win10 builds.
        if task_name.startswith("TaskName"):
            continue

        program = _win_expand(_win_unquote_command(task_to_run))
        sign = _win_sign_status(program) if program else {
            "status": "missing", "team": "", "authority": "",
        }
        sus = _win_is_suspicious(program)
        entries.append(PersistenceEntry(
            source="Scheduled Tasks",
            plist=task_name,
            label=task_name.lstrip("\\"),
            program=program,
            run_at_load=row[16].strip().lower() in ("at logon time", "at startup", "on boot"),
            keep_alive=False,
            sign_status=sign["status"],
            sign_team=sign["team"],
            sign_authority=sign["authority"],
            suspicious_path=sus,
            severity=_classify(sign["status"], sus),
        ))
    return entries


def _audit_windows() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    try:
        entries += _scan_windows_run_keys()
    except Exception as exc:                            # noqa: BLE001
        # winreg should always be importable on real Windows; if it isn't
        # we're in a weird environment — surface a synthetic warn entry so
        # the UI shows something rather than a blank list.
        entries.append(PersistenceEntry(
            source="Registry", plist="winreg",
            label=f"registry scan failed: {exc}",
            program="", run_at_load=False, keep_alive=False,
            sign_status="invalid", sign_team="", sign_authority="error",
            suspicious_path=False, severity="warn",
        ))
    entries += _scan_windows_startup_folders()
    entries += _scan_windows_scheduled_tasks()

    # Authenticode pass: batch every distinct program path through one
    # PowerShell session and overwrite the heuristic sign_status with the
    # real certificate verdict where it succeeds. Entries whose path isn't
    # in the result keep their heuristic classification — fail-safe by design.
    paths = [e.program for e in entries if e.program]
    sign_map = _authenticode_batch(paths)
    if sign_map:
        for e in entries:
            if not e.program:
                continue
            sign = sign_map.get(e.program)
            if sign is None:
                continue
            e.sign_status    = sign["status"]
            e.sign_team      = sign["team"]
            e.sign_authority = sign["authority"]
            # Re-classify severity since sign_status may have shifted; e.g.
            # a SystemRoot binary that the heuristic called "apple" might
            # actually be Authenticode-Invalid (HashMismatch / NotTrusted).
            e.severity = _classify(e.sign_status, e.suspicious_path)
    return entries


@router.get("/persistence/audit")
def audit() -> dict[str, list[PersistenceEntry]]:
    if IS_DARWIN:
        entries = _audit_mac()
    elif IS_LINUX:
        entries = _audit_linux()
    elif IS_WINDOWS:
        entries = _audit_windows()
    else:
        entries = []
    sev_order = {"high": 0, "warn": 1, "info": 2}
    entries.sort(key=lambda e: (sev_order[e.severity], e.source, e.label))
    return {"entries": entries}
