"""IDS helpers — listening-port snapshot + auth-log classification."""
from __future__ import annotations

import re
import subprocess

# Process names that ship with macOS — finding them in the baseline doesn't
# warrant a warning (just informational).
KNOWN_LISTENERS: frozenset[str] = frozenset({
    "launchd", "mDNSResponder", "mDNSResponderHelper", "rapportd",
    "ControlCenter", "sharingd", "AirPlayXPCHelper", "AirPlayUIAgent",
    "remoted", "cloudd", "rpcbind", "smbd", "afpd", "configd", "syslogd",
    "sshd-keygen-wrapper", "nsurlsessiond", "accountsd", "secd", "trustd",
    "screencaptured", "softwareupdated", "identityservicesd",
    "WirelessRadioManagerd",
})

AUTH_FAIL_PATTERNS: tuple[str, ...] = (
    "authentication failure",
    "authentication failed",
    "failed password",
    "incorrect password",
    "auth failed",
    "invalid user",
    "permission denied",
)

LOG_PREDICATE = (
    '(eventMessage CONTAINS[c] "failed password") OR '
    '(eventMessage CONTAINS[c] "authentication failure") OR '
    '(eventMessage CONTAINS[c] "authentication failed") OR '
    '(eventMessage CONTAINS[c] "incorrect password") OR '
    '(eventMessage CONTAINS[c] "invalid user") OR '
    '(process == "sudo" AND eventMessage CONTAINS[c] "incorrect")'
)

_LSOF_ESC_RE     = re.compile(r"\\x([0-9a-fA-F]{2})")
_SYSLOG_LINE_RE  = re.compile(
    r"^\S+\s+\S+(?:[+-]\d{4})?\s+\S+\s+(\S+\[\d+\]):\s+(.*)$"
)
_SUBSYSTEM_RE    = re.compile(r"^\([^)]*\)\s+")
_BRACKET_TAG_RE  = re.compile(r"\[com\.apple\.[^\]]+\]\s*")
_OBJC_METHOD_RE  = re.compile(r"-\[[^\]]+\]\s+\|\s*")
_PROC_PID_RE     = re.compile(r"\b([A-Za-z_][\w.-]*)\[\d+\]")


def lsof_unescape(name: str) -> str:
    return _LSOF_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), name)


def listening_snapshot() -> set[tuple[str, str, int, int, str]]:
    """Return {(proto, addr, port, pid, command), ...} for TCP listeners + UDP sockets."""
    snapshot: set[tuple[str, str, int, int, str]] = set()

    def parse(lines: list[str], proto: str, listen_only: bool):
        for line in lines[1:]:    # skip header
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            command, pid_str = parts[0], parts[1]
            tail = parts[8].strip()
            if listen_only and "(LISTEN)" not in tail:
                continue
            name_addr = tail.split(" ", 1)[0]
            m = re.match(r"(\[[^\]]+\]|[^:]+):(\d+)$", name_addr)
            if not m:
                continue
            try:
                snapshot.add((proto, m.group(1), int(m.group(2)),
                              int(pid_str), lsof_unescape(command)))
            except ValueError:
                continue

    for proto, flags, listen_only in (
        ("TCP", ["-iTCP", "-sTCP:LISTEN"], True),
        ("UDP", ["-iUDP"],                 False),
    ):
        try:
            r = subprocess.run(["lsof", "+c0", *flags, "-n", "-P"],
                               capture_output=True, text=True, timeout=8)
            parse(r.stdout.splitlines(), proto, listen_only)
        except Exception:
            pass
    return snapshot


def clean_auth_line(line: str) -> str:
    """Reduce a noisy syslog line to 'process[pid]  meaningful message'."""
    m = _SYSLOG_LINE_RE.match(line.strip())
    if not m:
        return line.strip()
    proc_pid, msg = m.group(1), m.group(2)
    msg = _SUBSYSTEM_RE.sub("", msg)
    msg = _BRACKET_TAG_RE.sub("", msg)
    msg = _OBJC_METHOD_RE.sub("", msg)
    return f"{proc_pid}  {msg.strip()}"


def classify_auth_line(line: str) -> tuple[str, str, str] | None:
    """Return (severity, process_key, summary) or None if line isn't an auth event."""
    # Reject `log stream`'s own "Filtering the log data using ..." banner
    if not _PROC_PID_RE.search(line):
        return None
    lo = line.lower()
    if not any(p in lo for p in AUTH_FAIL_PATTERNS):
        if not ("sudo" in lo and ("incorrect" in lo or "fail" in lo)):
            return None
    severity = "high" if ("invalid user" in lo or "failed password" in lo) else "warn"
    summary = clean_auth_line(line)
    proc_match = _PROC_PID_RE.search(line)
    process_key = proc_match.group(1) if proc_match else "auth"
    if len(summary) > 220:
        summary = summary[:217] + "..."
    return severity, process_key, summary
