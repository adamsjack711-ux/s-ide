"""Linux users / accounts audit.

  GET /users/audit

Pulls together:
  - /etc/passwd → real users (UID >= 1000) and system users with shells
  - sudo / wheel / admin group members (via /etc/group)
  - last logins (lastlog -t 90 → recent 90 days)
  - per-user ~/.ssh/authorized_keys (when readable) with key fingerprints
  - sudoers files: perms + non-default contents in /etc/sudoers.d
  - findings rollup with severity tagging
"""
from __future__ import annotations

import base64
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from lib import scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode

router = APIRouter(tags=["users"], dependencies=[Depends(require_local_auth)])

IS_LINUX = sys.platform.startswith("linux")


def _require_linux() -> None:
    if not IS_LINUX:
        raise HTTPException(501, "users audit is Linux-only")


# ── /etc/passwd ──────────────────────────────────────────────────────────────

# Login shells we treat as "interactive" — others are nologin/false/sync.
_LOGIN_SHELLS = {
    "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/bin/ash",
    "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish",
    "/bin/fish", "/bin/ksh", "/usr/bin/ksh",
}


def _parse_passwd() -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    try:
        text = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return users
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_i = int(uid)
            gid_i = int(gid)
        except ValueError:
            continue
        users.append({
            "name":  name,
            "uid":   uid_i,
            "gid":   gid_i,
            "gecos": gecos,
            "home":  home,
            "shell": shell,
            "is_login":  shell in _LOGIN_SHELLS,
            "is_system": uid_i < 1000,
        })
    return users


# ── /etc/group → sudo / wheel / admin members ────────────────────────────────

def _privileged_group_members() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    try:
        text = Path("/etc/group").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name = parts[0]
        if name in ("sudo", "wheel", "admin", "root", "adm"):
            members = [m for m in parts[3].split(",") if m]
            out[name] = members
    return out


# ── lastlog ──────────────────────────────────────────────────────────────────

def _last_logins(days: int = 90) -> dict[str, str]:
    """{user: 'Mon May 22 14:23:55 -0400 2026'} from `lastlog -t <days>`.
    Users with no recent login are absent from the dict."""
    out: dict[str, str] = {}
    lastlog = shutil.which("lastlog")
    if not lastlog:
        return out
    try:
        r = subprocess.run([lastlog, "-t", str(days)],
                           capture_output=True, text=True, timeout=6)
    except subprocess.TimeoutExpired:
        return out
    # Header: "Username         Port     From             Latest"
    for line in r.stdout.splitlines()[1:]:
        # The trailing date can have spaces; split on first ≥2 whitespace blocks.
        # Use a fixed-width-ish approach: name is field 1, latest starts after
        # "From" which can be empty.
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 2:
            user = line.split()[0]
            # Last "column" is the timestamp; if only 2 columns it might be
            # "Port" — skip those.
            latest = parts[-1].strip()
            if latest and "Never" not in latest:
                out[user] = latest
    return out


# ── SSH authorized_keys ──────────────────────────────────────────────────────

_KEY_PATTERN = re.compile(
    r"^\s*((?:ssh-|ecdsa-|sk-)[a-z0-9\-]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$"
)


def _key_fingerprint(b64key: str) -> str:
    """SHA256 fingerprint matching `ssh-keygen -lf`."""
    try:
        raw = base64.b64decode(b64key)
    except Exception:
        return ""
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode("ascii")


def _ssh_keys_for(home: Path) -> list[dict[str, str]]:
    """Returns [{type, fingerprint, comment, perms_ok}] or [] if unreadable."""
    keys: list[dict[str, str]] = []
    ak = home / ".ssh" / "authorized_keys"
    try:
        st = ak.stat()
    except OSError:
        return keys
    mode = st.st_mode & 0o777
    perms_ok = (mode & 0o077) == 0  # group/other should have no perms
    try:
        text = ak.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        # We see the file but can't read it (running as a different user) —
        # surface that as a single entry so the UI knows it exists.
        return [{"type": "(unreadable)", "fingerprint": "",
                 "comment": str(ak), "perms_ok": str(perms_ok)}]
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _KEY_PATTERN.match(line)
        if not m:
            continue
        ktype, b64, comment = m.group(1), m.group(2), (m.group(3) or "")
        keys.append({
            "type":        ktype,
            "fingerprint": _key_fingerprint(b64),
            "comment":     comment.strip(),
            "perms_ok":    "true" if perms_ok else "false",
        })
    return keys


# ── sudoers permissions ──────────────────────────────────────────────────────

def _sudoers_audit() -> dict[str, Any]:
    out: dict[str, Any] = {
        "sudoers_perms": "",
        "world_writable": [],
        "non_root_owned": [],
        "dropin_files":   [],
    }
    main = Path("/etc/sudoers")
    try:
        st = main.stat()
        out["sudoers_perms"] = f"{st.st_mode & 0o777:04o}"
    except OSError:
        pass
    drop = Path("/etc/sudoers.d")
    if drop.exists() and drop.is_dir():
        try:
            for f in sorted(drop.iterdir()):
                try:
                    st = f.stat()
                except OSError:
                    continue
                mode = st.st_mode & 0o777
                out["dropin_files"].append({"path": str(f),
                                            "perms": f"{mode:04o}",
                                            "uid":   st.st_uid})
                if mode & 0o002:
                    out["world_writable"].append(str(f))
                if st.st_uid != 0:
                    out["non_root_owned"].append({"path": str(f), "uid": st.st_uid})
        except OSError:
            pass
    return out


# ── findings rollup ──────────────────────────────────────────────────────────

def _classify(users: list[dict[str, Any]],
              groups: dict[str, list[str]],
              keys_by_user: dict[str, list[dict[str, str]]],
              sudo: dict[str, Any]) -> list[dict[str, Any]]:
    f: list[dict[str, Any]] = []

    # UID 0 collision detection (only root should have uid=0)
    uid0 = [u["name"] for u in users if u["uid"] == 0]
    if len(uid0) > 1:
        f.append({"severity": "high", "label": f"Multiple UID-0 accounts: {uid0}",
                  "detail": "Only `root` should have UID 0. Extra accounts may be backdoors."})

    # Interactive non-system users
    for u in users:
        if u["is_login"] and not u["is_system"] and u["name"] != "root":
            f.append({"severity": "info", "label": f"User {u['name']} (uid {u['uid']}) has login shell {u['shell']}"})
        # Login-shell on a system account is suspicious
        if u["is_login"] and u["is_system"]:
            f.append({"severity": "warn",
                      "label": f"System account {u['name']} (uid {u['uid']}) has login shell {u['shell']}",
                      "detail": "System accounts typically use /usr/sbin/nologin or /bin/false."})

    # Privileged group membership
    for grp, members in groups.items():
        for m in members:
            if grp in ("sudo", "wheel", "admin"):
                f.append({"severity": "warn",
                          "label": f"{m} ∈ {grp} (passwordless? check NOPASSWD)"})

    # Authorized keys: bad perms
    for user, keys in keys_by_user.items():
        for k in keys:
            if k["perms_ok"] == "false":
                f.append({"severity": "high",
                          "label": f"~{user}/.ssh/authorized_keys is group/world-readable",
                          "detail": "sshd may refuse to use the file; also a credentials disclosure."})
                break

    # Sudoers
    if sudo["sudoers_perms"] and sudo["sudoers_perms"] not in ("0440", "0400"):
        f.append({"severity": "warn",
                  "label": f"/etc/sudoers perms {sudo['sudoers_perms']} (want 0440)"})
    for w in sudo["world_writable"]:
        f.append({"severity": "high", "label": f"world-writable {w}",
                  "detail": "Any user can grant themselves sudo by editing."})
    for n in sudo["non_root_owned"]:
        f.append({"severity": "high",
                  "label": f"{n['path']} owned by uid {n['uid']}",
                  "detail": "Sudoers files must be owned by root (uid 0)."})

    return f


# ── public endpoint ──────────────────────────────────────────────────────────

@router.get("/users/audit")
def audit(request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    _require_linux()
    users = _parse_passwd()
    groups = _privileged_group_members()
    lastlogs = _last_logins()
    sudo = _sudoers_audit()

    # SSH keys per interactive user (skip system accounts to keep it fast).
    keys_by_user: dict[str, list[dict[str, str]]] = {}
    for u in users:
        if not u["is_login"]:
            continue
        keys = _ssh_keys_for(Path(u["home"]))
        if keys:
            keys_by_user[u["name"]] = keys

    # Stitch last-login times onto users for convenience
    for u in users:
        u["last_login"] = lastlogs.get(u["name"], "")

    findings = _classify(users, groups, keys_by_user, sudo)

    return {
        "users":             users,
        "privileged_groups": groups,
        "ssh_keys":          keys_by_user,
        "sudoers":           sudo,
        "findings":          findings,
        "summary": {
            "total_users":      len(users),
            "login_users":      sum(1 for u in users if u["is_login"]),
            "system_users":     sum(1 for u in users if u["is_system"]),
            "privileged_groups": len(groups),
            "users_with_ssh_keys": len(keys_by_user),
        },
    }
