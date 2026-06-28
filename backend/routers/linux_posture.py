"""Linux security posture snapshot.

REST  GET /linux/posture

Returns a structured report on:
  - **MAC**            — SELinux / AppArmor enforcement state
  - **Firewall**       — UFW or firewalld active rules count
  - **SSH**            — /etc/ssh/sshd_config: root login, password auth,
                         X11 forwarding, max auth tries
  - **Kernel**         — sysctl hardening flags (kptr_restrict, dmesg_restrict,
                         randomize_va_space, ip_forward)
  - **Updates**        — pending package upgrades (apt / dnf / pacman)
  - **Sudo**           — perms on /etc/sudoers and /etc/sudoers.d/*
  - **Disk**           — LUKS encryption presence
  - **Findings**       — severity-tagged rollup

Mirrors the response shape of `routers/macos_posture.py` where it makes
sense: nested per-section dicts + a flat `findings` list.

All probes run as the backend's user — no privilege escalation here.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from lib import scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode
from lib.platform_util import require_linux

router = APIRouter(tags=["linux"], dependencies=[Depends(require_local_auth)])


def _run(cmd: list[str], timeout: int = 6) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


# ── Mandatory Access Control (SELinux + AppArmor) ────────────────────────────

def _mac() -> dict[str, Any]:
    out: dict[str, Any] = {"selinux": "absent", "apparmor": "absent",
                           "enforcing_profiles": 0, "raw": ""}

    se = shutil.which("getenforce")
    if se:
        s = _run([se]).lower()
        if "enforc" in s:    out["selinux"] = "enforcing"
        elif "permissive" in s: out["selinux"] = "permissive"
        elif "disabled" in s:   out["selinux"] = "disabled"
        else:                   out["selinux"] = "unknown"
        out["raw"] += f"selinux: {s}\n"

    aa = shutil.which("aa-status") or shutil.which("apparmor_status")
    if aa:
        s = _run([aa])
        out["raw"] += f"apparmor: {s[:200]}\n"
        if "is loaded" in s:
            out["apparmor"] = "loaded"
        m = re.search(r"(\d+)\s+profiles? are in enforce mode", s)
        if m:
            out["enforcing_profiles"] = int(m.group(1))
            out["apparmor"] = "enforcing"

    return out


# ── Firewall (UFW first, firewalld second, raw iptables last) ────────────────

def _firewall() -> dict[str, Any]:
    out: dict[str, Any] = {"backend": "none", "active": False,
                           "rules": 0, "raw": ""}

    ufw = shutil.which("ufw")
    if ufw:
        s = _run([ufw, "status"])
        out["raw"] = s
        out["backend"] = "ufw"
        if re.search(r"^Status:\s*active", s, re.MULTILINE):
            out["active"] = True
            # crude rule count: lines starting with ALLOW/DENY/LIMIT/REJECT
            out["rules"] = sum(
                1 for line in s.splitlines()
                if re.search(r"\b(ALLOW|DENY|LIMIT|REJECT)\b", line)
            )
        return out

    fcmd = shutil.which("firewall-cmd")
    if fcmd:
        state = _run([fcmd, "--state"]).lower()
        out["backend"] = "firewalld"
        out["active"] = state.startswith("running")
        if out["active"]:
            rules = _run([fcmd, "--list-all"])
            out["raw"] = rules
            out["rules"] = sum(1 for l in rules.splitlines() if l.strip() and ":" in l)
        return out

    ipt = shutil.which("iptables")
    if ipt:
        # `iptables -L -n` requires CAP_NET_ADMIN; non-root → empty output.
        s = _run([ipt, "-S"])
        if s:
            out["backend"] = "iptables"
            out["raw"] = s
            # rules other than the default policy lines (-P ...)
            out["rules"] = sum(1 for l in s.splitlines() if l.startswith("-A "))
            out["active"] = out["rules"] > 0
        else:
            out["backend"] = "iptables (insufficient perms)"
    return out


# ── SSH config ───────────────────────────────────────────────────────────────

_SSHD_PATH = Path("/etc/ssh/sshd_config")
_SSHD_DROPIN = Path("/etc/ssh/sshd_config.d")


def _sshd_config() -> dict[str, Any]:
    out: dict[str, Any] = {
        "present": False,
        "permit_root_login": "unset",
        "password_authentication": "unset",
        "x11_forwarding": "unset",
        "max_auth_tries": "unset",
        "kbdint_authentication": "unset",
        "raw_path": str(_SSHD_PATH),
    }
    files: list[Path] = []
    if _SSHD_PATH.exists():
        files.append(_SSHD_PATH)
        out["present"] = True
    if _SSHD_DROPIN.exists() and _SSHD_DROPIN.is_dir():
        files.extend(sorted(_SSHD_DROPIN.glob("*.conf")))
    if not files:
        return out

    keys = {
        "PermitRootLogin":           "permit_root_login",
        "PasswordAuthentication":    "password_authentication",
        "X11Forwarding":             "x11_forwarding",
        "MaxAuthTries":              "max_auth_tries",
        "KbdInteractiveAuthentication": "kbdint_authentication",
    }
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            k, v = parts[0], parts[1].split("#", 1)[0].strip()
            if k in keys:
                out[keys[k]] = v
    return out


# ── sysctl kernel hardening ──────────────────────────────────────────────────

_SYSCTL_KEYS = [
    "kernel.kptr_restrict",          # 1 or 2: hide kernel pointers
    "kernel.dmesg_restrict",         # 1: only root reads dmesg
    "kernel.randomize_va_space",     # 2: full ASLR
    "kernel.unprivileged_bpf_disabled",   # 1: lock down BPF
    "net.ipv4.ip_forward",           # 0 if not a router
    "net.ipv4.conf.all.rp_filter",   # 1: reverse-path filter
    "kernel.yama.ptrace_scope",      # 1+: restrict ptrace
]


def _sysctl() -> dict[str, Any]:
    """Read each hardening flag. If sysctl errors (key absent), skip — don't
    store the error text as the value."""
    values: dict[str, str] = {}
    sctl = shutil.which("sysctl")
    for key in _SYSCTL_KEYS:
        # Direct /proc read is more reliable than parsing sysctl(8) output —
        # avoids "cannot stat" warnings leaking into our value strings.
        p = Path("/proc/sys") / key.replace(".", "/")
        try:
            values[key] = p.read_text().strip()
            continue
        except OSError:
            pass
        # Fallback: sysctl -n, but only accept successful, non-empty results.
        if sctl:
            try:
                r = subprocess.run([sctl, "-n", key],
                                   capture_output=True, text=True, timeout=2)
                if r.returncode == 0 and r.stdout.strip():
                    values[key] = r.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
    return {"values": values}


# ── Pending package updates ──────────────────────────────────────────────────

def _updates() -> dict[str, Any]:
    out: dict[str, Any] = {"manager": "none", "pending": 0, "security": 0, "raw": ""}

    apt = shutil.which("apt")
    if apt:
        out["manager"] = "apt"
        # `apt list --upgradable` is the cheap path. `-q` suppresses progress.
        s = _run([apt, "list", "--upgradable", "-q"], timeout=10)
        out["raw"] = s[:400]
        out["pending"] = max(0, sum(1 for l in s.splitlines()
                                    if "/" in l and "[upgradable" in l))
        # Security updates are tagged with `-security` source. Hint only.
        out["security"] = sum(1 for l in s.splitlines() if "-security" in l)
        return out

    dnf = shutil.which("dnf") or shutil.which("yum")
    if dnf:
        out["manager"] = Path(dnf).name
        # `check-update` exits 100 if updates are pending, 0 if none.
        try:
            r = subprocess.run([dnf, "-q", "check-update"],
                               capture_output=True, text=True, timeout=15)
        except Exception:
            return out
        out["raw"] = (r.stdout + r.stderr)[:400]
        out["pending"] = sum(1 for l in r.stdout.splitlines()
                             if l.strip() and not l.startswith(" ")
                             and not l.startswith("Last"))
        return out

    pac = shutil.which("pacman")
    if pac:
        out["manager"] = "pacman"
        s = _run([pac, "-Qu"], timeout=10)
        out["raw"] = s[:400]
        out["pending"] = sum(1 for l in s.splitlines() if l.strip())
        return out

    return out


# ── sudoers permissions ──────────────────────────────────────────────────────

def _sudoers() -> dict[str, Any]:
    out: dict[str, Any] = {"sudoers_perms": "", "world_writable": [],
                           "non_root_owned": []}
    paths: list[Path] = [Path("/etc/sudoers")]
    drop = Path("/etc/sudoers.d")
    if drop.exists() and drop.is_dir():
        try:
            paths.extend(sorted(drop.iterdir()))
        except OSError:
            pass

    for p in paths:
        try:
            st = p.stat()
        except (OSError, PermissionError):
            continue
        mode = st.st_mode & 0o777
        if p == Path("/etc/sudoers"):
            out["sudoers_perms"] = f"{mode:04o}"
        if mode & 0o002:
            out["world_writable"].append(str(p))
        if st.st_uid != 0:
            out["non_root_owned"].append({"path": str(p), "uid": st.st_uid})
    return out


# ── Disk encryption ──────────────────────────────────────────────────────────

def _disk_encryption() -> dict[str, Any]:
    out: dict[str, Any] = {"luks_devices": [], "any_encrypted": False}
    lsblk = shutil.which("lsblk")
    if not lsblk:
        return out
    s = _run([lsblk, "-no", "NAME,FSTYPE,MOUNTPOINT", "-r"])
    for line in s.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, fstype = parts[0], parts[1]
        if fstype == "crypto_LUKS":
            out["luks_devices"].append(name)
            out["any_encrypted"] = True
    return out


# ── Findings rollup ──────────────────────────────────────────────────────────

def _classify(mac: dict[str, Any], fw: dict[str, Any],
              sshd: dict[str, Any], sctl: dict[str, Any],
              upd: dict[str, Any], sudo: dict[str, Any],
              disk: dict[str, Any]) -> list[dict[str, Any]]:
    f: list[dict[str, Any]] = []

    # ── MAC ───────────────────────────────────────────────────────────────
    if mac["selinux"] == "absent" and mac["apparmor"] == "absent":
        f.append({"severity": "warn", "label": "No MAC framework",
                  "detail": "Neither SELinux nor AppArmor is loaded — kernel "
                            "has no mandatory access control layer."})
    elif mac["selinux"] == "permissive":
        f.append({"severity": "warn", "label": "SELinux permissive",
                  "detail": "Policy violations are logged but not blocked."})
    elif not (mac["selinux"] == "enforcing"
              or (mac["apparmor"] == "loaded" and mac["enforcing_profiles"] > 0)):
        f.append({"severity": "warn", "label": "MAC framework not enforcing",
                  "detail": f"selinux={mac['selinux']} apparmor={mac['apparmor']} "
                            f"({mac['enforcing_profiles']} enforcing profiles)"})

    # ── Firewall ──────────────────────────────────────────────────────────
    if fw["backend"] == "none":
        f.append({"severity": "warn", "label": "No firewall manager",
                  "detail": "Neither ufw nor firewalld is installed. Inbound "
                            "exposure is whatever the kernel default policy is."})
    elif not fw["active"]:
        f.append({"severity": "high", "label": f"Firewall inactive ({fw['backend']})",
                  "detail": "Inbound traffic is not filtered."})

    # ── SSH ───────────────────────────────────────────────────────────────
    if sshd["present"]:
        prl = sshd["permit_root_login"].lower()
        if prl in ("yes", "without-password"):
            f.append({"severity": "high", "label": f"sshd PermitRootLogin={prl}",
                      "detail": "Direct SSH root login is enabled."})
        pa = sshd["password_authentication"].lower()
        if pa == "yes":
            f.append({"severity": "warn", "label": "sshd PasswordAuthentication=yes",
                      "detail": "Password login allowed — key-only auth is preferred."})
        x11 = sshd["x11_forwarding"].lower()
        if x11 == "yes":
            f.append({"severity": "info", "label": "sshd X11Forwarding=yes",
                      "detail": "Disable if not needed — small attack surface."})

    # ── sysctl ────────────────────────────────────────────────────────────
    v = sctl["values"]
    if v.get("kernel.kptr_restrict", "0") == "0":
        f.append({"severity": "warn", "label": "kernel.kptr_restrict=0",
                  "detail": "Kernel pointers exposed via /proc — set to 1 or 2."})
    if v.get("kernel.dmesg_restrict", "0") == "0":
        f.append({"severity": "info", "label": "kernel.dmesg_restrict=0",
                  "detail": "Unprivileged users can read kernel log."})
    if v.get("kernel.randomize_va_space", "0") not in ("2",):
        f.append({"severity": "warn", "label": "ASLR not full",
                  "detail": f"kernel.randomize_va_space="
                            f"{v.get('kernel.randomize_va_space','?')} (want 2)"})
    if v.get("net.ipv4.ip_forward", "0") == "1":
        f.append({"severity": "info", "label": "IP forwarding on",
                  "detail": "Acts as a router. Expected on gateways, suspicious otherwise."})

    # ── Updates ───────────────────────────────────────────────────────────
    if upd["pending"] > 50:
        f.append({"severity": "high",
                  "label": f"{upd['pending']} package updates pending",
                  "detail": f"Run `{upd['manager']} upgrade` to apply."})
    elif upd["pending"] > 10:
        f.append({"severity": "warn",
                  "label": f"{upd['pending']} package updates pending"})
    if upd.get("security", 0) > 0:
        f.append({"severity": "high",
                  "label": f"{upd['security']} security updates pending"})

    # ── Sudoers ───────────────────────────────────────────────────────────
    if sudo["sudoers_perms"] and sudo["sudoers_perms"] not in ("0440", "0400"):
        f.append({"severity": "warn",
                  "label": f"/etc/sudoers perms {sudo['sudoers_perms']} (want 0440)"})
    for w in sudo["world_writable"]:
        f.append({"severity": "high", "label": f"world-writable {w}",
                  "detail": "Any user can grant themselves sudo."})
    for n in sudo["non_root_owned"]:
        f.append({"severity": "high",
                  "label": f"{n['path']} owned by uid {n['uid']}",
                  "detail": "Sudoers files must be owned by root (uid 0)."})

    # ── Disk ──────────────────────────────────────────────────────────────
    if not disk["any_encrypted"]:
        f.append({"severity": "info", "label": "No LUKS volumes detected",
                  "detail": "Disks are not encrypted at rest (or use another scheme)."})

    return f


# ── public endpoint ──────────────────────────────────────────────────────────

@router.get("/linux/posture")
def linux_posture(request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    require_linux("linux/posture is Linux-only; see /macos/posture (Mac) "
                  "or /windows/posture (Windows).")

    t0 = time.monotonic()
    mac     = _mac()
    fw      = _firewall()
    sshd    = _sshd_config()
    sctl    = _sysctl()
    upd     = _updates()
    sudo    = _sudoers()
    disk    = _disk_encryption()
    findings = _classify(mac, fw, sshd, sctl, upd, sudo, disk)

    return {
        "mac":        mac,
        "firewall":   fw,
        "sshd":       sshd,
        "sysctl":     sctl,
        "updates":    upd,
        "sudoers":    sudo,
        "disk":       disk,
        "findings":   findings,
        "elapsed_seconds": round(time.monotonic() - t0, 2),
    }
