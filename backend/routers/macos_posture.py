"""macOS security posture snapshot.

REST  GET /macos/posture

Pulls SIP / Gatekeeper / FileVault / Application Firewall / XProtect state
via the standard system CLIs (no privileged access needed for any of these
on user-owned macOS).

Response:
  {
    "sip":         { "status": "enabled"|"disabled"|"unknown", "raw": "..." },
    "gatekeeper":  { "status": "...", "raw": "..." },
    "filevault":   { "status": "...", "raw": "..." },
    "firewall":    { "global_state": int, "block_all": bool, "stealth": bool,
                     "logging": bool, "raw": "..." },
    "xprotect":    { "version": "...", "path": "..." },
    "findings":    [ {severity, label, detail}, ... ],
  }
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from lib import hids_notify, scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode
from lib.platform_util import require_darwin

router = APIRouter(tags=["macos"], dependencies=[Depends(require_local_auth)])


def _run(cmd: list[str], timeout: int = 4) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return f"(error: {exc})"


def _sip() -> dict[str, Any]:
    out = _run(["/usr/bin/csrutil", "status"])
    status = "unknown"
    if "enabled" in out.lower() and "disabled" not in out.lower():
        status = "enabled"
    elif "disabled" in out.lower():
        status = "disabled"
    return {"status": status, "raw": out}


def _gatekeeper() -> dict[str, Any]:
    out = _run(["/usr/sbin/spctl", "--status"])
    status = "unknown"
    if "assessments enabled" in out.lower():
        status = "enabled"
    elif "assessments disabled" in out.lower():
        status = "disabled"
    return {"status": status, "raw": out}


def _filevault() -> dict[str, Any]:
    out = _run(["/usr/bin/fdesetup", "status"])
    status = "unknown"
    if "filevault is on" in out.lower():
        status = "on"
    elif "filevault is off" in out.lower():
        status = "off"
    elif "deferred" in out.lower():
        status = "pending"
    return {"status": status, "raw": out}


def _firewall() -> dict[str, Any]:
    SF = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    global_state_raw  = _run([SF, "--getglobalstate"])
    block_all_raw     = _run([SF, "--getblockall"])
    stealth_raw       = _run([SF, "--getstealthmode"])
    logging_raw       = _run([SF, "--getloggingmode"])

    def _num(text: str) -> int:
        m = re.search(r"state is (\d+)|enabled|disabled", text.lower())
        if not m:
            return -1
        if m.group(1):
            return int(m.group(1))
        return 1 if m.group(0) == "enabled" else 0

    return {
        "global_state": _num(global_state_raw),
        "block_all":    "enabled" in block_all_raw.lower(),
        "stealth":      "enabled" in stealth_raw.lower(),
        "logging":      "enabled" in logging_raw.lower(),
        "raw":          "\n".join([global_state_raw, block_all_raw, stealth_raw, logging_raw]),
    }


def _xprotect() -> dict[str, Any]:
    paths = [
        "/var/db/SystemPolicyConfiguration/ExecPolicy",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    ]
    for plist in paths:
        p = Path(plist)
        if not p.exists():
            continue
        if plist.endswith(".plist"):
            ver = _run(["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", plist])
            return {"version": ver, "path": plist}
    return {"version": "unknown", "path": ""}


@router.get("/macos/posture")
async def macos_posture(request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    require_darwin("macos/posture is macOS-only; see /linux/posture (Linux) "
                   "or /windows/posture (Windows).")

    t0 = time.monotonic()

    sip = _sip()
    gk  = _gatekeeper()
    fv  = _filevault()
    fw  = _firewall()
    xp  = _xprotect()

    # ── Findings ────────────────────────────────────────────────────────────
    findings: list[dict[str, Any]] = []
    high = 0

    if sip["status"] == "disabled":
        findings.append({"severity": "high", "label": "SIP disabled",
                         "detail": "System Integrity Protection is off. Re-enable from Recovery."})
        high += 1
    elif sip["status"] == "unknown":
        findings.append({"severity": "warn", "label": "SIP status unknown",
                         "detail": "csrutil did not return a clear answer"})

    if gk["status"] == "disabled":
        findings.append({"severity": "high", "label": "Gatekeeper disabled",
                         "detail": "Unsigned apps run without prompt"})
        high += 1

    if fv["status"] == "off":
        findings.append({"severity": "high", "label": "FileVault off",
                         "detail": "Disk is not encrypted at rest"})
        high += 1
    elif fv["status"] == "pending":
        findings.append({"severity": "warn", "label": "FileVault deferred",
                         "detail": "Encryption pending — will start on next sign-in"})

    if fw["global_state"] == 0:
        findings.append({"severity": "warn", "label": "Application Firewall off",
                         "detail": "All inbound connections allowed"})
    elif fw["global_state"] in (1, 2):
        if not fw["stealth"]:
            findings.append({"severity": "info", "label": "Stealth mode off",
                             "detail": "Mac responds to ICMP/probes — consider enabling"})
        if not fw["logging"]:
            findings.append({"severity": "info", "label": "Firewall logging off"})

    elapsed = round(time.monotonic() - t0, 2)
    sev = "warning" if high > 0 else "info"
    await hids_notify.notify(
        sev, "macos-posture",
        f"macOS posture: SIP={sip['status']} GK={gk['status']} FV={fv['status']} ({high} high)",
        {"sip": sip["status"], "gatekeeper": gk["status"],
         "filevault": fv["status"], "firewall_state": fw["global_state"],
         "high_findings": high},
    )

    return {
        "sip": sip, "gatekeeper": gk, "filevault": fv,
        "firewall": fw, "xprotect": xp,
        "findings": findings,
        "elapsed_seconds": elapsed,
    }
