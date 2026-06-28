"""Windows security posture snapshot.

REST  GET /windows/posture

Mirrors macos_posture / linux_posture: nested per-section dicts plus a flat
`findings` list. Sections probed:

  - **BitLocker**   — drive encryption state on the system drive
  - **Defender**    — Microsoft Defender real-time + cloud + tamper protection
  - **UAC**         — User Account Control gating (EnableLUA + consent prompt)
  - **Firewall**    — Windows Defender Firewall per profile (Domain/Private/Public)
  - **SmartScreen** — Explorer + Edge SmartScreen state
  - **SecureBoot**  — UEFI Secure Boot enabled
  - **Updates**     — last-installed hotfix date

All probes run as the backend's user — no UAC elevation. BitLocker and
manage-bde report the encryption state visible to the user; full
Authenticode/signtool checks are NOT performed here (too slow per request).
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request

from lib import scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode
from lib.platform_util import IS_WINDOWS, require_windows

router = APIRouter(tags=["windows"], dependencies=[Depends(require_local_auth)])


def _run(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return -1, f"(error: {exc})"


def _ps(script: str, timeout: int = 8) -> tuple[int, str]:
    """Run a PowerShell snippet. -NoProfile keeps cold start under 500 ms."""
    return _run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
    )


# ── BitLocker ────────────────────────────────────────────────────────────────

def _bitlocker() -> dict[str, Any]:
    # Get-BitLockerVolume is the modern API; manage-bde is the fallback.
    rc, out = _ps(
        "Get-BitLockerVolume -MountPoint $env:SystemDrive | "
        "Select-Object MountPoint,VolumeStatus,EncryptionMethod,"
        "ProtectionStatus,EncryptionPercentage | ConvertTo-Json -Compress",
        timeout=10,
    )
    info: dict[str, Any] = {"status": "unknown", "raw": out}
    if rc == 0 and out and out.startswith("{"):
        try:
            data = json.loads(out)
        except Exception:
            data = {}
        info["mount"]        = data.get("MountPoint", "")
        info["volume"]       = data.get("VolumeStatus", "")
        info["method"]       = data.get("EncryptionMethod", "")
        info["protection"]   = data.get("ProtectionStatus", "")
        info["percentage"]   = data.get("EncryptionPercentage", 0)
        prot = str(info["protection"]).lower()
        vol  = str(info["volume"]).lower()
        if prot in ("on", "1") and vol in ("fullyencrypted", "1"):
            info["status"] = "enabled"
        elif prot in ("off", "0"):
            info["status"] = "disabled"
        else:
            info["status"] = "partial"
        return info

    # Fallback: manage-bde -status C:
    rc, out = _run(["manage-bde", "-status", r"C:"])
    info["raw"] = out
    if rc == 0 and out:
        # Look for "Protection Status: Protection On" / "Protection Off"
        m = re.search(r"Protection Status:\s*Protection\s+(\w+)", out, re.I)
        if m:
            info["status"] = "enabled" if m.group(1).lower() == "on" else "disabled"
    return info


# ── Defender ─────────────────────────────────────────────────────────────────

def _defender() -> dict[str, Any]:
    rc, out = _ps(
        "Get-MpComputerStatus | "
        "Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntispywareEnabled,IsTamperProtected,AMServiceEnabled,"
        "OnAccessProtectionEnabled,BehaviorMonitorEnabled,"
        "IoavProtectionEnabled,NISEnabled,AntivirusSignatureLastUpdated,"
        "AntivirusSignatureVersion | ConvertTo-Json -Compress",
        timeout=12,
    )
    info: dict[str, Any] = {"status": "unknown", "raw": out}
    if rc == 0 and out and out.startswith("{"):
        try:
            data = json.loads(out)
        except Exception:
            data = {}
        info.update({
            "antivirus":         bool(data.get("AntivirusEnabled")),
            "realtime":          bool(data.get("RealTimeProtectionEnabled")),
            "antispyware":       bool(data.get("AntispywareEnabled")),
            "tamper_protected":  bool(data.get("IsTamperProtected")),
            "service":           bool(data.get("AMServiceEnabled")),
            "behaviour_monitor": bool(data.get("BehaviorMonitorEnabled")),
            "ioav_protection":   bool(data.get("IoavProtectionEnabled")),
            "network_inspection": bool(data.get("NISEnabled")),
            "sig_version":       data.get("AntivirusSignatureVersion", ""),
            "sig_updated":       data.get("AntivirusSignatureLastUpdated", ""),
        })
        if info["antivirus"] and info["realtime"]:
            info["status"] = "enabled"
        elif info["antivirus"]:
            info["status"] = "partial"
        else:
            info["status"] = "disabled"
    return info


# ── UAC ──────────────────────────────────────────────────────────────────────

def _uac() -> dict[str, Any]:
    info: dict[str, Any] = {"status": "unknown", "raw": ""}
    try:
        import winreg                                  # type: ignore[import-not-found]
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            0, winreg.KEY_READ,
        )
    except OSError as exc:
        info["raw"] = f"registry open failed: {exc}"
        return info
    try:
        def _val(name: str) -> int:
            try:
                v, _ = winreg.QueryValueEx(key, name)
                return int(v)
            except OSError:
                return -1
        info["enable_lua"]             = _val("EnableLUA")
        info["consent_prompt_admin"]   = _val("ConsentPromptBehaviorAdmin")
        info["consent_prompt_user"]    = _val("ConsentPromptBehaviorUser")
        info["prompt_on_secure_desktop"] = _val("PromptOnSecureDesktop")
        info["raw"] = (f"EnableLUA={info['enable_lua']} "
                       f"ConsentPromptBehaviorAdmin={info['consent_prompt_admin']} "
                       f"PromptOnSecureDesktop={info['prompt_on_secure_desktop']}")
        if info["enable_lua"] == 1:
            info["status"] = "enabled"
        elif info["enable_lua"] == 0:
            info["status"] = "disabled"
    finally:
        try: winreg.CloseKey(key)
        except Exception: pass
    return info


# ── Firewall ─────────────────────────────────────────────────────────────────

def _firewall() -> dict[str, Any]:
    rc, out = _ps(
        "Get-NetFirewallProfile | "
        "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,"
        "LogAllowed,LogBlocked | ConvertTo-Json -Compress",
        timeout=10,
    )
    info: dict[str, Any] = {"profiles": [], "raw": out, "all_enabled": False}
    if rc == 0 and out and out.startswith(("[", "{")):
        try:
            data = json.loads(out)
        except Exception:
            data = []
        if isinstance(data, dict):
            data = [data]
        profiles = []
        for p in data:
            enabled = p.get("Enabled")
            # PowerShell's ConvertTo-Json renders [bool] sometimes as bool,
            # sometimes as the integer "1"/"2" (True/False mapping varies by
            # cmdlet). Normalise.
            if isinstance(enabled, bool):
                en = enabled
            elif isinstance(enabled, int):
                en = enabled in (1, True)
            else:
                en = str(enabled).lower() in ("true", "1")
            profiles.append({
                "name":   p.get("Name", ""),
                "enabled": en,
                "inbound":  str(p.get("DefaultInboundAction", "")),
                "outbound": str(p.get("DefaultOutboundAction", "")),
            })
        info["profiles"] = profiles
        info["all_enabled"] = bool(profiles) and all(p["enabled"] for p in profiles)
    return info


# ── SmartScreen ──────────────────────────────────────────────────────────────

def _smartscreen() -> dict[str, Any]:
    info: dict[str, Any] = {"status": "unknown", "raw": ""}
    try:
        import winreg                                  # type: ignore[import-not-found]
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer",
            0, winreg.KEY_READ,
        )
    except OSError as exc:
        info["raw"] = f"registry open failed: {exc}"
        return info
    try:
        try:
            v, _ = winreg.QueryValueEx(key, "SmartScreenEnabled")
            info["explorer"] = str(v)
            info["raw"]      = f"Explorer SmartScreenEnabled={v}"
            low = str(v).lower()
            if low in ("requireadmin", "on"):
                info["status"] = "enabled"
            elif low == "warn":
                info["status"] = "partial"
            elif low == "off":
                info["status"] = "disabled"
        except OSError:
            info["explorer"] = ""
    finally:
        try: winreg.CloseKey(key)
        except Exception: pass
    return info


# ── Secure Boot ──────────────────────────────────────────────────────────────

def _secure_boot() -> dict[str, Any]:
    rc, out = _ps("Confirm-SecureBootUEFI", timeout=8)
    info: dict[str, Any] = {"status": "unknown", "raw": out}
    if rc == 0 and out:
        low = out.strip().lower()
        if low == "true":
            info["status"] = "enabled"
        elif low == "false":
            info["status"] = "disabled"
        # Common non-UEFI error message keeps status="unknown"
        elif "cmdlet not supported" in low or "legacy bios" in low:
            info["status"] = "legacy-bios"
    return info


# ── Updates ──────────────────────────────────────────────────────────────────

def _updates() -> dict[str, Any]:
    # Get-HotFix returns the most recent patches; the most recent InstalledOn
    # is what we care about for the "patched recently?" finding.
    rc, out = _ps(
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 5 HotFixID,Description,InstalledOn | "
        "ConvertTo-Json -Compress",
        timeout=12,
    )
    info: dict[str, Any] = {"recent": [], "days_since_last": -1, "raw": out}
    if rc != 0 or not out:
        return info
    try:
        data = json.loads(out) if out.startswith(("[", "{")) else []
    except Exception:
        data = []
    if isinstance(data, dict):
        data = [data]
    recent = []
    for hf in data:
        installed = str(hf.get("InstalledOn", ""))
        recent.append({
            "id":          str(hf.get("HotFixID", "")),
            "description": str(hf.get("Description", "")),
            "installed":   installed,
        })
    info["recent"] = recent
    # Estimate days-since-last from the first entry's date — PowerShell
    # serialises DateTime as "/Date(ms)/" or ISO depending on locale.
    if recent:
        s = recent[0]["installed"]
        # ISO
        try:
            ts = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            # "/Date(1700000000000)/"
            m = re.search(r"/Date\((\d+)\)/", s)
            ts = (datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
                  if m else None)
        if ts is not None:
            delta = datetime.now(timezone.utc) - (ts if ts.tzinfo else
                                                  ts.replace(tzinfo=timezone.utc))
            info["days_since_last"] = max(0, delta.days)
    return info


# ── Findings rollup ──────────────────────────────────────────────────────────

def _classify(bl: dict, dfd: dict, uac: dict, fw: dict, ss: dict,
              sb: dict, upd: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if bl.get("status") == "disabled":
        findings.append({"severity": "high", "label": "BitLocker disabled",
                         "detail": "System drive is not encrypted. Enable BitLocker in Settings."})
    elif bl.get("status") == "partial":
        findings.append({"severity": "warn", "label": "BitLocker encrypting",
                         "detail": f"Encryption in progress: {bl.get('percentage', 0)}%"})
    elif bl.get("status") == "unknown":
        findings.append({"severity": "warn", "label": "BitLocker status unknown",
                         "detail": "Could not query Get-BitLockerVolume / manage-bde"})

    if dfd.get("status") == "disabled":
        findings.append({"severity": "high", "label": "Defender disabled",
                         "detail": "Microsoft Defender real-time protection is off"})
    elif not dfd.get("realtime", True):
        findings.append({"severity": "high", "label": "Real-time protection off",
                         "detail": "Defender is enabled but real-time scanning is off"})
    if dfd.get("status") in ("enabled", "partial") and not dfd.get("tamper_protected", True):
        findings.append({"severity": "warn", "label": "Tamper Protection off",
                         "detail": "Defender Tamper Protection is disabled — settings can be modified by other tools"})

    if uac.get("enable_lua") == 0:
        findings.append({"severity": "high", "label": "UAC disabled",
                         "detail": "EnableLUA=0 — admin processes run elevated without consent prompts"})
    elif uac.get("prompt_on_secure_desktop") == 0:
        findings.append({"severity": "warn", "label": "UAC secure-desktop off",
                         "detail": "Consent prompts appear on the normal desktop, weakening UAC"})

    if not fw.get("all_enabled", False):
        disabled = [p["name"] for p in fw.get("profiles", []) if not p["enabled"]]
        if disabled:
            findings.append({"severity": "high",
                             "label": f"Firewall off for {', '.join(disabled)} profile(s)",
                             "detail": "Windows Defender Firewall is disabled on at least one profile"})

    if ss.get("status") == "disabled":
        findings.append({"severity": "warn", "label": "SmartScreen off",
                         "detail": "Explorer SmartScreen will not warn on untrusted downloads"})

    if sb.get("status") == "disabled":
        findings.append({"severity": "warn", "label": "Secure Boot disabled",
                         "detail": "UEFI Secure Boot is off — boot-time integrity check skipped"})

    days = upd.get("days_since_last", -1)
    if isinstance(days, int) and days > 60:
        findings.append({"severity": "warn",
                         "label": f"No Windows updates in {days} days",
                         "detail": "Last hotfix installed more than 60 days ago"})

    findings.sort(key=lambda f: {"high": 0, "warn": 1, "info": 2}.get(f["severity"], 3))
    return findings


@router.get("/windows/posture")
def windows_posture(request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    require_windows("windows/posture is Windows-only; see /macos/posture (Mac) "
                    "or /linux/posture (Linux).")

    t0 = time.monotonic()
    bitlocker = _bitlocker()
    defender  = _defender()
    uac       = _uac()
    firewall  = _firewall()
    smartscr  = _smartscreen()
    secboot   = _secure_boot()
    updates   = _updates()
    findings  = _classify(bitlocker, defender, uac, firewall, smartscr,
                          secboot, updates)

    return {
        "bitlocker":   bitlocker,
        "defender":    defender,
        "uac":         uac,
        "firewall":    firewall,
        "smartscreen": smartscr,
        "secureboot":  secboot,
        "updates":     updates,
        "findings":    findings,
        "elapsed_ms":  int((time.monotonic() - t0) * 1000),
    }
