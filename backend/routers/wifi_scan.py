"""WiFi Scanner — passive scan via CoreWLAN (macOS) or nmcli/iw (Linux).

macOS 15+ note
==============
Apple gates SSID/BSSID reads behind **Location Services**. Without permission,
`CWNetwork.ssid()` and `.bssid()` return None even though the scan succeeds —
you still see RSSI / channel / security type, just not which network it is.

Grant the running app Location access in:
  System Settings → Privacy & Security → Location Services → enable for
  Terminal / s-ide / whatever spawned the backend.

`/wifi/scan` returns a `permission_hint` field set to "location-required" when
we detect all SSIDs as null — the UI uses that to show the fix-it instructions.

Linux note
==========
We prefer `nmcli` (no root required) and fall back to `iw dev <iface> scan` if
nmcli isn't installed. nmcli reports signal as 0..100 %; we map it to a rough
dBm via `dBm ≈ signal − 100` so the rest of the pipeline (which expects
RSSI in dBm) stays consistent. The conversion is approximate but monotonic,
which is what the evil-twin RSSI-gap heuristic actually depends on.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.platform_util import IS_DARWIN, IS_LINUX, IS_WINDOWS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/wifi-scan", tags=["wifi-scan"], dependencies=[Depends(require_local_auth)])

# CoreWLAN security type enum (CWSecurity) — Mac scans surface these as ints.
SECURITY_NAMES = {
    0: "None", 1: "WEP", 2: "WPA Personal", 3: "WPA Personal Mixed",
    4: "WPA2 Personal", 5: "Personal", 6: "Dynamic WEP", 7: "WPA Enterprise",
    8: "WPA Enterprise Mixed", 9: "WPA2 Enterprise", 10: "Enterprise",
    11: "WPA3 Personal", 12: "WPA3 Enterprise", 13: "WPA3 Transition",
    14: "OWE", 15: "OWE Transition",
}


# ── macOS scanner ────────────────────────────────────────────────────────────

def _import_corewlan():
    try:
        from CoreWLAN import CWWiFiClient
        return CWWiFiClient
    except ImportError as e:
        raise HTTPException(503,
            f"CoreWLAN not available ({e}). This tool is macOS-only. "
            "pip install pyobjc-framework-CoreWLAN")


def _network_to_dict(n) -> dict[str, Any]:
    chan = n.wlanChannel()
    sec_type = -1
    try:
        sec_type = int(n.securityType())
    except Exception:
        pass
    bssid = n.bssid() or ""
    ssid = n.ssid() or ""
    oui = bssid[:8].lower() if bssid else ""
    return {
        "ssid":     str(ssid) if ssid else None,
        "bssid":    str(bssid) if bssid else None,
        "rssi":     int(n.rssiValue() or 0),
        "noise":    int(n.noiseMeasurement() or 0),
        "channel":  int(chan.channelNumber()) if chan else 0,
        "band":     int(chan.channelBand()) if chan else 0,   # 1=2.4GHz, 2=5GHz
        "width":    int(chan.channelWidth()) if chan else 0,
        "security": SECURITY_NAMES.get(sec_type, f"unknown({sec_type})"),
        "security_id": sec_type,
        "country":  str(n.countryCode() or "") or None,
        "beacon_interval": int(n.beaconInterval() or 0),
        "oui":      oui,
        "is_hidden": not bool(ssid),
    }


def _scan_mac() -> dict[str, Any]:
    CWWiFiClient = _import_corewlan()
    client = CWWiFiClient.sharedWiFiClient()
    iface = client.interface()
    if iface is None:
        raise HTTPException(503, "no active WiFi interface")

    nets, err = iface.scanForNetworksWithName_error_(None, None)
    if err is not None:
        logger.warning("CoreWLAN scan failed: %r", err)
        raise MhpError(
            "CoreWLAN scan failed — see server log",
            code=ErrorCode.TOOL_FAILED, status_code=500,
        )
    if not nets:
        return {
            "interface": str(iface.interfaceName() or ""),
            "current_ssid": None,
            "current_bssid": None,
            "networks": [],
            "permission_hint": None,
        }

    rows = [_network_to_dict(n) for n in nets]
    all_null = all(r["ssid"] is None for r in rows)
    return {
        "interface": str(iface.interfaceName() or ""),
        "current_ssid": str(iface.ssid() or "") or None,
        "current_bssid": str(iface.bssid() or "") or None,
        "networks": sorted(rows, key=lambda r: -r["rssi"]),
        "permission_hint": "location-required" if all_null else None,
    }


# ── Linux scanner ────────────────────────────────────────────────────────────

def _wifi_iface_linux() -> str:
    iw = shutil.which("iw")
    if iw:
        out = subprocess.run([iw, "dev"], capture_output=True, text=True, timeout=4).stdout
        iface = ""
        for line in out.splitlines():
            ls = line.strip()
            if ls.startswith("Interface "):
                iface = ls.split()[1]
            elif ls.startswith("type ") and "managed" in ls and iface:
                return iface
        if iface:
            return iface
    nmcli = shutil.which("nmcli")
    if nmcli:
        out = subprocess.run([nmcli, "-t", "-f", "DEVICE,TYPE",
                              "device", "status"],
                             capture_output=True, text=True, timeout=4).stdout
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "wifi":
                return parts[0]
    return ""


def _freq_to_chan(freq_mhz: int) -> int:
    """Convert centre frequency to channel number. Covers 2.4 GHz + 5 GHz +
    rudimentary 6 GHz (Wi-Fi 6E). Check 6 GHz first — it starts at 5955 MHz,
    which would otherwise be misclassified as 5 GHz channel 191."""
    if 2412 <= freq_mhz <= 2484:
        if freq_mhz == 2484:
            return 14
        return (freq_mhz - 2407) // 5
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5
    if 5000 <= freq_mhz < 5955:
        return (freq_mhz - 5000) // 5
    return 0


def _nmcli_split(line: str) -> list[str]:
    # `nmcli -t` separates fields by ":" and escapes literal colons as "\:".
    parts = re.split(r"(?<!\\):", line)
    return [p.replace("\\:", ":") for p in parts]


def _scan_linux() -> dict[str, Any]:
    iface = _wifi_iface_linux()

    nmcli = shutil.which("nmcli")
    rows: list[dict[str, Any]] = []
    current_ssid: str | None = None
    current_bssid: str | None = None

    if nmcli:
        try:
            r = subprocess.run(
                [nmcli, "-t", "-f", "IN-USE,SSID,BSSID,SIGNAL,FREQ,SECURITY",
                 "device", "wifi", "list", "--rescan", "yes"],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            raise MhpError("nmcli scan timed out",
                           code=ErrorCode.TIMEOUT, status_code=504) from None
        except Exception:
            logger.exception("nmcli scan failed")
            raise MhpError("nmcli scan failed",
                           code=ErrorCode.TOOL_FAILED, status_code=500) from None
        if r.returncode != 0:
            logger.warning("nmcli scan rc=%s stderr=%s",
                           r.returncode, (r.stderr or "")[:200])
            raise MhpError(f"nmcli scan failed (rc={r.returncode})",
                           code=ErrorCode.TOOL_FAILED, status_code=500)

        for line in r.stdout.splitlines():
            parts = _nmcli_split(line)
            if len(parts) < 6:
                continue
            in_use, ssid, bssid, signal, freq, security = parts[:6]
            ssid = ssid or ""
            bssid = bssid.lower() if bssid else ""
            try:
                pct = int(signal)
            except ValueError:
                pct = 0
            # 0..100% → approximate dBm. Keep monotonic — exact mapping
            # depends on driver, but this is what the rest of the pipeline
            # (and evil-twin's >20 dB gap check) actually needs.
            rssi_dbm = pct - 100
            try:
                freq_int = int(freq.split()[0]) if freq else 0
            except ValueError:
                freq_int = 0
            chan = _freq_to_chan(freq_int) if freq_int else 0
            band = 1 if 2400 <= freq_int < 2500 else (2 if 5000 <= freq_int < 7200 else 0)
            sec = security.strip() or "None"
            if sec in ("--", ""):
                sec = "None"
            row = {
                "ssid": ssid if ssid else None,
                "bssid": bssid if bssid else None,
                "rssi": rssi_dbm,
                "noise": 0,
                "channel": chan,
                "band": band,
                "width": 0,
                "security": sec,
                "security_id": -1,
                "country": None,
                "beacon_interval": 0,
                "oui": bssid[:8] if bssid else "",
                "is_hidden": not bool(ssid),
            }
            rows.append(row)
            if in_use.strip() == "*":
                current_ssid = ssid or None
                current_bssid = bssid or None

    elif shutil.which("iw") and iface:
        rows, current_ssid, current_bssid = _scan_iw(iface)
    else:
        raise HTTPException(503,
            "no WiFi scanner available — install network-manager (nmcli) or "
            "iw (`apt install iw`) and ensure a wifi interface exists.")

    return {
        "interface": iface,
        "current_ssid": current_ssid,
        "current_bssid": current_bssid,
        "networks": sorted(rows, key=lambda r: -r["rssi"]),
        "permission_hint": None,
    }


def _scan_iw(iface: str) -> tuple[list[dict[str, Any]], str | None, str | None]:
    """Run `iw dev <iface> scan` (needs CAP_NET_ADMIN — typically root). Parse
    the verbose output. Used only when nmcli isn't installed."""
    iw = shutil.which("iw") or "iw"
    try:
        r = subprocess.run([iw, "dev", iface, "scan"],
                           capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        raise MhpError("iw scan timed out",
                       code=ErrorCode.TIMEOUT, status_code=504) from None
    if r.returncode != 0:
        logger.warning("iw scan rc=%s stderr=%s",
                       r.returncode, (r.stderr or "")[:200])
        raise MhpError(
            f"iw scan failed (rc={r.returncode}) — `iw scan` usually requires root.",
            code=ErrorCode.TOOL_FAILED, status_code=500,
        )

    rows: list[dict[str, Any]] = []
    cur: dict[str, Any] = {}

    def flush():
        if cur.get("bssid"):
            rows.append({
                "ssid": cur.get("ssid") if cur.get("ssid") else None,
                "bssid": cur["bssid"],
                "rssi": int(cur.get("rssi", -100)),
                "noise": 0,
                "channel": int(cur.get("channel", 0) or 0),
                "band": cur.get("band", 0),
                "width": 0,
                "security": cur.get("security", "None"),
                "security_id": -1,
                "country": None,
                "beacon_interval": 0,
                "oui": cur["bssid"][:8],
                "is_hidden": not bool(cur.get("ssid")),
            })

    for line in r.stdout.splitlines():
        if line.startswith("BSS "):
            flush()
            cur = {}
            m = re.search(r"([0-9a-f:]{17})", line)
            if m:
                cur["bssid"] = m.group(1).lower()
            continue
        ls = line.strip()
        if ls.startswith("SSID:"):
            cur["ssid"] = ls.split(":", 1)[1].strip()
        elif ls.startswith("signal:"):
            try:
                cur["rssi"] = int(float(ls.split(":", 1)[1].strip().split()[0]))
            except (ValueError, IndexError):
                pass
        elif ls.startswith("freq:"):
            try:
                freq = int(ls.split(":", 1)[1].strip())
                cur["channel"] = _freq_to_chan(freq)
                cur["band"] = 1 if 2400 <= freq < 2500 else (2 if 5000 <= freq < 7200 else 0)
            except ValueError:
                pass
        elif "RSN:" in ls:
            cur["security"] = "WPA2/WPA3"
        elif "WPA:" in ls:
            cur["security"] = cur.get("security", "WPA")
        elif "Privacy" in ls and "capability:" in ls.lower():
            cur.setdefault("security", "WEP")
    flush()
    return rows, None, None


# ── Windows scanner (netsh wlan) ─────────────────────────────────────────────

# netsh wlan output is localised — these patterns target English Windows.
# Non-English systems would need a different parser; calling
# `netsh wlan show networks mode=bssid` on a Spanish/German box returns
# "Tipo de red"/"Netzwerktyp" etc.
_WIN_SSID_RE   = re.compile(r"^SSID\s+\d+\s*:\s*(.*?)\s*$")
_WIN_BSSID_RE  = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})\s*$")
_WIN_AUTH_RE   = re.compile(r"^\s*Authentication\s*:\s*(.+?)\s*$")
_WIN_SIGNAL_RE = re.compile(r"^\s*Signal\s*:\s*(\d+)%\s*$")
_WIN_CHAN_RE   = re.compile(r"^\s*Channel\s*:\s*(\d+)\s*$")
_WIN_BAND_RE   = re.compile(r"^\s*Band\s*:\s*([\d.]+)\s*GHz\s*$")


def _win_security_normalise(auth: str) -> str:
    a = auth.strip().lower()
    if not a or a in ("open", "none"):
        return "None"
    if "wep" in a:
        return "WEP"
    if "wpa3" in a:
        return "WPA3"
    if "wpa2" in a:
        return "WPA2"
    if "wpa" in a:
        return "WPA"
    return auth.strip() or "None"


def _scan_windows() -> dict[str, Any]:
    """Windows WiFi scan via `netsh wlan show networks mode=bssid`.

    netsh is the only stable cross-Windows-version option without depending on
    PowerShell or third-party libraries (no winrt installed). The output is
    text-formatted with one block per SSID + nested BSSID entries. Returns
    the same dict shape as the Mac/Linux scanners so the FE renders unchanged.
    """
    netsh = shutil.which("netsh") or r"C:\Windows\System32\netsh.exe"
    try:
        r = subprocess.run(
            [netsh, "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        raise HTTPException(503, "netsh not found — Windows WiFi APIs unavailable")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "netsh wlan scan timed out")
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()
        # These aren't backend errors — they're "no WiFi available right now"
        # conditions (desktop with no WiFi card, WiFi disabled, headless CI VM).
        # Return 503 so the frontend can show a "WiFi unavailable" state
        # instead of a generic 500 error toast.
        no_wifi_markers = (
            "wlansvc",                            # Wireless AutoConfig service down
            "is not running",
            "no wireless interface",
            "There is no wireless interface",
            "powered down",
            "not currently allowed",
        )
        if any(m.lower() in err.lower() for m in no_wifi_markers):
            raise HTTPException(503, f"WiFi unavailable: {err}")
        raise HTTPException(
            500, f"netsh wlan scan failed (rc={r.returncode}): {err}")

    rows: list[dict[str, Any]] = []
    cur_ssid: str | None = None
    cur_auth: str = ""
    cur_bssid_entry: dict[str, Any] | None = None

    def _flush_bssid() -> None:
        if cur_bssid_entry and cur_bssid_entry.get("bssid"):
            bssid = cur_bssid_entry["bssid"].lower()
            rssi_pct = int(cur_bssid_entry.get("signal_pct", 0))
            rssi_dbm = rssi_pct - 100  # same monotonic mapping as nmcli
            rows.append({
                "ssid":     cur_ssid if cur_ssid else None,
                "bssid":    bssid,
                "rssi":     rssi_dbm,
                "noise":    0,
                "channel":  int(cur_bssid_entry.get("channel", 0)),
                "band":     int(cur_bssid_entry.get("band", 0)),
                "width":    0,
                "security": _win_security_normalise(cur_auth),
                "security_id": -1,
                "country":  None,
                "beacon_interval": 0,
                "oui":      bssid[:8],
                "is_hidden": not bool(cur_ssid),
            })

    for raw in r.stdout.splitlines():
        m = _WIN_SSID_RE.match(raw)
        if m:
            _flush_bssid()
            cur_bssid_entry = None
            cur_ssid = m.group(1).strip() or None
            cur_auth = ""
            continue
        m = _WIN_AUTH_RE.match(raw)
        if m:
            cur_auth = m.group(1)
            continue
        m = _WIN_BSSID_RE.match(raw)
        if m:
            _flush_bssid()
            cur_bssid_entry = {"bssid": m.group(1).lower()}
            continue
        if cur_bssid_entry is None:
            continue
        m = _WIN_SIGNAL_RE.match(raw)
        if m:
            cur_bssid_entry["signal_pct"] = int(m.group(1))
            continue
        m = _WIN_CHAN_RE.match(raw)
        if m:
            cur_bssid_entry["channel"] = int(m.group(1))
            continue
        m = _WIN_BAND_RE.match(raw)
        if m:
            try:
                ghz = float(m.group(1))
            except ValueError:
                ghz = 0.0
            if 2.0 <= ghz < 3.0:    cur_bssid_entry["band"] = 1   # 2.4 GHz
            elif 4.0 <= ghz < 6.0:  cur_bssid_entry["band"] = 2   # 5 GHz
            elif 5.9 <= ghz < 7.2:  cur_bssid_entry["band"] = 3   # 6 GHz (Wi-Fi 6E)
            continue
    _flush_bssid()

    # Pull the currently-associated SSID/BSSID from `netsh wlan show interfaces`.
    cur_ssid_now: str | None = None
    cur_bssid_now: str | None = None
    iface_name = ""
    try:
        r2 = subprocess.run(
            [netsh, "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=8,
        )
    except Exception:
        r2 = None
    if r2 is not None and r2.returncode == 0:
        for raw in r2.stdout.splitlines():
            ls = raw.strip()
            if ls.lower().startswith("name") and ":" in ls:
                # The first "Name :" block is the interface display name.
                if not iface_name:
                    iface_name = ls.split(":", 1)[1].strip()
            elif ls.lower().startswith("ssid") and ":" in ls and not ls.lower().startswith("bssid"):
                v = ls.split(":", 1)[1].strip()
                if v:
                    cur_ssid_now = v
            elif ls.lower().startswith("bssid") and ":" in ls:
                v = ls.split(":", 1)[1].strip().lower()
                if re.fullmatch(r"[0-9a-f:]{17}", v):
                    cur_bssid_now = v

    return {
        "interface":     iface_name,
        "current_ssid":  cur_ssid_now,
        "current_bssid": cur_bssid_now,
        "networks":      sorted(rows, key=lambda r: -r["rssi"]),
        "permission_hint": None,
    }


# ── public function: used by evil_twin too ───────────────────────────────────

def scan_networks() -> dict[str, Any]:
    """Platform-agnostic WiFi scan. Returns the same shape as /wifi-scan/scan."""
    if IS_DARWIN:
        return _scan_mac()
    if IS_LINUX:
        return _scan_linux()
    if IS_WINDOWS:
        return _scan_windows()
    raise HTTPException(501, "Unsupported platform for WiFi scan.")


@router.get("/scan")
def scan() -> dict[str, Any]:
    return scan_networks()
