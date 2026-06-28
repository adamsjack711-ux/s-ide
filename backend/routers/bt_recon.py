"""Bluetooth Recon — enumerate paired / connected / recent devices.

macOS: parses `system_profiler SPBluetoothDataType -json`. We don't do active
CoreBluetooth scanning (requires a delegate-driven event loop that fights with
FastAPI's request lifecycle); system_profiler's collected data covers the same
ground.

Linux: shells out to `bluetoothctl` (bluez). Same response shape, so the
frontend page renders identically. Active discovery is not initiated here —
we surface whatever bluez already knows about (paired, connected, and
recently-seen devices in the cache).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from typing import Any

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.platform_util import IS_DARWIN, require_unix

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bt", tags=["bt-recon"], dependencies=[Depends(require_local_auth)])

_BT_HINT = ("Bluetooth recon shells out to system_profiler (macOS) or "
            "bluetoothctl (Linux); Windows uses a different BT stack — "
            "native port pending.")


# ── macOS implementation ─────────────────────────────────────────────────────

def _run_sp() -> dict[str, Any]:
    try:
        r = subprocess.run(
            ["system_profiler", "SPBluetoothDataType", "-json"],
            capture_output=True, text=True, timeout=20,
        )
    except FileNotFoundError:
        raise HTTPException(503, "system_profiler not found (non-macOS?)")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "system_profiler timed out")
    if r.returncode != 0:
        logger.warning(
            "system_profiler exit=%s stderr=%r",
            r.returncode, (r.stderr or "")[:500],
        )
        raise MhpError(
            f"system_profiler failed (exit {r.returncode})",
            code=ErrorCode.TOOL_FAILED, status_code=500,
        )
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        logger.exception("system_profiler output was not valid JSON")
        raise MhpError(
            "system_profiler output was not parseable JSON",
            code=ErrorCode.TOOL_FAILED, status_code=500,
        )


def _normalize_device_mac(addr: str, info: dict[str, Any]) -> dict[str, Any]:
    return {
        "address":       addr,
        "name":          info.get("device_name", ""),
        "manufacturer":  info.get("device_manufacturer", ""),
        "minor_type":    info.get("device_minorType", ""),
        "vendor_id":     info.get("device_vendorID", ""),
        "product_id":    info.get("device_productID", ""),
        "firmware":      info.get("device_firmwareVersion", ""),
        "battery":       info.get("device_batteryPercent", ""),
        "rssi":          info.get("device_rssi", ""),
        "connected":     info.get("device_connected", "") == "attrib_Yes",
        "last_seen":     info.get("device_lastSeenTime", ""),
        "services":      info.get("device_services", "").split(", ")
                          if info.get("device_services") else [],
    }


def _status_mac() -> dict[str, Any]:
    data = _run_sp()
    payload = data.get("SPBluetoothDataType") or []
    controllers: list[dict[str, Any]] = []
    for item in payload:
        ctrl = item.get("controller_properties", {})
        controllers.append({
            "address":      ctrl.get("controller_address", ""),
            "state":        ctrl.get("controller_state", ""),
            "discoverable": ctrl.get("controller_discoverable", "") == "attrib_On",
            "firmware":     ctrl.get("controller_firmwareVersion", ""),
            "manufacturer": ctrl.get("controller_manufacturer", ""),
            "vendor_id":    ctrl.get("controller_vendorID", ""),
            "product_id":   ctrl.get("controller_productID", ""),
        })
    return {"controllers": controllers}


def _devices_mac() -> dict[str, Any]:
    data = _run_sp()
    payload = data.get("SPBluetoothDataType") or []
    connected: list[dict[str, Any]] = []
    paired:    list[dict[str, Any]] = []
    not_paired: list[dict[str, Any]] = []
    for item in payload:
        for d in item.get("device_connected", []):
            for addr, info in d.items():
                connected.append(_normalize_device_mac(addr, info))
        for d in item.get("device_paired", []):
            for addr, info in d.items():
                paired.append(_normalize_device_mac(addr, info))
        for d in item.get("device_not_paired", []):
            for addr, info in d.items():
                not_paired.append(_normalize_device_mac(addr, info))
    return {
        "connected": connected, "paired": paired, "not_paired": not_paired,
        "summary": {
            "connected": len(connected), "paired": len(paired),
            "not_paired": len(not_paired),
        },
    }


# ── Linux implementation ─────────────────────────────────────────────────────

_BT_INFO_RE = re.compile(r"^\s*([A-Za-z][\w \-]*?):\s*(.+?)\s*$")


def _bctl(args: list[str], timeout: int = 6) -> str:
    """Run bluetoothctl. Returns combined output, "" on failure."""
    bctl = shutil.which("bluetoothctl")
    if not bctl:
        raise HTTPException(503,
            "bluetoothctl not found — `apt install bluez` (or distro equivalent) "
            "and ensure the bluetooth service is running.")
    try:
        r = subprocess.run([bctl, *args],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    return r.stdout or ""


def _list_controllers_linux() -> list[dict[str, Any]]:
    """`bluetoothctl list` → controllers; `show <addr>` for details."""
    out = _bctl(["list"])
    controllers: list[dict[str, Any]] = []
    for line in out.splitlines():
        # "Controller AA:BB:CC:DD:EE:FF NameHere [default]"
        m = re.match(r"\s*Controller\s+([0-9A-Fa-f:]{17})\s+(.*?)(?:\s+\[default\])?\s*$", line)
        if not m:
            continue
        addr = m.group(1)
        name = m.group(2).strip()
        info = _bctl(["show", addr])
        info_d = _parse_bt_info(info)
        controllers.append({
            "address":      addr,
            "state":        "powered" if info_d.get("Powered", "").lower() == "yes" else "off",
            "discoverable": info_d.get("Discoverable", "").lower() == "yes",
            "firmware":     info_d.get("Modalias", ""),
            "manufacturer": name or info_d.get("Name", ""),
            "vendor_id":    "",
            "product_id":   "",
        })
    return controllers


def _parse_bt_info(text: str) -> dict[str, str]:
    """Parse `bluetoothctl info|show` output into key/value dict.

    `bluetoothctl info <addr>` lines look like:
        Device AA:BB:CC:DD:EE:FF (public)
            Name: Acme Earbuds
            Alias: Acme Earbuds
            Class: 0x00240418
            Icon: audio-headset
            Paired: yes
            Trusted: yes
            Blocked: no
            Connected: no
            UUID: ...   (one line per service)
    """
    out: dict[str, str] = {}
    uuids: list[str] = []
    for line in text.splitlines():
        # Skip the header line (e.g. "Device XX:XX...") and category markers.
        m = _BT_INFO_RE.match(line)
        if not m:
            continue
        k, v = m.group(1).strip(), m.group(2).strip()
        if k == "UUID":
            # Bluez format: "UUID: <name>             (<uuid>)"
            mm = re.match(r"(.+?)\s*\(([0-9a-fA-F-]+)\)\s*$", v)
            uuids.append(mm.group(1).strip() if mm else v)
            continue
        out[k] = v
    if uuids:
        out["_uuids"] = "\n".join(uuids)
    return out


def _list_known_addresses_linux() -> list[str]:
    """`bluetoothctl devices` lists every device the daemon knows about,
    paired or not. Returns the BD addresses in display order."""
    out = _bctl(["devices"])
    addrs: list[str] = []
    for line in out.splitlines():
        m = re.match(r"\s*Device\s+([0-9A-Fa-f:]{17})\s+", line)
        if m:
            addrs.append(m.group(1))
    return addrs


def _normalize_device_linux(addr: str, info: dict[str, str]) -> dict[str, Any]:
    name = info.get("Alias") or info.get("Name", "")
    services_raw = info.get("_uuids", "")
    services = [s for s in services_raw.splitlines() if s] if services_raw else []
    return {
        "address":      addr,
        "name":         name,
        # bluez doesn't decode the manufacturer string for arbitrary devices;
        # surface the Modalias which encodes vendor:product:version.
        "manufacturer": info.get("Modalias", ""),
        "minor_type":   info.get("Icon", ""),
        "vendor_id":    "",
        "product_id":   "",
        "firmware":     "",
        # RSSI is only present during/after active discovery.
        "battery":      info.get("Battery Percentage", ""),
        "rssi":         info.get("RSSI", ""),
        "connected":    info.get("Connected", "").lower() == "yes",
        "last_seen":    "",
        "services":     services,
    }


def _devices_linux() -> dict[str, Any]:
    addrs = _list_known_addresses_linux()
    connected:  list[dict[str, Any]] = []
    paired:     list[dict[str, Any]] = []
    not_paired: list[dict[str, Any]] = []
    for addr in addrs:
        info = _parse_bt_info(_bctl(["info", addr]))
        dev = _normalize_device_linux(addr, info)
        if dev["connected"]:
            connected.append(dev)
        if info.get("Paired", "").lower() == "yes":
            paired.append(dev)
        elif not dev["connected"]:
            not_paired.append(dev)
    return {
        "connected": connected, "paired": paired, "not_paired": not_paired,
        "summary": {
            "connected": len(connected), "paired": len(paired),
            "not_paired": len(not_paired),
        },
    }


# ── public endpoints ─────────────────────────────────────────────────────────

@router.get("/status")
def status() -> dict[str, Any]:
    require_unix(_BT_HINT)
    if IS_DARWIN:
        return _status_mac()
    return {"controllers": _list_controllers_linux()}


@router.get("/devices")
def devices(request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    require_unix(_BT_HINT)
    if IS_DARWIN:
        return _devices_mac()
    return _devices_linux()
