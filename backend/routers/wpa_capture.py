"""WPA Handshake / PMKID Capture wrapper.

Detects the aircrack-ng / hcxdumptool toolchain, lists wireless interfaces,
and streams output from a chosen capture command.

Cross-platform notes:
  - **macOS**: the built-in WiFi card cannot enter monitor mode; users need
    an external USB adapter (commonly routed to a Kali Linux VM).
  - **Linux**: native monitor-mode support — this is the canonical platform.
    The toolchain typically ships via `aircrack-ng` + `hcxdumptool` packages.
  - **Windows**: not supported (npcap monitor mode is fragmented).
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from lib import audit_log
from lib.auth import require_local_auth

logger = logging.getLogger(__name__)
from lib.platform_util import IS_DARWIN, IS_LINUX, require_unix

router = APIRouter(prefix="/wpa-capture", tags=["wpa-capture"], dependencies=[Depends(require_local_auth)])

_WPA_HINT = ("WPA capture wraps the aircrack-ng / hcxdumptool toolchain on "
             "macOS and Linux. Windows is not supported (npcap monitor mode "
             "is fragmented).")

# Tools we know about + their roles
TOOL_INFO = {
    "aircrack-ng": "Crack captured WPA handshakes against a wordlist.",
    "airodump-ng": "Capture frames; the standard handshake-capture tool.",
    "aireplay-ng": "Inject deauth frames to trigger reconnection.",
    "hcxdumptool": "Capture PMKID (modern WPA2 attack — no client needed).",
    "hcxpcapngtool": "Convert .pcapng to hashcat 22000 format.",
    "hashcat":      "Crack PMKID / handshake hashes (modes 22000 / 2500).",
}


def _list_macos_interfaces() -> list[dict[str, Any]]:
    """Parse `networksetup -listallhardwareports` blocks into structured records."""
    ifaces: list[dict[str, Any]] = []
    try:
        r = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return ifaces
    if r.returncode != 0:
        return ifaces

    def _flush(block: dict[str, str]) -> None:
        if not block.get("Device"):
            return
        port = block.get("Hardware Port", "")
        port_low = port.lower()
        ifaces.append({
            "device": block.get("Device", ""),
            "name":   port,
            "mac":    block.get("Ethernet Address", ""),
            "is_wifi": "wi-fi" in port_low or "wifi" in port_low,
            "is_usb":  "usb" in port_low,
        })

    block: dict[str, str] = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            _flush(block); block = {}
        elif ":" in line:
            k, _, v = line.partition(":")
            block[k.strip()] = v.strip()
    _flush(block)
    return ifaces


def _list_linux_interfaces() -> list[dict[str, Any]]:
    """Read /sys/class/net to find every interface with a wireless capability.

    We only return wireless devices here — wpa_capture is for monitor-mode
    captures, and there's no point flagging eth0. `is_usb` is detected by
    resolving /sys/class/net/<dev>/device to a path under /sys/devices/.../usb*.
    """
    ifaces: list[dict[str, Any]] = []
    net = Path("/sys/class/net")
    if not net.is_dir():
        return ifaces
    for dev in sorted(net.iterdir()):
        if not (dev / "wireless").exists():
            continue
        try:
            mac = (dev / "address").read_text().strip()
        except OSError:
            mac = ""
        is_usb = False
        try:
            phys = (dev / "device").resolve()
            is_usb = "/usb" in str(phys) or any(p.name.startswith("usb") for p in phys.parents)
        except OSError:
            pass
        ifaces.append({
            "device": dev.name,
            "name":   "Wi-Fi (USB)" if is_usb else "Wi-Fi",
            "mac":    mac,
            "is_wifi": True,
            "is_usb":  is_usb,
        })
    return ifaces


@router.get("/status")
def status() -> dict[str, Any]:
    """Detect installed wireless tools + list wireless interfaces (best effort)."""
    require_unix(_WPA_HINT)
    tools: dict[str, dict[str, Any]] = {}
    for name, descr in TOOL_INFO.items():
        path = shutil.which(name)
        tools[name] = {"installed": bool(path), "path": path or "", "description": descr}

    if IS_DARWIN:
        ifaces = _list_macos_interfaces()
        note = ("macOS removed monitor-mode + frame-injection from the built-in "
                "WiFi card (airport sniff). For real handshake / PMKID captures "
                "use an external USB adapter passed through to a Kali Linux VM — "
                "AWUS036ACS / AWUS036ACH are common picks.")
    elif IS_LINUX:
        ifaces = _list_linux_interfaces()
        note = ("Linux supports monitor mode natively. Install the toolchain "
                "via `apt install aircrack-ng hcxtools hcxdumptool` (Debian) "
                "or your distro's equivalent. Most onboard cards work; an "
                "external Atheros/Ralink adapter avoids driver headaches.")
    else:
        ifaces, note = [], ""

    return {"tools": tools, "interfaces": ifaces, "platform_note": note,
            # Back-compat: existing frontend still reads `macos_note`.
            "macos_note": note}


@router.websocket("/ws/run")
async def run_capture(ws: WebSocket) -> None:
    """Stream output from a user-chosen capture command.

    init = {"argv": ["airodump-ng", "-c", "6", "--bssid", "AA:BB:...", "wlan0mon"]}
    """
    await ws.accept()
    stop = asyncio.Event()

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set(); return
        except Exception:
            stop.set()

    proc: asyncio.subprocess.Process | None = None
    audit_id: str | None = None
    try:
        init = await ws.receive_json()
        engagement_id = init.get("engagement_id") or None
        if not bool(init.get("confirm_auth", False)):
            await ws.send_json({
                "type": "error",
                "code": "NEED_CONFIRM",
                "detail": "Confirm you have authorization to capture / deauth on this WiFi.",
            })
            await ws.close(); return
        argv = list(init.get("argv") or [])
        if not argv:
            await ws.send_json({"type": "error", "detail": "argv required"})
            await ws.close(); return

        # Allow only known tools
        binary = argv[0].split("/")[-1]
        if binary not in TOOL_INFO:
            await ws.send_json({"type": "error",
                "detail": f"refusing to run {binary!r} (not in allowlist)"})
            await ws.close(); return

        # argv[1:] is intentionally a free-form compose surface — this is an
        # advanced-user endpoint for airodump/aircrack/hcxdumptool flag combos
        # we can't usefully whitelist. Per-arg shell-meta + length guard is
        # defense in depth (argv goes to create_subprocess_exec without a shell).
        BAD_CHARS = set(";|&`$\n\r\0")
        for a in argv[1:]:
            if not isinstance(a, str) or len(a) > 512:
                await ws.send_json({"type": "error",
                    "detail": "argv entry too long or not a string"})
                await ws.close(); return
            if any(c in BAD_CHARS for c in a):
                await ws.send_json({"type": "error",
                    "detail": f"argv entry contains forbidden characters: {a!r}"})
                await ws.close(); return

        path = shutil.which(binary)
        if not path:
            hint = ("`brew install aircrack-ng hcxdumptool`" if IS_DARWIN
                    else "`apt install aircrack-ng hcxtools hcxdumptool` (Debian/Ubuntu) "
                         "or your distro's equivalent")
            await ws.send_json({"type": "error",
                "detail": f"{binary!r} not installed (try {hint})"})
            await ws.close(); return

        try:
            audit_id = audit_log.start(
                tool="wpa_capture",
                target=binary,
                argv=[path] + argv[1:],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (capture continues)")

        await ws.send_json({"type": "started", "cmd": [path] + argv[1:],
                            "audit_id": audit_id})
        listener = asyncio.create_task(listen_for_stop())

        proc = await asyncio.create_subprocess_exec(
            path, *argv[1:],
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        if proc.stdout is None:
            await ws.send_json({"type": "error",
                                "detail": "subprocess stdout pipe unavailable"})
            await ws.close(); return
        async for raw in proc.stdout:
            if stop.is_set():
                proc.terminate(); break
            line = raw.decode(errors="replace").rstrip("\n")
            await ws.send_json({"type": "line", "text": line})

        rc = await proc.wait()
        listener.cancel()
        await ws.send_json({"type": "done", "rc": rc, "stopped": stop.is_set()})
        if audit_id:
            summary = f"{binary} rc={rc}"
            try:
                if stop.is_set():
                    audit_log.stopped(audit_id, summary=summary)
                else:
                    audit_log.complete(audit_id, summary=summary)
            except Exception:
                logger.exception("audit_log finalize failed")
    except WebSocketDisconnect:
        stop.set()
        if proc and proc.returncode is None:
            proc.terminate()
        if audit_id:
            try: audit_log.stopped(audit_id, summary="client disconnected")
            except Exception: pass
    except Exception as exc:
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json({"type": "error",
                                "detail": f"{type(exc).__name__}: {exc}"})
        except Exception:
            pass
        if proc and proc.returncode is None:
            try: proc.terminate()
            except Exception: pass
    finally:
        try: await ws.close()
        except Exception: pass
