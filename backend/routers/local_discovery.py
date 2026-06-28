"""Local network discovery — mDNS / SSDP / LLMNR.

WS  /ws/local-discovery
    client -> server: {"protocols": ["mdns","ssdp","llmnr"], "duration": 8}
    server -> client:
      {"type":"start",  "protocols":[...], "duration":N}
      {"type":"found",  "proto":"mdns"|"ssdp"|"llmnr", ...fields}
      {"type":"done",   "elapsed", "counts":{...}}
      {"type":"error",  "detail"}
"""
from __future__ import annotations

import asyncio
import re
import socket
import struct
import time
from typing import Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from lib import hids_notify, scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode

router = APIRouter(tags=["local-discovery"], dependencies=[Depends(require_local_auth)])


# ── SSDP ──────────────────────────────────────────────────────────────────────

SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")


async def _ssdp_scan(duration: float, on_found) -> None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.setblocking(False)
    try:
        sock.sendto(SSDP_MSEARCH, (SSDP_GROUP, SSDP_PORT))
    except OSError as exc:
        sock.close()
        raise

    seen: set[tuple[str, str]] = set()
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        except OSError:
            break
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            continue
        headers: dict[str, str] = {}
        for line in text.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        st = headers.get("st") or headers.get("nt") or ""
        location = headers.get("location", "")
        server = headers.get("server", "")
        usn = headers.get("usn", "")
        key = (addr[0], usn or location)
        if key in seen:
            continue
        seen.add(key)
        await on_found({
            "proto": "ssdp", "ip": addr[0], "port": addr[1],
            "st": st, "location": location, "server": server, "usn": usn,
        })
    sock.close()


# ── LLMNR ─────────────────────────────────────────────────────────────────────

LLMNR_GROUP = "224.0.0.252"
LLMNR_PORT = 5355


def _build_llmnr_query(name: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS-style query packet."""
    tid = 0x1234
    flags = 0x0000   # standard query
    qd = 1
    header = struct.pack(">HHHHHH", tid, flags, qd, 0, 0, 0)
    qname = b"".join(struct.pack("B", len(p)) + p.encode("ascii")
                     for p in name.split(".") if p) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    return header + question


async def _llmnr_probe(duration: float, on_found) -> None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    # Send queries for some commonly-spoofed names
    for name in ("wpad", "isatap", "company", "fileserver", "printer"):
        try:
            sock.sendto(_build_llmnr_query(name), (LLMNR_GROUP, LLMNR_PORT))
        except OSError:
            pass

    seen: set[tuple[str, str]] = set()
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        except OSError:
            break
        if len(data) < 12:
            continue
        key = (addr[0], data[:12].hex())
        if key in seen:
            continue
        seen.add(key)
        await on_found({"proto": "llmnr", "ip": addr[0], "bytes": len(data)})
    sock.close()


# ── mDNS via dns-sd ───────────────────────────────────────────────────────────

async def _mdns_browse(duration: float, on_found) -> None:
    """Browse all mDNS services by enumerating service types, then browsing each."""
    types: set[str] = set()

    proc = await asyncio.create_subprocess_exec(
        "dns-sd", "-B", "_services._dns-sd._udp", "local.",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    end_browse = time.monotonic() + min(2.5, duration / 2)
    assert proc.stdout is not None
    # Lines look like:
    #   "21:48:02.439  Add  3  1  .  _tcp.local.  _airplay"
    # The service type to browse is "_airplay._tcp".
    enum_re = re.compile(
        r"\d+:\d+:\d+\.\d+\s+Add\s+\d+\s+\d+\s+\S+\s+_(tcp|udp)\.local\.\s+(\S+)\s*$"
    )
    while time.monotonic() < end_browse:
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.4)
        except asyncio.TimeoutError:
            continue
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip()
        m = enum_re.match(text)
        if m:
            proto = m.group(1)            # "tcp" or "udp"
            instance = m.group(2)         # e.g. "_airplay"
            types.add(f"{instance}._{proto}")
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=1.0)
    except (ProcessLookupError, asyncio.TimeoutError):
        try: proc.kill()
        except Exception: pass

    # Now browse each service type and collect instances
    remaining = max(1.5, duration - (time.monotonic() - (end_browse - min(2.5, duration / 2))))
    deadline = time.monotonic() + remaining
    seen: set[tuple[str, str]] = set()

    async def browse_type(svc: str) -> None:
        try:
            p = await asyncio.create_subprocess_exec(
                "dns-sd", "-B", svc, "local.",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return
        try:
            assert p.stdout is not None
            while time.monotonic() < deadline:
                try:
                    line = await asyncio.wait_for(p.stdout.readline(), timeout=0.3)
                except asyncio.TimeoutError:
                    continue
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                m = re.match(r"\d+:\d+:\d+\.\d+\s+Add\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(.+)$", text)
                if not m:
                    continue
                _domain, svc_type, instance = m.group(1), m.group(2), m.group(3).strip()
                key = (instance, svc_type)
                if key in seen:
                    continue
                seen.add(key)
                await on_found({"proto": "mdns", "service_type": svc_type,
                                "instance": instance})
        finally:
            try: p.terminate()
            except Exception: pass
            try: await asyncio.wait_for(p.wait(), timeout=0.5)
            except Exception:
                try: p.kill()
                except Exception: pass

    # Cap concurrency at 8
    if types:
        sem = asyncio.Semaphore(8)
        async def bound(t: str) -> None:
            async with sem:
                await browse_type(t)
        await asyncio.gather(*(bound(t) for t in types), return_exceptions=True)


# ── WS endpoint ───────────────────────────────────────────────────────────────

@router.websocket("/ws/local-discovery")
async def local_discovery_ws(ws: WebSocket) -> None:
    await ws.accept()
    try:
        init = await ws.receive_json()

        # LAN discovery broadcasts on the active interface; "target" is the
        # local segment, which we don't try to scope-match. Just require an
        # engagement under Engagement mode so the sweep is attributable.
        engagement_id = init.get("engagement_id") or get_engagement_id(ws)
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        if not await scope.enforce_engagement_present_ws(ws, engagement_id, mode):
            return

        protocols = init.get("protocols") or ["mdns", "ssdp", "llmnr"]
        duration = float(init.get("duration", 8))
        duration = max(2.0, min(duration, 30.0))

        await ws.send_json({"type": "start", "protocols": protocols, "duration": duration})

        counts = {"mdns": 0, "ssdp": 0, "llmnr": 0}
        send_lock = asyncio.Lock()

        async def emit(event: dict[str, Any]) -> None:
            counts[event.get("proto", "")] = counts.get(event.get("proto", ""), 0) + 1
            async with send_lock:
                await ws.send_json({"type": "found", **event})

        t0 = time.monotonic()
        tasks: list = []
        if "mdns" in protocols:
            tasks.append(_mdns_browse(duration, emit))
        if "ssdp" in protocols:
            tasks.append(_ssdp_scan(duration, emit))
        if "llmnr" in protocols:
            tasks.append(_llmnr_probe(duration, emit))

        await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({"type": "done", "elapsed": elapsed, "counts": counts})

        await hids_notify.notify(
            "info", "local-discovery",
            f"LAN discovery — mDNS={counts['mdns']} SSDP={counts['ssdp']} LLMNR={counts['llmnr']}",
            {"counts": counts, "elapsed_seconds": elapsed, "protocols": protocols},
        )

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await ws.send_json({"type": "error", "detail": str(exc)})
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
