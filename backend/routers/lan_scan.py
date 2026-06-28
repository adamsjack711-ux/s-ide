"""LAN Scan — WebSocket streaming endpoint.

REST helper:  GET /lan/info  → {local_ip, network_base, prefix, total_hosts}

WS protocol (`/ws/lan-scan`):

    client -> server (handshake):
        {}                                  // auto-detect subnet
        {"network": "192.168.0.0/24"}        // explicit

    server -> client:
        {"type": "started",  "local_ip": "...", "network": "...", "total_hosts": 254}
        {"type": "host",     "ip": "...", "hostname": "...", "mac": "..."}
        {"type": "progress", "done": 50, "total": 254, "found": 3}
        {"type": "mac_update", "ip": "...", "mac": "..."}
        {"type": "done",     "elapsed": 6.4, "found": 8, "stopped": false}
        {"type": "error",    "detail": "..."}

    client -> server (any time):
        {"action": "stop"}
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from lib import hids_notify, lan, scope
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import MAX_TARGET_LEN

logger = logging.getLogger(__name__)

router = APIRouter(tags=["lan-scan"])


def _validate_network_spec(value: str) -> tuple[str, int]:
    """Validate a CIDR network spec. Returns (base, prefix).

    LAN scanning takes IPv4 CIDR. We accept any host-bit form (strict=False)
    because users often paste "192.168.1.10/24" rather than the network
    address. Keeps the validation local rather than reaching for the generic
    target validator — CIDR isn't a hostname.
    """
    s = (value or "").strip()
    if not s:
        raise MhpError("network is required", code=ErrorCode.INVALID_RANGE)
    if len(s) > MAX_TARGET_LEN:
        raise MhpError(
            f"network is too long (max {MAX_TARGET_LEN} chars)",
            code=ErrorCode.INVALID_RANGE,
        )
    try:
        net = ipaddress.IPv4Network(s, strict=False)
    except ValueError:
        raise MhpError(
            "network is not a valid IPv4 CIDR (e.g. 192.168.1.0/24)",
            code=ErrorCode.INVALID_RANGE,
        ) from None
    return str(net.network_address), net.prefixlen


@router.get("/lan/info")
def lan_info() -> dict[str, Any]:
    try:
        ip = lan.local_ip()
        base, prefix = lan.subnet_info(ip)
    except Exception:
        logger.exception("lan_info subnet detection failed")
        raise MhpError(
            "could not determine local subnet",
            code=ErrorCode.INTERNAL,
            status_code=500,
        ) from None
    net = ipaddress.IPv4Network(f"{base}/{prefix}", strict=False)
    return {
        "local_ip":      ip,
        "network_base":  base,
        "prefix":        prefix,
        "network":       f"{base}/{prefix}",
        "total_hosts":   max(0, net.num_addresses - 2),
    }


@router.websocket("/ws/lan-scan")
async def lan_scan_ws(ws: WebSocket) -> None:
    await ws.accept()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set()
                    return
        except WebSocketDisconnect:
            stop.set()
        except Exception:
            stop.set()

    try:
        init: dict[str, Any] = await ws.receive_json()
        my_ip = lan.local_ip()

        if init.get("network"):
            try:
                base, prefix = _validate_network_spec(str(init["network"]))
            except MhpError as exc:
                await ws.send_json(ws_error(exc.code, exc.message))
                await ws.close(); return
        else:
            base, prefix = lan.subnet_info(my_ip)

        # Engagement scope on the CIDR. scope.py's IP-net matcher recognises
        # CIDR scope entries, so a scope of "10.0.0.0/8" allows any subnet
        # inside it. Defaults to allow in Lab mode.
        engagement_id = init.get("engagement_id") or None
        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        cidr_target = f"{base}/{prefix}"
        if not await scope.enforce_ws(ws, cidr_target, engagement_id, mode, confirm=confirm):
            return

        hosts = lan.subnet_hosts(base, prefix)
        targets = [h for h in hosts if h != my_ip]
        arp = lan.arp_cache()

        listener = asyncio.create_task(listen_for_stop())
        try:
            try:
                my_host = socket.gethostname()
            except Exception:
                my_host = ""

            await ws.send_json({
                "type":        "started",
                "local_ip":    my_ip,
                "network":     f"{base}/{prefix}",
                "total_hosts": len(targets),
            })
            # Always emit our own machine first
            await ws.send_json({
                "type":     "host",
                "ip":       my_ip,
                "hostname": my_host,
                "mac":      arp.get(my_ip, ""),
                "is_self":  True,
            })

            last_progress_at = 0.0

            def on_host(ip: str, hostname: str, mac: str) -> None:
                asyncio.run_coroutine_threadsafe(
                    ws.send_json({"type": "host", "ip": ip,
                                  "hostname": hostname, "mac": mac,
                                  "is_self": False}),
                    loop,
                )

            def on_progress(done: int, total: int, found: int) -> None:
                nonlocal last_progress_at
                now = time.monotonic()
                if done < total and now - last_progress_at < 0.05:
                    return
                last_progress_at = now
                asyncio.run_coroutine_threadsafe(
                    ws.send_json({"type": "progress", "done": done,
                                  "total": total, "found": found}),
                    loop,
                )

            def should_stop() -> bool:
                return stop.is_set()

            t0 = time.monotonic()
            live_ips = await loop.run_in_executor(
                None,
                lambda: lan.scan_stream(
                    targets, arp,
                    on_host=on_host, on_progress=on_progress,
                    should_stop=should_stop,
                ),
            )

            # Single ARP rebuild — TCP probes populated the kernel table by now,
            # so MACs missing initially usually resolve.
            try:
                fresh = lan.arp_cache()
                for ip in live_ips:
                    if not arp.get(ip) and fresh.get(ip):
                        await ws.send_json({"type": "mac_update",
                                            "ip": ip, "mac": fresh[ip]})
            except Exception:
                pass

            elapsed = round(time.monotonic() - t0, 2)
            await ws.send_json({
                "type": "done",
                "elapsed": elapsed,
                "found":   len(live_ips) + 1,   # + self
                "stopped": stop.is_set(),
            })
            if not stop.is_set():
                await hids_notify.notify(
                    "info", "lan-scan",
                    f"LAN scan complete — {len(live_ips) + 1} hosts on {base}/{prefix}",
                    {"network": f"{base}/{prefix}",
                     "found": len(live_ips) + 1,
                     "elapsed_seconds": elapsed},
                )
        finally:
            listener.cancel()
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("lan_scan_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during LAN scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
