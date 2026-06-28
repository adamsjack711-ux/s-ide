"""Network Audit — two-phase WebSocket.

Phase 1: TCP-probe sweep of the subnet (reuses lib.lan).
Phase 2: scan each live host for known-risky ports (lib.audit).

Protocol (`/ws/audit`):

    client -> server:
        {}                                 // auto-detect subnet
        {"network": "192.168.0.0/24"}
        {"target_host": "127.0.0.1"}        // skip Phase 1, audit single host
        {"action": "stop"}                  // any time

    server -> client:
        {"type": "started",   "local_ip", "network", "total_hosts"}
        {"type": "phase",     "phase": "discovery" | "audit"}
        {"type": "progress",  "pct": 0..1, "label": "..."}
        {"type": "host",      "ip", "hostname", "is_self",
                              "open_risky": [{port, service, risk}, ...],
                              "risk_level": "clean"|"low"|"medium"|"high"|"critical"}
        {"type": "done",      "elapsed", "hosts_audited", "stopped"}
        {"type": "error",     "detail"}
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit, hids_notify, lan
from lib.errors import ErrorCode, MhpError, ws_error
from lib.validators import MAX_TARGET_LEN, validate_target

logger = logging.getLogger(__name__)

_HIDS_RISK_SEVERITY = {"high": "warning", "critical": "critical"}

router = APIRouter(tags=["audit"])


@router.websocket("/ws/audit")
async def audit_ws(ws: WebSocket) -> None:
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
        raw_target = init.get("target_host")
        if isinstance(raw_target, str):
            raw_target = raw_target.strip()
        else:
            raw_target = ""
        raw_net = init.get("network")
        if raw_target:
            # Single-host override: validate, resolve, skip Phase 1.
            if len(raw_target) > MAX_TARGET_LEN:
                await ws.send_json(ws_error(
                    ErrorCode.INVALID_TARGET,
                    f"target_host too long (max {MAX_TARGET_LEN} chars)",
                ))
                await ws.close(); return
            try:
                normalised = validate_target(raw_target, field="target_host")
            except MhpError as exc:
                await ws.send_json(ws_error(
                    exc.code, str(exc),
                ))
                await ws.close(); return
            # Resolve hostname -> IP if needed so downstream code sees an IP.
            try:
                ipaddress.ip_address(normalised)
                target_ip = normalised
            except ValueError:
                try:
                    target_ip = socket.gethostbyname(normalised)
                except OSError as exc:
                    await ws.send_json(ws_error(
                        ErrorCode.INVALID_TARGET,
                        f"could not resolve target_host: {exc}",
                    ))
                    await ws.close(); return
            base, prefix = target_ip, 32
        elif raw_net:
            # Strip + length cap before letting ipaddress parse: the network
            # spec is user input and ipaddress will happily parse a 10 MB
            # string before failing.
            raw_net = str(raw_net).strip()
            if len(raw_net) > MAX_TARGET_LEN:
                await ws.send_json(ws_error(
                    ErrorCode.INVALID_TARGET,
                    f"network spec too long (max {MAX_TARGET_LEN} chars)",
                ))
                await ws.close(); return
            try:
                net = ipaddress.IPv4Network(raw_net, strict=False)
                base, prefix = str(net.network_address), net.prefixlen
            except ValueError as exc:
                await ws.send_json(ws_error(
                    ErrorCode.INVALID_TARGET,
                    f"bad network spec: {exc}",
                ))
                await ws.close(); return
        else:
            base, prefix = lan.subnet_info(my_ip)

        listener = asyncio.create_task(listen_for_stop())
        try:
            single_host_mode = bool(raw_target)
            t0 = time.monotonic()

            def should_stop() -> bool:
                return stop.is_set()

            discovered: list[tuple[str, str, bool]] = []   # (ip, hostname, is_self)

            if single_host_mode:
                # Skip Phase 1 entirely — treat target_ip as the sole live host.
                target_hostname = ""
                if raw_target != target_ip:
                    # User typed a hostname; preserve it for the row label.
                    target_hostname = raw_target
                else:
                    try:
                        target_hostname = socket.gethostbyaddr(target_ip)[0]
                    except (OSError, socket.herror):
                        target_hostname = ""
                discovered.append((target_ip, target_hostname, target_ip == my_ip))

                await ws.send_json({
                    "type": "started",
                    "local_ip":    my_ip,
                    "network":     f"{base}/{prefix}",
                    "total_hosts": 1,
                })
                await ws.send_json({"type": "phase", "phase": "discovery"})
                await ws.send_json({
                    "type": "progress", "pct": 0.5,
                    "label": f"Discovery skipped · auditing {target_ip}",
                })
            else:
                targets = [h for h in lan.subnet_hosts(base, prefix) if h != my_ip]
                arp     = lan.arp_cache()

                await ws.send_json({
                    "type": "started",
                    "local_ip":    my_ip,
                    "network":     f"{base}/{prefix}",
                    "total_hosts": len(targets) + 1,
                })

                # ── Phase 1: discovery ────────────────────────────────────
                await ws.send_json({"type": "phase", "phase": "discovery"})

                last_progress_at = 0.0
                try:
                    my_hostname = socket.gethostname()
                except Exception:
                    my_hostname = ""
                discovered.append((my_ip, my_hostname, True))

                def on_disc_host(ip: str, hostname: str, mac: str) -> None:
                    # We don't surface every alive host yet — we wait for audit
                    # results. Just buffer for Phase 2.
                    discovered.append((ip, hostname, False))

                def on_disc_progress(d: int, tot: int, found: int) -> None:
                    nonlocal last_progress_at
                    now = time.monotonic()
                    if d < tot and now - last_progress_at < 0.07:
                        return
                    last_progress_at = now
                    pct = (d / tot) * 0.5 if tot else 0.5
                    asyncio.run_coroutine_threadsafe(
                        ws.send_json({"type": "progress", "pct": pct,
                                      "label": f"Discovering {d}/{tot} · {found} found"}),
                        loop,
                    )

                await loop.run_in_executor(
                    None,
                    lambda: lan.scan_stream(
                        targets, arp,
                        on_host=on_disc_host,
                        on_progress=on_disc_progress,
                        should_stop=should_stop,
                    ),
                )

            if stop.is_set():
                await ws.send_json({"type": "done",
                                    "elapsed": round(time.monotonic() - t0, 2),
                                    "hosts_audited": 0,
                                    "stopped": True})
                return

            # ── Phase 2: audit ──────────────────────────────────────────────
            await ws.send_json({"type": "phase", "phase": "audit"})
            await ws.send_json({"type": "progress", "pct": 0.5,
                                "label": f"Auditing {len(discovered)} hosts…"})

            last_progress_at = 0.0
            risky_count = 0

            def on_audit_host(ip: str, hostname: str, is_self: bool,
                              open_risky: list[dict], risk_level: str) -> None:
                nonlocal risky_count
                asyncio.run_coroutine_threadsafe(
                    ws.send_json({"type": "host", "ip": ip,
                                  "hostname": hostname, "is_self": is_self,
                                  "open_risky": open_risky,
                                  "risk_level": risk_level}),
                    loop,
                )
                hids_sev = _HIDS_RISK_SEVERITY.get(risk_level)
                if hids_sev:
                    risky_count += 1
                    hids_notify.notify_threadsafe(
                        hids_sev, "audit",
                        f"Risky host {ip}{' (' + hostname + ')' if hostname else ''}",
                        {"ip": ip, "hostname": hostname,
                         "risk_level": risk_level,
                         "open_risky": open_risky},
                    )

            def on_audit_progress(done: int, total: int, hosts_done: int) -> None:
                nonlocal last_progress_at
                now = time.monotonic()
                if done < total and now - last_progress_at < 0.07:
                    return
                last_progress_at = now
                pct = 0.5 + (done / total) * 0.5 if total else 1.0
                asyncio.run_coroutine_threadsafe(
                    ws.send_json({"type": "progress", "pct": pct,
                                  "label": f"Auditing {hosts_done}/{len(discovered)} hosts…"}),
                    loop,
                )

            await loop.run_in_executor(
                None,
                lambda: audit.audit_stream(
                    discovered,
                    on_host=on_audit_host,
                    on_progress=on_audit_progress,
                    should_stop=should_stop,
                ),
            )

            await ws.send_json({"type": "done",
                                "elapsed": round(time.monotonic() - t0, 2),
                                "hosts_audited": len(discovered),
                                "stopped": stop.is_set()})
            if not stop.is_set():
                await hids_notify.notify(
                    "info", "audit",
                    f"Network audit done — {len(discovered)} hosts, {risky_count} risky",
                    {"network": f"{base}/{prefix}",
                     "hosts_audited": len(discovered),
                     "risky_count": risky_count,
                     "elapsed_seconds": round(time.monotonic() - t0, 2)},
                )
        finally:
            listener.cancel()
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("audit_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during network audit",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
