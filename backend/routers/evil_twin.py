"""Evil Twin Detector — flag duplicate SSIDs with suspicious differences.

We run N scans (default 3) spaced apart, aggregate observations per (SSID,
BSSID), and surface findings when two different BSSIDs claim the same SSID
*and* something about them looks like an evil twin:

  - Different security types (e.g. real AP is WPA2-Personal, twin is Open) —
    classic captive-portal evil twin.
  - Different vendor OUI prefixes (manufacturers).
  - One signal much stronger than the legitimate AP (proximity hint).
  - One AP only intermittently visible.

WS  /ws/evil-twin
    client -> server:
        {"scans": 3, "interval_sec": 2.0, "target_ssid": "<optional>"}
    server -> client:
        {"type":"scan_start", "round": 1, "total": 3}
        {"type":"observation","ssid","bssid","rssi","security","round"}
        {"type":"finding", "ssid","bssids":[...], "reason","severity"}
        {"type":"done","total_unique","groups": N,"stopped"}
        {"type":"error","detail"}
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from lib import scope
from lib.errors import ErrorCode, ws_error
from lib.mode import get_mode

from .wifi_scan import scan_networks

logger = logging.getLogger(__name__)

router = APIRouter(tags=["evil-twin"])


@router.websocket("/ws/evil-twin")
async def evil_twin_ws(ws: WebSocket) -> None:
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

    try:
        init = await ws.receive_json()
        # SSID is not a network endpoint; scope's hostname/CIDR matching
        # doesn't apply. Just require an active engagement under Engagement
        # mode so the scan ties to a record.
        engagement_id = init.get("engagement_id") or None
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        if not await scope.enforce_engagement_present_ws(ws, engagement_id, mode):
            return
        try:
            rounds = max(1, min(int(init.get("scans", 3)), 10))
        except (TypeError, ValueError):
            rounds = 3
        try:
            interval = max(0.5, min(float(init.get("interval_sec", 2.0)), 30.0))
        except (TypeError, ValueError):
            interval = 2.0
        target_raw = init.get("target_ssid") or ""
        if not isinstance(target_raw, str):
            target_raw = ""
        # SSIDs are capped at 32 bytes by 802.11 — clamp aggressively to stop
        # pathological input from being kept around in the observation map.
        target = (target_raw.strip()[:64]) or None

        # First scan also serves as a health check — surface scanner errors
        # before we start the round loop so the UI can show a usable message.
        loop = asyncio.get_event_loop()
        try:
            first = await loop.run_in_executor(None, scan_networks)
        except HTTPException as e:
            await ws.send_json(ws_error(
                ErrorCode.TOOL_FAILED, str(e.detail),
            ))
            await ws.close(); return
        if not first.get("interface"):
            await ws.send_json(ws_error(
                ErrorCode.TOOL_MISSING, "no WiFi interface",
            ))
            await ws.close(); return

        listener = asyncio.create_task(listen_for_stop())

        # (ssid, bssid) -> list of observations
        observations: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

        for round_no in range(1, rounds + 1):
            if stop.is_set():
                break
            await ws.send_json({"type": "scan_start", "round": round_no, "total": rounds})

            if round_no == 1:
                rows = first.get("networks", [])
            else:
                try:
                    snap = await loop.run_in_executor(None, scan_networks)
                    rows = snap.get("networks", [])
                except HTTPException as e:
                    await ws.send_json(ws_error(
                        ErrorCode.TOOL_FAILED, str(e.detail),
                    ))
                    rows = []

            for r in rows:
                ssid = r["ssid"]
                bssid = r["bssid"]
                if not ssid or not bssid:
                    continue
                if target and ssid != target:
                    continue
                observations[(ssid, bssid)].append({
                    "round": round_no, "rssi": r["rssi"],
                    "security": r["security"], "channel": r["channel"],
                    "oui": r["oui"],
                })
                await ws.send_json({
                    "type": "observation", "ssid": ssid, "bssid": bssid,
                    "rssi": r["rssi"], "security": r["security"], "round": round_no,
                })

            if round_no < rounds and not stop.is_set():
                await asyncio.sleep(interval)

        # Correlate
        ssid_to_bssids: dict[str, list[str]] = defaultdict(list)
        for (ssid, bssid) in observations:
            if bssid not in ssid_to_bssids[ssid]:
                ssid_to_bssids[ssid].append(bssid)

        findings_emitted = 0
        for ssid, bssids in ssid_to_bssids.items():
            if len(bssids) < 2:
                continue

            # Pull the latest observation per BSSID for comparison
            samples: list[dict[str, Any]] = []
            for b in bssids:
                obs = observations[(ssid, b)]
                if not obs:
                    continue
                latest = obs[-1]
                samples.append({"bssid": b, **latest, "rounds_seen": len(obs)})

            reasons: list[str] = []
            severity = "info"

            sec_set = set(s["security"] for s in samples)
            if len(sec_set) > 1:
                reasons.append(f"different security types: {sorted(sec_set)}")
                severity = "high"

            ouis = set(s["oui"] for s in samples if s["oui"])
            if len(ouis) > 1:
                reasons.append(f"different vendor OUIs: {sorted(ouis)}")
                if severity != "high":
                    severity = "medium"

            channels = set(s["channel"] for s in samples)
            if len(channels) > 1:
                reasons.append(f"different channels: {sorted(channels)}")
                if severity == "info":
                    severity = "low"

            # Intermittent visibility
            rounds_counts = sorted(s["rounds_seen"] for s in samples)
            if rounds_counts[0] < rounds_counts[-1]:
                reasons.append(
                    f"intermittent: one BSSID seen in "
                    f"{rounds_counts[0]}/{rounds} scans vs {rounds_counts[-1]}/{rounds}"
                )

            # RSSI gap (one much stronger = closer to operator)
            rssis = [s["rssi"] for s in samples]
            if max(rssis) - min(rssis) > 20:
                reasons.append(
                    f"RSSI gap {max(rssis) - min(rssis)} dB "
                    f"({min(rssis)} → {max(rssis)})"
                )

            if not reasons:
                reasons.append("multiple BSSIDs for the same SSID (could be roaming)")

            await ws.send_json({
                "type": "finding", "ssid": ssid,
                "bssids": [s["bssid"] for s in samples],
                "samples": samples,
                "reasons": reasons,
                "severity": severity,
            })
            findings_emitted += 1

        listener.cancel()
        await ws.send_json({
            "type": "done",
            "total_unique": len(observations),
            "groups": findings_emitted,
            "stopped": stop.is_set(),
        })
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("evil_twin_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during evil twin scan",
            ))
        except Exception:
            pass
    finally:
        try: await ws.close()
        except Exception: pass
