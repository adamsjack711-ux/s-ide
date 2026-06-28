"""S3 Bucket Scanner — permutation-based public bucket finder.

Given a target name (e.g. "acme"), generate plausible bucket names by combining
the target with common prefixes/suffixes (acme-prod, acme-backup, prod-acme,
acme-logs, acme1, etc.), then HEAD each against s3.amazonaws.com. Result
classifications:

  - 200/206         → bucket exists, listable (public)
  - 403             → bucket exists, listing forbidden (private but enumerable)
  - 404/NoSuchBucket → does not exist
  - 301             → exists in a different region

WS  /ws/s3-scan
    client -> server:
        {"target":"acme","extra_keywords":["data","internal"],
         "rate_per_sec":10}

    server -> client:
        {"type":"started",  "target","total"}
        {"type":"bucket",   "name","status","exists","listable","region"?,"hint"?}
        {"type":"progress", "done","total","found"}
        {"type":"done",     "elapsed","found","listable","stopped"}
        {"type":"error",    "detail"}
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

import httpx
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope
from lib.errors import ErrorCode, ws_error
from lib.mode import get_mode

logger = logging.getLogger(__name__)

router = APIRouter(tags=["s3-scanner"])

# Common bucket-naming patterns. Each one is templated with the target.
PERMUTATIONS = [
    "{t}",                "{t}-prod",            "{t}-production",
    "{t}-dev",            "{t}-development",     "{t}-staging",
    "{t}-stage",          "{t}-test",            "{t}-qa",
    "{t}-internal",       "{t}-corp",            "{t}-private",
    "{t}-public",         "{t}-www",             "{t}-static",
    "{t}-assets",         "{t}-cdn",             "{t}-media",
    "{t}-images",         "{t}-img",             "{t}-files",
    "{t}-data",           "{t}-database",        "{t}-db",
    "{t}-backup",         "{t}-backups",         "{t}-bak",
    "{t}-logs",           "{t}-log",             "{t}-archive",
    "{t}-upload",         "{t}-uploads",         "{t}-downloads",
    "{t}-temp",           "{t}-tmp",             "{t}-old",
    "{t}-new",             "{t}-share",           "{t}-shared",
    "{t}-data1",          "{t}-data2",
    "{t}1",               "{t}2",                "{t}3",
    "{t}-1",              "{t}-2",               "{t}-3",
    "{t}-2024",           "{t}-2025",            "{t}-2026",
    # Reversed
    "prod-{t}",           "dev-{t}",             "staging-{t}",
    "backup-{t}",         "backups-{t}",         "logs-{t}",
    "data-{t}",           "internal-{t}",        "static-{t}",
    "assets-{t}",         "media-{t}",
    "files-{t}",          "uploads-{t}",         "downloads-{t}",
    # No separator
    "{t}prod",            "{t}dev",              "{t}backup",
    "{t}logs",            "{t}data",
]

UA = "HackingPal/0.1 s3-scanner"


def generate_names(target: str, extra_keywords: list[str]) -> list[str]:
    target = target.strip().lower()
    seen: set[str] = set()
    names: list[str] = []

    # Base permutations
    for tpl in PERMUTATIONS:
        n = tpl.format(t=target)
        if _valid_bucket_name(n) and n not in seen:
            seen.add(n); names.append(n)

    # Extra keyword permutations
    for kw in extra_keywords:
        kw = kw.strip().lower()
        if not kw:
            continue
        for tpl in (
            "{t}-{kw}", "{kw}-{t}", "{t}{kw}", "{kw}{t}",
            "{t}-{kw}-prod", "{t}-{kw}-dev",
        ):
            n = tpl.format(t=target, kw=kw)
            if _valid_bucket_name(n) and n not in seen:
                seen.add(n); names.append(n)

    return names


_S3_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


def _valid_bucket_name(name: str) -> bool:
    if len(name) < 3 or len(name) > 63:
        return False
    if not _S3_NAME_RE.match(name):
        return False
    if ".." in name or ".-" in name or "-." in name:
        return False
    return True


def _classify(status: int, body: str) -> tuple[bool, bool, str | None, str | None]:
    """Return (exists, listable, region_hint, finding_hint)."""
    if status in (200, 206):
        return True, True, None, "Bucket is publicly listable"
    if status == 403:
        return True, False, None, "Bucket exists (listing forbidden)"
    if status in (301, 307):
        m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body or "")
        if m:
            return True, False, m.group(1), "Bucket exists in a different region"
        return True, False, None, "Bucket exists, redirected"
    if status == 404 or "NoSuchBucket" in (body or ""):
        return False, False, None, None
    return False, False, None, None


@router.websocket("/ws/s3-scan")
async def s3_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()
    audit_id: str | None = None

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
        engagement_id = init.get("engagement_id") or None
        if not bool(init.get("confirm_auth", False)):
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Confirm you have authorization to enumerate S3 buckets for this target.",
            ))
            await ws.close(); return
        target = str(init.get("target", "")).strip().lower()
        # Cap target + each extra keyword length so a runaway payload can't
        # produce a 100k-permutation queue.
        if len(target) > 63:
            await ws.send_json(ws_error(
                ErrorCode.INVALID_TARGET,
                "target must be 3-63 chars (S3 bucket-name limit)",
            ))
            await ws.close(); return
        extra_raw = list(init.get("extra_keywords") or [])[:20]
        extra = [str(k).strip().lower()[:32] for k in extra_raw if k]
        try:
            rate = max(1, min(int(init.get("rate_per_sec", 10)), 30))
        except (TypeError, ValueError):
            rate = 10

        if not target or not _valid_bucket_name(target.replace("_", "-")):
            await ws.send_json(ws_error(
                ErrorCode.INVALID_TARGET,
                "target must look like a bucket-name fragment (3-63 chars, lowercase letters/digits/hyphens)",
            ))
            await ws.close(); return

        # Scope check — the S3 target is an org-name fragment (e.g. "acme")
        # used to generate bucket-name permutations. Engagement scope still
        # applies: in engagement mode with scope set, the fragment must match
        # an entry (bare-host scope like "acme" or a CIDR/IP — wildcards like
        # "*.acme.com" won't match a bare fragment, by design).
        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        sc_verdict, sc_reason, sc_layers = scope.check_combined(
            target, engagement_id, mode,
        )
        await ws.send_json({
            "type": "scope", "target": target, "mode": mode,
            "verdict": sc_verdict, "reason": sc_reason, "layers": sc_layers,
        })
        if sc_verdict == "deny":
            await ws.send_json(ws_error(
                ErrorCode.TARGET_DENIED,
                f"scope check failed: {sc_reason}",
                target=target,
            ))
            await ws.close(); return
        if sc_verdict == "warn" and not confirm:
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                sc_reason, target=target, need_confirm=True,
            ))
            await ws.close(); return

        names = generate_names(target, extra)
        total = len(names)
        try:
            audit_id = audit_log.start(
                tool="s3_scanner",
                target=target,
                argv=[f"target={target}", f"extras={len(extra)}",
                      f"permutations={total}", f"rate={rate}/s"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (scan continues)")

        await ws.send_json({"type": "started", "target": target,
                            "total": total, "audit_id": audit_id})

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        done = 0
        found = 0
        listable = 0
        interval = 1.0 / rate

        async with httpx.AsyncClient(
            timeout=10.0, headers={"User-Agent": UA},
            follow_redirects=False, verify=False,
        ) as client:
            for name in names:
                if stop.is_set():
                    break
                # HEAD doesn't return the body needed for region detection,
                # so we use GET with a Range trick (or just GET, ~6KB).
                try:
                    r = await client.get(f"https://{name}.s3.amazonaws.com/")
                    status, body = r.status_code, r.text
                except Exception:
                    status, body = 0, ""
                done += 1
                exists, is_listable, region, hint = _classify(status, body)
                if exists:
                    found += 1
                    if is_listable:
                        listable += 1
                await ws.send_json({
                    "type": "bucket", "name": name, "status": status,
                    "exists": exists, "listable": is_listable,
                    "region": region, "hint": hint,
                })
                if done % 5 == 0 or done == total:
                    await ws.send_json({"type": "progress",
                                        "done": done, "total": total,
                                        "found": found})
                await asyncio.sleep(interval)

        listener.cancel()
        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({"type": "done",
                            "elapsed": elapsed,
                            "found": found, "listable": listable,
                            "stopped": stop.is_set()})
        if audit_id:
            summary = f"{found} exist, {listable} listable of {total} probed in {elapsed}s"
            try:
                if stop.is_set():
                    audit_log.stopped(audit_id, summary=summary)
                else:
                    audit_log.complete(audit_id, summary=summary)
            except Exception:
                logger.exception("audit_log finalize failed")
    except WebSocketDisconnect:
        stop.set()
        if audit_id:
            try: audit_log.stopped(audit_id, summary="client disconnected")
            except Exception: pass
    except Exception as exc:
        logger.exception("s3_scan_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during S3 scan",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
