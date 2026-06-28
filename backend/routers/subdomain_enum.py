"""Subdomain enumeration — aggregates multiple external sources.

Free sources (no key): crt.sh, HackerTarget, AlienVault OTX, RapidDNS.
Key-gated (read from Keychain via settings router): SecurityTrails, VirusTotal,
Shodan. Sources fire concurrently; we dedupe + resolve.

WS  /ws/subdom-enum
    client -> server:
        {"domain":"example.com", "sources":[...], "resolve":true}

    server -> client:
        {"type":"started",     "domain","sources":[...]}
        {"type":"source_start","source"}
        {"type":"found",       "name","ip"|null,"sources":[...]}     # per discovery
        {"type":"source_done", "source","count","error"?}
        {"type":"done",        "elapsed","total","resolved","stopped"}
        {"type":"error",       "detail"}
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from typing import Any

import httpx
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from lib import audit_log, scope
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_mode
from lib.validators import validate_domain

from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(tags=["subdomain-enum"])

UA = "HackingPal/0.1 subdomain-enum"
TIMEOUT = 15.0

ALL_SOURCES = [
    "crt.sh", "hackertarget", "otx", "rapiddns",
    "securitytrails", "virustotal", "shodan",
]

# Permutation generation — applied after the initial enum settles, only to
# the labels we've already seen (so the wordlist stays scoped to the
# target's own naming conventions).
_PERM_PREFIXES = (
    "dev", "staging", "stage", "prod", "production", "test", "uat", "qa",
    "old", "new", "internal", "external", "admin", "private", "public",
    "secure", "beta", "alpha", "demo", "preview",
)
_PERM_SUFFIXES = ("2", "3", "v2", "v3", "-v2", "-v3", "-old", "-new")
_PERM_CONCURRENCY = 32      # max in-flight DNS lookups
_PERM_HARD_CAP   = 3000     # hard ceiling on the permutation set we test


async def _resolve(host: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except OSError:
        return None


def _build_permutations(domain: str, found: list[str]) -> list[str]:
    """Generate candidate subdomains from the labels already discovered.

    Only mutates the *leaf* label of each known subdomain so the candidate
    set stays bounded:

        api.example.com -> dev-api.example.com, staging-api.example.com,
                           api-v2.example.com, api2.example.com, ...
    """
    suffix = "." + domain
    leaves: set[str] = set()
    for sub in found:
        if sub.endswith(suffix):
            label = sub[: -len(suffix)]
            # Skip multi-level labels like api.us-east — we'd combinatorially
            # explode and most of them point at internal naming we'd never
            # guess. The leftmost label is the high-signal one.
            leaves.add(label.split(".", 1)[0])

    # Always add the bare common labels even if we didn't see them, so an
    # initial enum that returned only `www.` still gets the obvious tests.
    leaves.update({"www", "mail", "api"})

    candidates: set[str] = set()
    for label in leaves:
        for prefix in _PERM_PREFIXES:
            candidates.add(f"{prefix}-{label}.{domain}")
            candidates.add(f"{prefix}.{label}.{domain}")
        for suf in _PERM_SUFFIXES:
            candidates.add(f"{label}{suf}.{domain}")
    # Drop anything we already know about.
    for sub in found:
        candidates.discard(sub)
    out = sorted(candidates)
    if len(out) > _PERM_HARD_CAP:
        out = out[:_PERM_HARD_CAP]
    return out


async def src_crtsh(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    r.raise_for_status()
    data = r.json()
    out: set[str] = set()
    for row in data:
        nv = row.get("name_value", "")
        for line in nv.split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line.endswith(domain) and line != domain:
                out.add(line)
    return sorted(out)


async def src_hackertarget(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    r.raise_for_status()
    text = r.text or ""
    if "API count exceeded" in text or "error" in text[:50].lower():
        raise RuntimeError(text.strip()[:120])
    out: set[str] = set()
    for line in text.splitlines():
        name = line.split(",", 1)[0].strip().lower()
        if name.endswith(domain) and name != domain:
            out.add(name)
    return sorted(out)


async def src_otx(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    )
    r.raise_for_status()
    data = r.json()
    out: set[str] = set()
    for rec in data.get("passive_dns", []):
        h = rec.get("hostname", "").lower()
        if h.endswith(domain) and h != domain:
            out.add(h)
    return sorted(out)


async def src_rapiddns(client: httpx.AsyncClient, domain: str) -> list[str]:
    # RapidDNS exposes an HTML endpoint; parse rows of <td>name</td>.
    r = await client.get(f"https://rapiddns.io/subdomain/{domain}?full=1")
    r.raise_for_status()
    import re
    out: set[str] = set()
    for m in re.finditer(r"<td>([\w\-.]+\." + re.escape(domain) + r")</td>",
                         r.text, re.IGNORECASE):
        n = m.group(1).lower()
        if n != domain:
            out.add(n)
    return sorted(out)


async def src_securitytrails(client: httpx.AsyncClient, domain: str, key: str) -> list[str]:
    r = await client.get(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false",
        headers={"APIKEY": key},
    )
    if r.status_code == 401:
        raise RuntimeError("SecurityTrails: invalid key (401)")
    r.raise_for_status()
    data = r.json()
    return sorted({f"{s.lower()}.{domain}" for s in data.get("subdomains", [])})


async def src_virustotal(client: httpx.AsyncClient, domain: str, key: str) -> list[str]:
    r = await client.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100",
        headers={"x-apikey": key},
    )
    if r.status_code == 401:
        raise RuntimeError("VirusTotal: invalid key (401)")
    r.raise_for_status()
    data = r.json()
    return sorted({d.get("id", "").lower() for d in data.get("data", [])
                   if d.get("id", "").lower().endswith(domain)})


async def src_shodan(client: httpx.AsyncClient, domain: str, key: str) -> list[str]:
    r = await client.get(
        f"https://api.shodan.io/dns/domain/{domain}?key={key}",
    )
    if r.status_code == 401:
        raise RuntimeError("Shodan: invalid key (401)")
    r.raise_for_status()
    data = r.json()
    out: set[str] = set()
    for sub in data.get("subdomains", []):
        out.add(f"{sub.lower()}.{domain}")
    return sorted(out)


SOURCE_CONFIG = {
    "crt.sh":         {"fn": src_crtsh,         "needs_key": None},
    "hackertarget":   {"fn": src_hackertarget,  "needs_key": None},
    "otx":            {"fn": src_otx,           "needs_key": None},
    "rapiddns":       {"fn": src_rapiddns,      "needs_key": None},
    "securitytrails": {"fn": src_securitytrails,"needs_key": "securitytrails_api_key"},
    "virustotal":     {"fn": src_virustotal,    "needs_key": "virustotal_api_key"},
    "shodan":         {"fn": src_shodan,        "needs_key": "shodan_api_key"},
}


@router.get("/subdom/status")
def status() -> dict[str, Any]:
    return {
        "sources": [
            {"name": s, "needs_key": cfg["needs_key"] is not None,
             "key_configured": (cfg["needs_key"] is None
                                or keychain_get_named(cfg["needs_key"]) is not None)}
            for s, cfg in SOURCE_CONFIG.items()
        ]
    }


@router.websocket("/ws/subdom-enum")
async def subdom_ws(ws: WebSocket) -> None:
    await ws.accept()
    stop = asyncio.Event()
    audit_id: str | None = None

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set(); return
        except WebSocketDisconnect:
            stop.set()
        except Exception:
            stop.set()

    try:
        init = await ws.receive_json()
        engagement_id = init.get("engagement_id") or None
        if not bool(init.get("confirm_auth", False)):
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                "Confirm you have authorization to enumerate this domain.",
            ))
            await ws.close(); return
        raw_domain = str(init.get("domain", "")).strip().lower().lstrip(".")
        sources = list(init.get("sources") or ALL_SOURCES)
        do_resolve = bool(init.get("resolve", True))
        run_permutations = bool(init.get("permutations", True))

        try:
            domain = validate_domain(raw_domain, field="domain")
        except MhpError as exc:
            await ws.send_json(ws_error(exc.code, exc.message))
            await ws.close(); return

        # Scope check — combines target_policy + engagement scope, gated by
        # Lab/Engagement mode. `confirm` lets the client re-send the handshake
        # after the user acknowledges a `warn` verdict.
        confirm = bool(init.get("confirm", False))
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )
        sc_verdict, sc_reason, sc_layers = scope.check_combined(
            domain, engagement_id, mode,
        )
        await ws.send_json({
            "type": "scope", "target": domain, "mode": mode,
            "verdict": sc_verdict, "reason": sc_reason, "layers": sc_layers,
        })
        if sc_verdict == "deny":
            await ws.send_json(ws_error(
                ErrorCode.TARGET_DENIED,
                f"scope check failed: {sc_reason}",
                target=domain,
            ))
            await ws.close(); return
        if sc_verdict == "warn" and not confirm:
            await ws.send_json(ws_error(
                ErrorCode.NEED_CONFIRM,
                sc_reason, target=domain, need_confirm=True,
            ))
            await ws.close(); return

        sources = [s for s in sources if s in SOURCE_CONFIG]
        try:
            audit_id = audit_log.start(
                tool="subdomain_enum",
                target=domain,
                argv=[f"sources={','.join(sources)}",
                      f"resolve={do_resolve}", f"permutations={run_permutations}"],
                engagement_id=engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (enum continues)")

        await ws.send_json({"type": "started", "domain": domain,
                            "sources": sources, "audit_id": audit_id})

        listener = asyncio.create_task(listen_for_stop())
        t0 = time.monotonic()
        seen: dict[str, dict[str, Any]] = {}
        # name -> {"sources": [..], "ip": None}

        async with httpx.AsyncClient(
            timeout=TIMEOUT, headers={"User-Agent": UA},
            follow_redirects=True,
        ) as client:
            async def run_one(name: str) -> None:
                if stop.is_set():
                    return
                cfg = SOURCE_CONFIG[name]
                await ws.send_json({"type": "source_start", "source": name})
                key = None
                if cfg["needs_key"]:
                    key = keychain_get_named(cfg["needs_key"])
                    if not key:
                        await ws.send_json({"type": "source_done",
                                            "source": name, "count": 0,
                                            "error": f"no API key configured ({cfg['needs_key']})"})
                        return
                try:
                    found = await cfg["fn"](client, domain, key) if key else await cfg["fn"](client, domain)
                except Exception as e:
                    await ws.send_json({"type": "source_done", "source": name,
                                        "count": 0, "error": f"{type(e).__name__}: {e}"})
                    return
                count = 0
                for sub in found:
                    if stop.is_set():
                        break
                    if sub in seen:
                        if name not in seen[sub]["sources"]:
                            seen[sub]["sources"].append(name)
                        continue
                    seen[sub] = {"sources": [name], "ip": None}
                    ip = await _resolve(sub) if do_resolve else None
                    seen[sub]["ip"] = ip
                    count += 1
                    await ws.send_json({"type": "found", "name": sub,
                                        "ip": ip, "sources": seen[sub]["sources"]})
                await ws.send_json({"type": "source_done", "source": name, "count": count})

            await asyncio.gather(*(run_one(s) for s in sources),
                                 return_exceptions=True)

            # ── Phase 2: permutation engine ────────────────────────────────
            # Run only if the caller asked for it and there's anything to
            # mutate against. DNS lookups happen in the executor; we cap
            # concurrency so we don't accidentally DoS the resolver.
            perm_found = 0
            if run_permutations and not stop.is_set():
                candidates = _build_permutations(domain, list(seen.keys()))
                if candidates:
                    await ws.send_json({
                        "type":    "phase",
                        "phase":   "permutation",
                        "count":   len(candidates),
                        "message": f"Testing {len(candidates)} permutations...",
                    })
                    sem = asyncio.Semaphore(_PERM_CONCURRENCY)

                    async def probe(name: str) -> None:
                        nonlocal perm_found
                        if stop.is_set():
                            return
                        async with sem:
                            ip = await _resolve(name)
                        if not ip or stop.is_set():
                            return
                        if name not in seen:
                            seen[name] = {"sources": ["permutation"], "ip": ip}
                            perm_found += 1
                            # `send_json` raises if the client disconnected
                            # mid-scan. We're in gather(return_exceptions=True)
                            # so the exception would be silently captured —
                            # explicit try/except keeps the intent visible
                            # and lets us flip `stop` so sibling probes exit.
                            try:
                                await ws.send_json({
                                    "type": "permutation_found",
                                    "subdomain": name,
                                    "ip": ip,
                                })
                            except (WebSocketDisconnect, RuntimeError):
                                stop.set()

                    await asyncio.gather(
                        *(probe(c) for c in candidates),
                        return_exceptions=True,
                    )

        listener.cancel()
        elapsed = round(time.monotonic() - t0, 2)
        total_found = len(seen)
        resolved_count = sum(1 for v in seen.values() if v["ip"])
        await ws.send_json({
            "type": "done", "elapsed": elapsed,
            "total": total_found,
            "resolved": resolved_count,
            "permutations_found": perm_found if run_permutations else 0,
            "stopped": stop.is_set(),
        })
        if audit_id:
            summary = (f"{total_found} unique, {resolved_count} resolved, "
                       f"{elapsed}s")
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
        logger.exception("subdom_ws unhandled exception")
        if audit_id:
            try: audit_log.error(audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during subdomain enumeration",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
