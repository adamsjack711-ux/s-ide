"""Targets registry REST surface.

CRUD over the `targets` table in `engagements.db`. Discovery endpoints
(Tailscale / SSH config / LAN sweep) are added in `routers/targets_discover.py`
and mounted under the same `/targets` prefix.

All endpoints are gated by `require_local_auth` — the registry can hold
addresses of internal hosts and shouldn't be reachable from anywhere but
the local app session.
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import shutil
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from lib import targets as targets_lib
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/targets", tags=["targets"],
                   dependencies=[Depends(require_local_auth)])


# ── Request models ──────────────────────────────────────────────────────────

TargetKind = Literal["lab", "manual", "tailscale", "ssh", "lan"]
ScopeTag = Literal["lab", "owned", "authorized", "manual"]


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    address: str = Field(..., min_length=1, max_length=500)
    kind: TargetKind = "manual"
    engagement_id: str | None = Field(default=None, max_length=64)
    source_meta: dict[str, Any] = Field(default_factory=dict)
    scope_tag: ScopeTag = "manual"


class TargetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    address: str | None = Field(default=None, min_length=1, max_length=500)
    scope_tag: ScopeTag | None = None
    engagement_id: str | None = Field(default=None, max_length=64)
    source_meta: dict[str, Any] | None = None
    hidden: bool | None = None


# ── CRUD ────────────────────────────────────────────────────────────────────

@router.get("")
def list_all(
    engagement_id: str | None = None,
    kind: str | None = None,
    include_hidden: bool = False,
) -> dict[str, Any]:
    return {
        "targets": targets_lib.list_targets(
            engagement_id=engagement_id,
            kind=kind,
            include_hidden=include_hidden,
        ),
    }


@router.post("")
def create(body: TargetCreate) -> dict[str, Any]:
    return targets_lib.create_target(
        name=body.name,
        address=body.address,
        kind=body.kind,
        engagement_id=body.engagement_id,
        source_meta=body.source_meta,
        scope_tag=body.scope_tag,
    )


@router.get("/{tid}")
def get_one(tid: str) -> dict[str, Any]:
    t = targets_lib.get_target(tid)
    if not t:
        raise MhpError(f"target not found: {tid}",
                       code=ErrorCode.NOT_FOUND, status_code=404)
    return t


@router.patch("/{tid}")
def patch_one(tid: str, body: TargetPatch) -> dict[str, Any]:
    if targets_lib.get_target(tid) is None:
        raise MhpError(f"target not found: {tid}",
                       code=ErrorCode.NOT_FOUND, status_code=404)
    patch = body.model_dump(exclude_unset=True)
    t = targets_lib.update_target(tid, patch)
    return t  # type: ignore[return-value]


@router.delete("/{tid}")
def delete_one(tid: str) -> dict[str, bool]:
    ok = targets_lib.delete_target(tid)
    if not ok:
        raise MhpError(f"target not found: {tid}",
                       code=ErrorCode.NOT_FOUND, status_code=404)
    return {"deleted": True}


# ── Discovery ───────────────────────────────────────────────────────────────
# Each discover endpoint is read-only: it surfaces candidate targets from an
# external source but never writes to the targets table. The frontend lets
# the user pick which ones to add — adoption is always explicit.

async def _run_cmd(argv: list[str], timeout: float = 10) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return -1, "", f"timed out after {timeout}s"
    return (proc.returncode or 0,
            out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))


def _tailscale_binary() -> str | None:
    p = shutil.which("tailscale")
    if p:
        return p
    # Mac install ships the CLI inside the app bundle and symlinks
    # /usr/local/bin/tailscale to it; uvicorn may not have /usr/local/bin
    # on its inherited PATH in all launch modes.
    for guess in ("/usr/local/bin/tailscale",
                  "/Applications/Tailscale.app/Contents/MacOS/Tailscale"):
        if Path(guess).exists():
            return guess
    return None


@router.get("/discover/tailscale")
async def discover_tailscale() -> dict[str, Any]:
    """Return Self + Peer entries from `tailscale status --json`.

    Never writes to the registry. Each candidate has the shape
    ``{role, name, address, dns_name, os, online, last_seen}`` — the
    frontend POSTs the ones the user adopts back to ``POST /targets``.
    """
    binary = _tailscale_binary()
    if binary is None:
        return {"available": False, "peers": [], "error": "tailscale CLI not found"}
    rc, out, err = await _run_cmd([binary, "status", "--json"], timeout=5)
    if rc != 0:
        return {"available": True, "peers": [],
                "error": (err or out).strip()[:300] or "tailscale exited non-zero"}
    try:
        data = _json.loads(out)
    except _json.JSONDecodeError as exc:
        return {"available": True, "peers": [], "error": f"parse: {exc}"}

    def _entry(node: dict[str, Any], role: str) -> dict[str, Any] | None:
        ips = node.get("TailscaleIPs") or []
        ipv4 = next((ip for ip in ips if ":" not in ip), None)
        if not ipv4:
            return None
        return {
            "role":      role,
            "name":      node.get("HostName") or node.get("DNSName") or ipv4,
            "address":   ipv4,
            "dns_name":  (node.get("DNSName") or "").rstrip("."),
            "os":        node.get("OS") or "",
            "online":    bool(node.get("Online")),
            "last_seen": node.get("LastSeen"),
        }

    peers: list[dict[str, Any]] = []
    self_entry = _entry(data.get("Self") or {}, "self")
    if self_entry:
        peers.append(self_entry)
    for p in (data.get("Peer") or {}).values():
        e = _entry(p, "peer")
        if e:
            peers.append(e)
    return {"available": True, "peers": peers,
            "tailnet": (data.get("CurrentTailnet") or {}).get("Name", "")}


def _parse_ssh_config(text: str) -> list[dict[str, Any]]:
    """Minimal ~/.ssh/config parser.

    Returns one entry per ``Host`` block whose pattern is a single literal
    name (no glob wildcards). Glob patterns like ``Host *`` or ``*.dev``
    are intentionally skipped because they're defaults, not concrete hosts.

    Only the four keys we care about are extracted: HostName, User, Port,
    IdentityFile. Unknown keywords and ``Include`` directives are ignored.
    """
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # `Key value...` or `Key=value...` — split on first whitespace or =
        if "=" in line and not line.lower().startswith("host "):
            key, _, value = line.partition("=")
        else:
            parts = line.split(None, 1)
            if len(parts) == 1:
                continue
            key, value = parts[0], parts[1]
        key_lc = key.strip().lower()
        value = value.strip()
        if key_lc == "host":
            # Close out the in-progress block first.
            if current is not None and current.get("name"):
                entries.append(current)
            # Multi-name Host lines: take the first literal (no globs).
            patterns = [p for p in value.split() if "*" not in p and "?" not in p]
            current = {"name": patterns[0]} if patterns else None
        elif current is not None:
            if key_lc == "hostname":
                current["hostname"] = value
            elif key_lc == "user":
                current["user"] = value
            elif key_lc == "port":
                try: current["port"] = int(value)
                except ValueError: pass
            elif key_lc == "identityfile":
                current["identity_file"] = value
    if current is not None and current.get("name"):
        entries.append(current)
    return entries


@router.get("/discover/lan")
def discover_lan() -> dict[str, Any]:
    """Return hosts currently in the system ARP table on the local subnet.

    No active sweep — just reads the kernel's ARP cache, so it's fast (<1s)
    and emits zero packets. Hosts the OS hasn't recently talked to won't
    show up; for those, the user runs the actual LAN scan tool.

    Broadcast / multicast IPs are filtered out. Reverse-DNS per host is
    attempted with a short timeout so a single slow PTR lookup can't hang
    the endpoint.
    """
    # Local import: ``lib.lan`` is heavyweight (pulls socket/struct/subprocess
    # at import time and the lan_scan WS uses it) — defer until called.
    from concurrent.futures import ThreadPoolExecutor
    from ipaddress import ip_address, ip_network

    from lib import lan as lan_lib

    try:
        local = lan_lib.local_ip()
    except OSError:
        return {"available": False, "hosts": [], "error": "no local IP"}
    net_base, prefix = lan_lib.subnet_info(local)
    subnet_str = f"{net_base}/{prefix}"
    try:
        subnet = ip_network(subnet_str, strict=False)
    except ValueError:
        subnet = None

    cache = lan_lib.arp_cache()
    candidates: list[tuple[str, str]] = []
    for ip, mac in cache.items():
        try:
            addr = ip_address(ip)
        except ValueError:
            continue
        if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            continue
        if subnet is not None and addr not in subnet:
            continue
        if ip.endswith(".255"):
            continue
        candidates.append((ip, mac))

    # Reverse-DNS in parallel with a short cap so PTR-less hosts don't stall.
    hosts: list[dict[str, Any]] = []
    if candidates:
        with ThreadPoolExecutor(max_workers=min(16, len(candidates))) as pool:
            futures = {pool.submit(lan_lib.resolve_hostname, ip): (ip, mac)
                       for ip, mac in candidates}
            for fut, (ip, mac) in futures.items():
                try:
                    hostname = fut.result(timeout=1.0)
                except Exception:
                    hostname = ""
                hosts.append({
                    "address":  ip,
                    "mac":      mac,
                    "hostname": hostname,
                    "is_self":  ip == local,
                })
    hosts.sort(key=lambda h: tuple(int(x) for x in h["address"].split(".")))
    return {"available": True, "hosts": hosts, "subnet": subnet_str, "local_ip": local}


@router.get("/discover/ssh")
def discover_ssh() -> dict[str, Any]:
    """Return Host blocks from ``~/.ssh/config``.

    Each candidate is ``{name, address, user, port, identity_file}`` where
    ``address`` falls back to ``name`` when no HostName is set. Wildcard
    Host patterns are skipped. Missing config file → empty list with
    ``available=False``.
    """
    path = Path.home() / ".ssh" / "config"
    if not path.exists():
        return {"available": False, "hosts": [], "path": str(path)}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"available": True, "hosts": [], "error": str(exc), "path": str(path)}
    parsed = _parse_ssh_config(text)
    hosts = [
        {
            "name":          h["name"],
            "address":       h.get("hostname") or h["name"],
            "user":          h.get("user") or "",
            "port":          h.get("port") or 22,
            "identity_file": h.get("identity_file") or "",
        }
        for h in parsed
    ]
    return {"available": True, "hosts": hosts, "path": str(path)}
