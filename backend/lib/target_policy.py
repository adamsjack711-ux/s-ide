"""Target policy — gate every red-team-ish endpoint on a config-driven check.

Returns one of:
  ("allow", reason)  — proceed silently
  ("warn",  reason)  — proceed but UI should show a confirmation banner
  ("deny",  reason)  — refuse, return 403

The default policy is permissive: anything resolving to a private, loopback,
or Tailscale (100.64.0.0/10) address is "allow"; everything else is "warn"
unless deny_external_by_default is true. The user can move targets into
allow_external (CIDRs or exact hostnames) to silence the warning.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from functools import lru_cache
from pathlib import Path
from typing import Literal

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

Verdict = Literal["allow", "warn", "deny"]


_TAILSCALE = ipaddress.ip_network("100.64.0.0/10")


def _load_policy() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text()).get("target_policy", {})
    except (OSError, json.JSONDecodeError):
        return {}


@lru_cache(maxsize=1)
def _policy() -> dict:
    p = _load_policy()
    return {
        "allow_private": p.get("allow_private", True),
        "allow_loopback": p.get("allow_loopback", True),
        "allow_tailscale": p.get("allow_tailscale", True),
        "allow_external": list(p.get("allow_external", [])),
        "deny_external_by_default": p.get("deny_external_by_default", False),
    }


def reload_policy() -> None:
    _policy.cache_clear()


def _resolve(target: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname to a list of IPs. Returns [] on failure."""
    try:
        ipaddress.ip_address(target)
        return [ipaddress.ip_address(target)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
        ips = []
        for fam, _, _, _, sa in infos:
            try:
                ips.append(ipaddress.ip_address(sa[0]))
            except (ValueError, IndexError):
                pass
        return list(dict.fromkeys(ips))
    except socket.gaierror:
        return []


def _matches_allow_external(target: str, ips: list) -> bool:
    pol = _policy()
    for entry in pol["allow_external"]:
        entry = entry.strip()
        if not entry:
            continue
        # CIDR?
        try:
            net = ipaddress.ip_network(entry, strict=False)
            for ip in ips:
                if ip in net:
                    return True
            continue
        except ValueError:
            pass
        # Exact hostname / suffix match
        t = target.lower()
        e = entry.lower()
        if t == e or t.endswith("." + e):
            return True
    return False


def check_target(target: str) -> tuple[Verdict, str]:
    """Classify a target. `target` may be hostname or IP."""
    if not target or not target.strip():
        return "deny", "empty target"
    pol = _policy()
    ips = _resolve(target)
    if not ips:
        # Unresolvable hostname — let the caller fail naturally; classify as warn
        return "warn", f"could not resolve {target!r}"

    # Loopback / private / Tailscale checks
    for ip in ips:
        if ip.is_loopback and pol["allow_loopback"]:
            return "allow", "loopback"
    for ip in ips:
        if ip.version == 4 and ip in _TAILSCALE and pol["allow_tailscale"]:
            return "allow", "tailscale"
    for ip in ips:
        if ip.is_private and pol["allow_private"]:
            return "allow", "private"

    # External — check allowlist
    if _matches_allow_external(target, ips):
        return "allow", "in allow_external"

    if pol["deny_external_by_default"]:
        return "deny", "external target not in allow_external"

    return "warn", "external target — confirm before scanning"


def require_target(target: str, confirm: bool = False) -> str:
    """For use inside routers. Raises HTTPException on deny / unconfirmed warn.

    Pass confirm=True if the caller has already shown the warning UI and the
    user confirmed.
    """
    from fastapi import HTTPException

    verdict, reason = check_target(target)
    if verdict == "deny":
        raise HTTPException(
            status_code=403,
            detail={
                "reason": f"target denied: {reason}",
                "code": "TARGET_DENIED",
                "target": target,
            },
        )
    if verdict == "warn" and not confirm:
        raise HTTPException(
            status_code=409,
            detail={
                "reason": reason,
                "code": "NEED_CONFIRM",
                "need_confirm": True,
                "target": target,
            },
        )
    return reason
