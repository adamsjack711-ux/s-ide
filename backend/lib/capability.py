"""Server-side capability enforcement — the hard half of "open but secure".

The sandbox posture is *maximally open capability, safe default*: privileged /
intrusive / external-setup tools ship registered and callable, but stay OFF
until the operator enables their group. Until now that "off until enabled" gate
lived only in the frontend (``shell/tools/capability.ts`` → localStorage), so a
direct API call to ``/ws/xss`` or ``/ws/nmap`` bypassed it entirely.

This module moves the gate server-side. A gated router carries a
``require_capability(group)`` dependency; the request is refused (HTTP 403 / WS
1008) unless that group has been enabled via ``POST /capabilities/{group}``.
Enablement persists to ``capabilities.json`` in the app-data dir and is
audit-logged. Scope + authorization attestation remain separate hard gates on
top of this.

Group keys are the frontend's display-group strings ("Web Exploit", "Active
Directory", …) so the UI toggle and the backend gate share one vocabulary.
"""
from __future__ import annotations

import json
import threading

from fastapi import HTTPException, WebSocketException, status
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocket

from lib.platform_util import app_data_dir

# ── Group → gated router keys ───────────────────────────────────────────────
# Only the privileged / intrusive routers appear here; the always-on Tier-1
# tools in the same UI group (e.g. `fingerprint` in Recon) are intentionally
# absent, so enabling a group unlocks exactly the tools the UI gates. Keys are
# the ``routers/<key>.py`` module names used in ``main.py``.
GROUP_ROUTERS: dict[str, tuple[str, ...]] = {
    "Web Exploit": ("xss", "sqli", "cmdi", "lfi", "ssrf", "idor"),
    "Active Directory": (
        "ldap_enum", "smb_enum", "ad_spray", "kerberos_roast",
        "bloodhound_ingest", "lateral",
    ),
    "Red Team": ("reverse_shell", "c2_beacon"),
    "Recon": ("nmap",),
    "Discovery": ("lan_scan",),
    "Web Recon": ("subdomain_enum",),
}

# Inverse: router key → its capability group (None ⇒ ungated / always available).
ROUTER_GROUP: dict[str, str] = {
    key: group for group, keys in GROUP_ROUTERS.items() for key in keys
}

ALL_GROUPS: tuple[str, ...] = tuple(GROUP_ROUTERS.keys())


def router_group(key: str) -> str | None:
    """The capability group gating this router key, or None if ungated."""
    return ROUTER_GROUP.get(key)


# ── Persisted enablement state ──────────────────────────────────────────────
_lock = threading.Lock()
_STORE = app_data_dir() / "capabilities.json"


def _load() -> set[str]:
    try:
        raw = json.loads(_STORE.read_text())
        return {g for g in raw if g in GROUP_ROUTERS}
    except (OSError, ValueError):
        return set()


_enabled: set[str] = _load()


def _persist() -> None:
    try:
        _STORE.parent.mkdir(parents=True, exist_ok=True)
        _STORE.write_text(json.dumps(sorted(_enabled)))
    except OSError:
        # Non-fatal: enablement still holds in-memory for this session.
        pass


def is_enabled(group: str) -> bool:
    with _lock:
        return group in _enabled


def enabled_groups() -> set[str]:
    with _lock:
        return set(_enabled)


def set_enabled(group: str, on: bool) -> None:
    """Enable/disable a capability group and persist. Unknown groups raise."""
    if group not in GROUP_ROUTERS:
        raise KeyError(group)
    with _lock:
        if on:
            _enabled.add(group)
        else:
            _enabled.discard(group)
        _persist()


# ── The dependency ──────────────────────────────────────────────────────────
def _reject(conn: HTTPConnection, detail: str) -> None:
    if isinstance(conn, WebSocket):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason=detail)
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def require_capability(group: str):
    """Build a FastAPI dependency that refuses the request unless ``group`` is
    enabled. Works for both HTTP and WebSocket routes (same HTTPConnection
    pattern as the auth guards)."""

    def _guard(conn: HTTPConnection) -> None:
        if not is_enabled(group):
            _reject(
                conn,
                f"capability '{group}' is disabled — enable it in "
                f"Settings → Capabilities",
            )

    return _guard
