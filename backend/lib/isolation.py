"""Egress self-check — the isolation gate for lab-arming.

The learning sandbox arms labs into a *fail-closed* posture: a lab may only be
armed when the host cannot reach the public internet. This module performs a
stdlib-only probe (no external deps) by attempting short-timeout outbound TCP
connects to a couple of well-known external endpoints.

The contract is deliberately inverted from intuition: isolation *holds* when
egress is **blocked**. ``ok`` is therefore ``not egress_reachable``. Callers
that arm labs MUST refuse when ``ok`` is False (see ``routers/isolation.py``).

Scope note: this gates LAB-ARMING only. Real-target engagements may legitimately
reach the internet and are not subject to this check.
"""
from __future__ import annotations

import socket
from typing import Any

# Well-known external endpoints. Port 53 (DNS) is almost always open through
# firewalls that permit any egress at all, so a successful TCP connect here is
# a strong signal that the host is NOT isolated. These are connect-only probes:
# we never send or receive application data.
_ENDPOINTS: tuple[tuple[str, int], ...] = (
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
)

# Per-endpoint connect timeout. Short by design — a held-isolation host should
# fail fast (connection refused / timed out) rather than stall the UI poll.
_TIMEOUT = 1.5


def _tcp_reachable(host: str, port: int, timeout: float = _TIMEOUT) -> bool:
    """Return True iff a TCP connection to ``host:port`` completes in time.

    Any failure (timeout, refused, unreachable network, DNS error) is treated
    as *unreachable* — i.e. isolation-positive for that endpoint.
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return True
    except OSError:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def egress_check() -> dict[str, Any]:
    """Probe a couple of external endpoints and report isolation posture.

    Returns::

        {
          "egress_reachable": bool,     # any endpoint reachable
          "checks": [{"target": "1.1.1.1:53", "reachable": bool}, ...],
          "ok": bool,                   # == not egress_reachable (isolation HOLDS)
        }
    """
    checks: list[dict[str, Any]] = []
    egress_reachable = False
    for host, port in _ENDPOINTS:
        reachable = _tcp_reachable(host, port)
        if reachable:
            egress_reachable = True
        checks.append({"target": f"{host}:{port}", "reachable": reachable})
    return {
        "egress_reachable": egress_reachable,
        "checks": checks,
        "ok": not egress_reachable,
    }
