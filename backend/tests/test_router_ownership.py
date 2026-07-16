"""Enforces the router-ownership boundary (docs/ROUTER-OWNERSHIP.md).

A vendored tool router must NOT carry engagement/spine STATE — it couples to the
engagement model only through the lib seam (lib.scope / lib.safety / lib.mode).
Only the owned state-carrier routers may import the spine/engagements storage or
mint findings. If this fails, a tool router has crossed into Tier A: fork-and-own
it (with tests) instead of hand-editing the vendored snapshot, and add it to
OWNED below. This keeps the "which is which" boundary enforced, not just written
down.
"""
from __future__ import annotations

import re
from pathlib import Path

ROUTERS = Path(__file__).resolve().parent.parent / "routers"

# Routers allowed to touch engagement/spine STATE directly (Tier A).
OWNED = {"spine.py", "summarize.py"}

# Signals that a router carries spine/engagement state rather than just calling
# the seam: importing the spine/engagements storage, or minting findings.
STATE_SIGNALS = re.compile(
    r"from lib import spine\b"
    r"|from lib\.spine\b"
    r"|from lib import engagements\b"
    r"|from lib\.engagements\b"
    r"|create_pairing_finding"
    r"|findings_for_"
)


def test_only_owned_routers_carry_spine_state():
    offenders = []
    for p in sorted(ROUTERS.glob("*.py")):
        if p.name in OWNED or p.name == "__init__.py":
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        if STATE_SIGNALS.search(text):
            offenders.append(p.name)
    assert not offenders, (
        "vendored tool routers must couple to the engagement model only via the "
        "lib seam (lib.scope / lib.safety / lib.mode), not by carrying spine "
        f"state. These crossed the boundary: {offenders}. If that's intentional, "
        "fork-and-own the router (with tests) and add it to OWNED. "
        "See docs/ROUTER-OWNERSHIP.md."
    )
