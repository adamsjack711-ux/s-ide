"""Engagement self-assessment API — readiness gaps for one engagement.

`GET /self-assess/{eid}` returns the readiness report computed by
`lib.self_assess`: recon coverage, findings quality (evidence / CVSS / triage),
external-target attestation, and report export. Read-only; no new storage.
Gated by the same loopback + token guards as every privileged route (applied
in `main.py`).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from lib import self_assess

router = APIRouter(prefix="/self-assess", tags=["self-assess"])


@router.get("/{eid}")
def get_self_assessment(eid: str) -> dict[str, Any]:
    return self_assess.assess(eid)
