"""Safety — HTTP surface over `lib/safety.py`.

Mounted at `/safety`. Lets the operator inspect a target's provenance and
manage authorization attestations (the deliberate, gated exceptions that let
an active run reach OUTSIDE the sandbox).

The attestation *gate* itself is enforced server-side inside the active tool
routers (via `lib.scope.enforce_ws/enforce_rest(active=True)`), not here — this
router only creates / lists attestations and reports provenance. There is no
endpoint to bypass the gate; an external active run with no covering
attestation is refused at the tool boundary with a 403.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from lib import safety
from lib.auth import require_local_auth

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/safety",
    tags=["safety"],
    dependencies=[Depends(require_local_auth)],
)


class AttestationCreate(BaseModel):
    engagement_id: str | None = Field(default=None, max_length=64)
    targets: list[str] = Field(default_factory=list)
    window_start: str = Field(min_length=1, max_length=40)
    window_end: str = Field(min_length=1, max_length=40)
    authority_note: str = Field(default="", max_length=4000)
    attested_by: str = Field(default="", max_length=200)


@router.get("/attestations")
def list_attestations(
    engagement_id: str | None = Query(None, max_length=64),
) -> dict[str, Any]:
    rows = safety.list_attestations(engagement_id)
    return {"count": len(rows), "attestations": rows}


@router.post("/attestations")
def create_attestation(body: AttestationCreate) -> dict[str, Any]:
    att = safety.create_attestation(
        engagement_id=body.engagement_id,
        targets=body.targets,
        window_start=body.window_start,
        window_end=body.window_end,
        authority_note=body.authority_note,
        attested_by=body.attested_by,
    )
    return {"attestation": att}


@router.get("/provenance")
def get_provenance(target: str = Query(..., min_length=1, max_length=2048)) -> dict[str, str]:
    return {"provenance": safety.provenance(target)}
