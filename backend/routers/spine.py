"""Engagement spine — REST surface over `lib/spine.py`.

Mounted at `/spine`. The four-tab spine (Targets / Engagements / Workbench /
Findings) drives these endpoints. The hard rules live in the lib layer and are
enforced here too:

  * A sub-target is un-armed by default; `/spine/run` and `/spine/findings`
    against an un-armed sub-target are refused server-side (403,
    code=SUBTARGET_UNARMED) — the parent Target never confers authorization.
  * Arming = attaching an engagement (which carries scope + attestation). At run
    time the arming engagement's scope + the safety attestation gate apply
    (via `lib.scope` / `lib.safety`) — a local-only engagement can't reach
    outside its scope.
  * Every pairing run carries the arming engagement id onto its backend writes
    (the audit ledger row + the run record), and findings store
    { engagement_id, sub_target_id, target_id } for exact provenance + roll-up.

This router does not weaken `target_policy` and reuses the existing
`X-MHP-*` header contract via the shared auth dependency.
"""
from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from lib import spine
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/spine",
    tags=["spine"],
    dependencies=[Depends(require_local_auth)],
)


Provenance = Literal["lab", "owned", "external"]
SubTargetType = Literal["host", "service", "url", "endpoint", "directory"]
Severity = Literal["info", "low", "medium", "high", "critical"]


# ── Request models ───────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    provenance: Provenance = "external"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    provenance: Provenance | None = None
    metadata: dict[str, Any] | None = None


class SubTargetCreate(BaseModel):
    type: SubTargetType
    address: str = Field(..., min_length=1, max_length=2048)
    label: str = Field(default="", max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SubTargetPatch(BaseModel):
    type: SubTargetType | None = None
    address: str | None = Field(default=None, min_length=1, max_length=2048)
    label: str | None = Field(default=None, max_length=200)
    metadata: dict[str, Any] | None = None


class ArmRequest(BaseModel):
    engagement_id: str = Field(..., min_length=1, max_length=64)


class RunRequest(BaseModel):
    sub_target_id: str = Field(..., min_length=1, max_length=64)
    tool: str = Field(default="connect", max_length=120)


class PairingFindingCreate(BaseModel):
    sub_target_id: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=1, max_length=200)
    severity: Severity
    description: str = Field(default="", max_length=20_000)
    evidence: str = Field(default="", max_length=200_000)
    tool: str = Field(default="", max_length=200)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _target_or_404(tid: str) -> dict[str, Any]:
    t = spine.get_target(tid)
    if not t:
        raise MhpError(f"target not found: {tid}", code=ErrorCode.NOT_FOUND, status_code=404)
    return t


def _sub_or_404(sid: str) -> dict[str, Any]:
    s = spine.get_sub_target(sid)
    if not s:
        raise MhpError(f"sub-target not found: {sid}", code=ErrorCode.NOT_FOUND, status_code=404)
    return s


def _bad(e: ValueError) -> MhpError:
    return MhpError(str(e), code=ErrorCode.VALIDATION_ERROR, status_code=400)


# ── Targets ──────────────────────────────────────────────────────────────────

@router.get("/targets")
def list_targets(expand: bool = Query(False)) -> dict[str, Any]:
    targets = spine.list_targets()
    if expand:
        for t in targets:
            t["sub_targets"] = spine.list_sub_targets(t["id"])
    return {"count": len(targets), "targets": targets}


@router.post("/targets")
def create_target(body: TargetCreate) -> dict[str, Any]:
    try:
        return spine.create_target(body.name, body.provenance, body.metadata)
    except ValueError as e:
        raise _bad(e) from e


@router.get("/targets/{tid}")
def get_target(tid: str) -> dict[str, Any]:
    t = _target_or_404(tid)
    t["sub_targets"] = spine.list_sub_targets(tid)
    return t


@router.patch("/targets/{tid}")
def patch_target(tid: str, body: TargetPatch) -> dict[str, Any]:
    _target_or_404(tid)
    try:
        return spine.update_target(tid, body.model_dump(exclude_unset=True))  # type: ignore[return-value]
    except ValueError as e:
        raise _bad(e) from e


@router.delete("/targets/{tid}")
def delete_target(tid: str) -> dict[str, bool]:
    _target_or_404(tid)
    return {"deleted": spine.delete_target(tid)}


@router.get("/targets/{tid}/findings")
def target_findings(tid: str) -> dict[str, Any]:
    """A Target's findings = union across its sub-targets' pairings (roll-up)."""
    _target_or_404(tid)
    rows = spine.findings_for_target(tid)
    return {"count": len(rows), "findings": rows}


# ── Sub-targets ──────────────────────────────────────────────────────────────

@router.post("/targets/{tid}/subtargets")
def create_sub_target(tid: str, body: SubTargetCreate) -> dict[str, Any]:
    _target_or_404(tid)
    try:
        return spine.create_sub_target(
            tid, body.type, body.address, body.label, body.metadata,
        )
    except ValueError as e:
        raise _bad(e) from e


@router.get("/subtargets/{sid}")
def get_sub_target(sid: str) -> dict[str, Any]:
    return _sub_or_404(sid)


@router.patch("/subtargets/{sid}")
def patch_sub_target(sid: str, body: SubTargetPatch) -> dict[str, Any]:
    _sub_or_404(sid)
    try:
        return spine.update_sub_target(sid, body.model_dump(exclude_unset=True))  # type: ignore[return-value]
    except ValueError as e:
        raise _bad(e) from e


@router.delete("/subtargets/{sid}")
def delete_sub_target(sid: str) -> dict[str, bool]:
    _sub_or_404(sid)
    return {"deleted": spine.delete_sub_target(sid)}


@router.get("/subtargets/{sid}/runs")
def sub_target_runs(sid: str) -> dict[str, Any]:
    _sub_or_404(sid)
    rows = spine.list_runs(sid)
    return {"count": len(rows), "runs": rows}


@router.get("/subtargets/{sid}/findings")
def sub_target_findings(sid: str) -> dict[str, Any]:
    _sub_or_404(sid)
    rows = spine.findings_for_sub_target(sid)
    return {"count": len(rows), "findings": rows}


# ── Arming (attach / detach an engagement) ───────────────────────────────────

@router.post("/subtargets/{sid}/arm")
def arm_sub_target(sid: str, body: ArmRequest) -> dict[str, Any]:
    """Attach an engagement — arm the sub-target. The deliberate authorizing act."""
    _sub_or_404(sid)
    try:
        arming = spine.arm(sid, body.engagement_id)
    except ValueError as e:
        # already-armed-by-another → conflict; everything else → 400.
        if "already armed" in str(e):
            raise MhpError(str(e), code=ErrorCode.CONFLICT, status_code=409) from e
        raise _bad(e) from e
    return {"armed": True, "sub_target": spine.get_sub_target(sid), "arming": arming}


@router.post("/subtargets/{sid}/disarm")
def disarm_sub_target(sid: str) -> dict[str, Any]:
    """Detach the engagement — return the sub-target to inert (un-armed)."""
    _sub_or_404(sid)
    changed = spine.disarm(sid)
    return {"disarmed": changed, "sub_target": spine.get_sub_target(sid)}


# ── Engagement view ──────────────────────────────────────────────────────────

@router.get("/engagements/{eid}/armed")
def engagement_armed(eid: str) -> dict[str, Any]:
    """Sub-targets this engagement currently arms."""
    rows = spine.armed_sub_targets(eid)
    return {"count": len(rows), "sub_targets": rows}


@router.get("/engagements/{eid}/findings")
def engagement_findings(eid: str) -> dict[str, Any]:
    rows = spine.findings_for_engagement(eid)
    return {"count": len(rows), "findings": rows}


# ── Workbench: run a pairing (engagement × sub-target) ───────────────────────

@router.post("/run")
def run(body: RunRequest) -> dict[str, Any]:
    """Run a tool against an armed sub-target.

    Refused (403, SUBTARGET_UNARMED) if the sub-target is un-armed. On an armed
    pairing the arming engagement's scope + the attestation gate apply, the run
    is recorded + audited under that engagement id, and the completed run is
    returned. The HTTPException from the arm gate / scope layer propagates as the
    refusal response.
    """
    return spine.run_pairing(body.sub_target_id, body.tool)


# ── Findings (born from a pairing) ───────────────────────────────────────────

@router.post("/findings")
def create_finding(body: PairingFindingCreate) -> dict[str, Any]:
    """Mint a finding from an armed pairing — refused if the sub-target is un-armed."""
    try:
        return spine.create_pairing_finding(
            sub_target_id=body.sub_target_id,
            title=body.title,
            severity=body.severity,
            description=body.description,
            evidence=body.evidence,
            tool=body.tool,
        )
    except ValueError as e:
        raise _bad(e) from e


@router.get("/findings")
def list_findings(
    engagement_id: str | None = Query(None, max_length=64),
    sub_target_id: str | None = Query(None, max_length=64),
    target_id: str | None = Query(None, max_length=64),
) -> dict[str, Any]:
    """Findings filterable by engagement, by sub-target, or rolled up by Target."""
    if sub_target_id:
        rows = spine.findings_for_sub_target(sub_target_id)
    elif target_id:
        rows = spine.findings_for_target(target_id)
    elif engagement_id:
        rows = spine.findings_for_engagement(engagement_id)
    else:
        rows = spine.all_pairing_findings()
    return {"count": len(rows), "findings": rows}


# ── Default-safe local surface ───────────────────────────────────────────────

@router.post("/bootstrap-local")
def bootstrap_local() -> dict[str, Any]:
    """Declare the local machine as a lab Target + ensure a local-only engagement.

    Idempotent. Declares the pieces only — nothing is auto-armed (un-armed is the
    default); arming localhost sub-targets stays a deliberate act.
    """
    return spine.ensure_local_surface()
