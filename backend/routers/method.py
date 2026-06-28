"""Learning-sandbox model surface — assets, method steps, labs, progress.

Thin REST over lib/method.py. The report / agent-export / retest read these;
the learner UI reads ONLY /method/labs/{id}/learner (solution-safe serializer).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body
from pydantic import BaseModel

from lib import method

router = APIRouter(prefix="/method", tags=["method"])


# ── Asset graph ──────────────────────────────────────────────────────────────
class AssetIn(BaseModel):
    scope_key: str
    kind: str
    key: str
    props: dict[str, Any] = {}
    source_tool: str | None = None


@router.post("/assets")
def post_asset(body: AssetIn) -> dict[str, Any]:
    return method.record_asset(body.scope_key, body.kind, body.key, body.props, body.source_tool)


@router.post("/assets/bulk")
def post_assets_bulk(scope_key: str = Body(...), source_tool: str | None = Body(None),
                     assets: list[dict[str, Any]] = Body(...)) -> dict[str, Any]:
    out = [method.record_asset(scope_key, a.get("kind"), a.get("key"), a.get("props", {}), source_tool)
           for a in assets if a.get("kind") and a.get("key")]
    return {"recorded": out, "new": sum(1 for a in out if a.get("new"))}


@router.get("/assets/{scope_key:path}")
def get_assets(scope_key: str) -> dict[str, Any]:
    return {"assets": method.list_assets(scope_key)}


# ── Method state + steps ─────────────────────────────────────────────────────
class MethodPatch(BaseModel):
    state: str | None = None
    root_cause: dict[str, Any] | None = None
    remediation: dict[str, Any] | None = None


class StepIn(BaseModel):
    action: dict[str, Any]
    evidence: dict[str, Any]
    interpretation: str | None = None
    links_from: str | None = None
    anchored: bool = False


@router.get("/findings/{finding_id}")
def get_finding_method(finding_id: str) -> dict[str, Any]:
    return method.get_method(finding_id)


@router.patch("/findings/{finding_id}")
def patch_finding_method(finding_id: str, body: MethodPatch) -> dict[str, Any]:
    return method.upsert_method(finding_id, body.state, body.root_cause, body.remediation)


@router.post("/findings/{finding_id}/steps")
def post_step(finding_id: str, body: StepIn) -> dict[str, Any]:
    return method.append_step(finding_id, body.action, body.evidence,
                              body.interpretation, body.links_from, body.anchored)


# ── Labs (learner-safe) ──────────────────────────────────────────────────────
class LabIn(BaseModel):
    armed_snapshot: dict[str, Any] | None = None
    solution: dict[str, Any] | None = None
    learner_view: dict[str, Any] | None = None
    source_anchor: dict[str, Any] | None = None


@router.put("/labs/{lab_id}")
def put_lab(lab_id: str, body: LabIn) -> dict[str, Any]:
    method.upsert_lab(lab_id, armed_snapshot=body.armed_snapshot, solution=body.solution,
                      learner_view=body.learner_view, source_anchor=body.source_anchor)
    return {"ok": True}


@router.get("/labs/{lab_id}/learner")
def get_lab_learner(lab_id: str) -> dict[str, Any]:
    """Solution-safe — never includes the private solution."""
    return method.learner_serialize(lab_id)


# ── Progress ─────────────────────────────────────────────────────────────────
class ProgressMark(BaseModel):
    lab_solved: str | None = None
    vuln_class: str | None = None
    methodology_id: str | None = None


@router.get("/progress")
def get_progress() -> dict[str, Any]:
    return method.get_progress()


@router.post("/progress")
def post_progress(body: ProgressMark) -> dict[str, Any]:
    return method.mark_progress(lab_solved=body.lab_solved, vuln_class=body.vuln_class,
                                methodology_id=body.methodology_id)
