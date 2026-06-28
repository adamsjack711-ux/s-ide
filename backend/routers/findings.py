"""Findings tracker — standalone HTTP surface over `lib/engagements.py`.

Findings are the evidence layer for engagements. A user "promotes" a scan
result on any tool page into a tracked finding attached to the active
engagement. Findings carry severity + status + description + raw evidence
(the captured scan output snippet) and feed the engagement report.

All endpoints are scoped to a single engagement via `?engagement_id=` (on
list/create) or via the finding's own engagement reference (read/update/
delete). The existing `/engagements/{eid}/findings` surface still works —
the tracker is the dedicated endpoint that's safer for promote-from-result
flows because the page only needs to thread `engagement_id`, not nest its
calls under an engagement path.

Every write appends an `audit_log` row with `tool='finding-<action>'` so
the engagement's trust anchor records who promoted/edited/removed what.
"""
from __future__ import annotations

import logging
from typing import Any, Literal

import anthropic
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from lib import audit_log, cvss as cvss_lib, engagements
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError

from .chat import resolve_model
from .settings import keychain_get
from .summarize import _resolve_summarize_prompt, _serialize_raw

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
    dependencies=[Depends(require_local_auth)],
)


Severity = Literal["info", "low", "medium", "high", "critical"]
# Canonical statuses only — legacy values (triaged/fixed/wont_fix) still
# load from the DB but the tracker won't accept new writes against them.
Status = Literal["open", "confirmed", "false_positive", "remediated"]

EvidenceType = Literal[
    "scan_output", "request_response", "screenshot_ref", "note", "command",
]


class FindingCreate(BaseModel):
    engagement_id:   str = Field(..., min_length=1, max_length=64)
    title:           str = Field(..., min_length=1, max_length=200)
    severity:        Severity
    description:     str = Field("", max_length=20_000)
    tool:            str = Field("", max_length=200)
    target:          str = Field("", max_length=500)
    evidence:        str = Field("", max_length=200_000)
    cvss_vector:     str | None = Field(None, max_length=200)
    cvss:            float | None = Field(None, ge=0, le=10)
    linked_result_id: str | None = Field(None, max_length=64)
    status:          Status = "open"


class EvidenceCreate(BaseModel):
    """Append a piece of evidence to a finding.

    `captured_at` is the OBSERVATION time (when the scan ran, when the
    request was sent). It defaults to "now" but the composer can override
    it so a tester can backfill historical proof and the timeline still
    tells the truth. `created_at` is set server-side at write time.
    """
    type:         EvidenceType
    content:      str = Field("", max_length=200_000)
    source_tool:  str | None = Field(default=None, max_length=200)
    captured_at:  str | None = Field(default=None, max_length=40)


class CvssScoreRequest(BaseModel):
    """Apply a CVSS v3.1 base score to a finding.

    Accepts either an explicit `vector` string OR a `metrics` object with
    the eight base metrics. Exactly one must be supplied. The endpoint
    canonicalises the vector, persists `cvss` + `cvss_vector`, and bumps
    the finding's `severity` to match the CVSS band (so the badge across
    the app reflects the scored value rather than the original heuristic).
    """
    vector:  str | None = Field(default=None, max_length=200)
    metrics: dict[str, str] | None = None


class FindingPatch(BaseModel):
    title:        str | None = Field(None, min_length=1, max_length=200)
    severity:     Severity | None = None
    description:  str | None = Field(None, max_length=20_000)
    tool:         str | None = Field(None, max_length=200)
    target:       str | None = Field(None, max_length=500)
    evidence:     str | None = Field(None, max_length=200_000)
    ai_summary:   str | None = Field(None, max_length=20_000)
    cvss_vector:  str | None = Field(None, max_length=200)
    cvss:         float | None = Field(None, ge=0, le=10)
    status:       Status | None = None


def _require_engagement(eid: str) -> dict[str, Any]:
    eng = engagements.get_engagement(eid)
    if not eng:
        raise MhpError(
            "engagement not found",
            code=ErrorCode.NOT_FOUND,
            status_code=404,
            extra={"engagement_id": eid},
        )
    return eng


def _require_finding(fid: str) -> dict[str, Any]:
    f = engagements.get_finding(fid)
    if not f:
        raise MhpError(
            "finding not found",
            code=ErrorCode.NOT_FOUND,
            status_code=404,
            extra={"finding_id": fid},
        )
    return f


def _audit_summary(f: dict[str, Any]) -> str:
    sev = (f.get("severity") or "").upper()
    title = (f.get("title") or "")[:120]
    return f"[{sev}] {title}" if sev else title


@router.get("")
def list_for_engagement(
    engagement_id: str = Query(..., min_length=1, max_length=64),
) -> dict[str, Any]:
    _require_engagement(engagement_id)
    rows = engagements.list_findings(engagement_id)
    return {"count": len(rows), "findings": rows}


@router.get("/{fid}")
def get_one(fid: str) -> dict[str, Any]:
    return _require_finding(fid)


@router.post("")
def create(body: FindingCreate) -> dict[str, Any]:
    _require_engagement(body.engagement_id)
    try:
        f = engagements.create_finding(
            engagement_id=body.engagement_id,
            title=body.title,
            severity=body.severity,
            description=body.description,
            evidence=body.evidence,
            cvss=body.cvss,
            cvss_vector=body.cvss_vector,
            tool=body.tool,
            target=body.target,
            linked_result_id=body.linked_result_id,
            status=body.status,
        )
    except ValueError as e:
        raise MhpError(str(e), code=ErrorCode.VALIDATION_ERROR, status_code=400) from e
    aid = audit_log.start(
        tool="finding-create",
        target=body.target or body.title[:120],
        argv=[body.severity, body.status],
        engagement_id=body.engagement_id,
    )
    audit_log.complete(aid, summary=_audit_summary(f))
    return f


@router.patch("/{fid}")
def patch(fid: str, body: FindingPatch) -> dict[str, Any]:
    existing = _require_finding(fid)
    patch_dict = body.model_dump(exclude_none=True)
    if not patch_dict:
        return existing
    try:
        updated = engagements.update_finding(fid, patch_dict)
    except ValueError as e:
        raise MhpError(str(e), code=ErrorCode.VALIDATION_ERROR, status_code=400) from e
    if updated is None:
        raise MhpError("finding not found", code=ErrorCode.NOT_FOUND, status_code=404)
    aid = audit_log.start(
        tool="finding-update",
        target=updated.get("target") or updated.get("title") or fid,
        argv=sorted(patch_dict.keys()),
        engagement_id=existing.get("engagement_id"),
    )
    audit_log.complete(aid, summary=_audit_summary(updated))
    return updated


@router.get("/{fid}/evidence")
def list_evidence(fid: str) -> dict[str, Any]:
    """List evidence items chronologically (oldest captured_at first).

    Read-time fallback: if a finding pre-dates the evidence table, the
    legacy `findings.evidence` blob is synthesized into a virtual
    scan_output item (id starts with `legacy-`) so older findings keep
    their proof on the timeline. The virtual item can't be DELETEd
    through this surface — edit the finding's description/evidence
    instead.
    """
    _require_finding(fid)
    items = engagements.list_evidence(fid)
    return {"count": len(items), "items": items}


@router.post("/{fid}/evidence")
def add_evidence(fid: str, body: EvidenceCreate) -> dict[str, Any]:
    existing = _require_finding(fid)
    try:
        item = engagements.add_evidence(
            finding_id=fid,
            type=body.type,
            content=body.content,
            source_tool=body.source_tool,
            captured_at=body.captured_at,
        )
    except ValueError as e:
        raise MhpError(str(e), code=ErrorCode.VALIDATION_ERROR, status_code=400) from e
    aid = audit_log.start(
        tool="evidence-add",
        target=existing.get("target") or existing.get("title") or fid,
        argv=[body.type, body.source_tool or ""],
        engagement_id=existing.get("engagement_id"),
    )
    audit_log.complete(aid, summary=f"[{body.type}] {body.content[:80]}")
    return item


@router.delete("/{fid}/evidence/{eid}")
def remove_evidence(fid: str, eid: str) -> dict[str, Any]:
    existing = _require_finding(fid)
    if eid.startswith("legacy-"):
        raise MhpError(
            "This is a synthesized item from the legacy evidence blob. "
            "Edit the finding's evidence field directly to remove it.",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    ok = engagements.delete_evidence(eid)
    if not ok:
        raise MhpError("evidence not found", code=ErrorCode.NOT_FOUND, status_code=404)
    aid = audit_log.start(
        tool="evidence-delete",
        target=existing.get("target") or existing.get("title") or fid,
        argv=[eid],
        engagement_id=existing.get("engagement_id"),
    )
    audit_log.complete(aid, summary=_audit_summary(existing))
    return {"deleted": True, "id": eid}


@router.post("/{fid}/ai-summary")
def ai_summary(fid: str) -> dict[str, Any]:
    """Generate an AI summary of the finding's evidence and store it on the row.

    Synchronous (non-streaming) — the call site fires-and-forgets after
    promotion. Reuses the same Anthropic client + prompt + model the
    `/summarize/stream` route uses so the wording is consistent with the
    in-tool "Summarize results" button.
    """
    existing = _require_finding(fid)

    api_key = keychain_get()
    if not api_key:
        raise MhpError(
            "Anthropic API key not set. Add one in Settings to enable summaries.",
            code="MISSING_API_KEY",
            status_code=401,
        )

    tool = existing.get("tool") or "(unknown tool)"
    target = existing.get("target") or ""
    evidence = existing.get("evidence") or ""
    description = existing.get("description") or ""
    title = existing.get("title") or ""

    if not evidence.strip() and not description.strip():
        raise MhpError(
            "Finding has no evidence or description to summarize.",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )

    raw_payload: dict[str, Any] = {"title": title}
    if description.strip():
        raw_payload["description"] = description
    if evidence.strip():
        raw_payload["evidence"] = evidence
    raw_serialized = _serialize_raw(raw_payload)

    user_message = (
        f"**Tool:** `{tool}`\n"
        + (f"**Target:** `{target}`\n" if target else "")
        + "\n**Raw result:**\n```\n"
        + raw_serialized
        + "\n```"
    )

    client = anthropic.Anthropic(api_key=api_key)
    model_name = resolve_model()
    system_prompt = _resolve_summarize_prompt()

    try:
        msg = client.messages.create(
            model=model_name,
            max_tokens=900,
            system=[{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": user_message}],
        )
    except anthropic.AuthenticationError as e:
        raise MhpError(
            "Anthropic rejected the API key. Check it in Settings.",
            code="UPSTREAM_AUTH",
            status_code=401,
        ) from e
    except anthropic.RateLimitError as e:
        raise MhpError(
            "Rate limited by Anthropic. Retry shortly.",
            code="UPSTREAM_RATE_LIMIT",
            status_code=429,
        ) from e
    except anthropic.APIError as e:
        logger.warning("anthropic api error type=%s", type(e).__name__)
        raise MhpError(
            "Anthropic API error — check the logs",
            code="UPSTREAM_ERROR",
            status_code=502,
        ) from e

    full_text = "".join(
        block.text for block in msg.content if getattr(block, "type", "") == "text"
    ).strip()
    if not full_text:
        raise MhpError(
            "Anthropic returned an empty summary.",
            code="UPSTREAM_ERROR",
            status_code=502,
        )

    try:
        updated = engagements.update_finding(fid, {"ai_summary": full_text})
    except ValueError as e:
        raise MhpError(str(e), code=ErrorCode.VALIDATION_ERROR, status_code=400) from e
    if updated is None:
        raise MhpError("finding not found", code=ErrorCode.NOT_FOUND, status_code=404)

    aid = audit_log.start(
        tool="finding-ai-summary",
        target=updated.get("target") or updated.get("title") or fid,
        argv=[model_name],
        engagement_id=existing.get("engagement_id"),
    )
    audit_log.complete(aid, summary=_audit_summary(updated))
    return updated


# CVSS bands → Finding severity values. None maps to "info" because the
# tracker doesn't model a "no impact" severity — and a scored 0.0 finding
# is still on the engagement timeline, just at the lowest tier.
_CVSS_BAND_TO_SEVERITY: dict[str, str] = {
    "None":     "info",
    "Low":      "low",
    "Medium":   "medium",
    "High":     "high",
    "Critical": "critical",
}


@router.post("/{fid}/cvss")
def score_cvss(fid: str, body: CvssScoreRequest) -> dict[str, Any]:
    """Score a finding via CVSS v3.1 and update its severity to the band.

    Accepts either `vector` or `metrics`. The cvss lib raises MhpError on
    malformed input, which propagates as a 400 envelope. After persistence,
    the finding's severity reflects the CVSS band — manual labels lose to
    a scored vector by design (single source of truth for the badge).
    """
    existing = _require_finding(fid)

    has_vector = bool(body.vector and body.vector.strip())
    has_metrics = bool(body.metrics)
    if has_vector == has_metrics:
        raise MhpError(
            "supply exactly one of `vector` or `metrics`",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )

    if has_vector:
        metrics = cvss_lib.parse_vector(body.vector or "")
    else:
        metrics = body.metrics or {}

    scored = cvss_lib.score_from_metrics(metrics)
    severity = _CVSS_BAND_TO_SEVERITY[scored["severity"]]

    try:
        updated = engagements.update_finding(fid, {
            "cvss":         scored["base_score"],
            "cvss_vector":  scored["vector"],
            "severity":     severity,
        })
    except ValueError as e:
        raise MhpError(str(e), code=ErrorCode.VALIDATION_ERROR, status_code=400) from e
    if updated is None:
        raise MhpError("finding not found", code=ErrorCode.NOT_FOUND, status_code=404)

    aid = audit_log.start(
        tool="finding-cvss",
        target=updated.get("target") or updated.get("title") or fid,
        argv=[scored["vector"], f"{scored['base_score']}"],
        engagement_id=existing.get("engagement_id"),
    )
    audit_log.complete(aid, summary=_audit_summary(updated))
    return updated


@router.delete("/{fid}")
def remove(fid: str) -> dict[str, Any]:
    existing = _require_finding(fid)
    ok = engagements.delete_finding(fid)
    if not ok:
        raise MhpError("finding not found", code=ErrorCode.NOT_FOUND, status_code=404)
    aid = audit_log.start(
        tool="finding-delete",
        target=existing.get("target") or existing.get("title") or fid,
        argv=[],
        engagement_id=existing.get("engagement_id"),
    )
    audit_log.complete(aid, summary=_audit_summary(existing))
    return {"deleted": True, "id": fid}
