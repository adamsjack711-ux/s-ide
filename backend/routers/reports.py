"""Engagement report export — markdown + PDF + structured preview.

Three read-only endpoints, all auth-gated, all audited as
`tool='report-export'` so the engagement's append-only log records every
deliverable that's been pulled. The actual rendering lives in
`lib/report.py` — this module is just HTTP plumbing + audit + content
disposition.

Distinct from the snapshot/rollup flow on the engagements router
(`/engagements/{eid}/report?format=html|md`) which is part of the older
AI-generated rollup pipeline. Those endpoints stay for their existing
callers; the new exporter is the defensible-workflow path.
"""
from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Query, Response

from lib import audit_log, engagements, report as report_lib
from lib.auth import mint_report_nonce
from lib.errors import ErrorCode, MhpError

logger = logging.getLogger(__name__)

# Auth + nonce gate is applied at the app level (_REPORT_GATE in main.py)
# so POST /engagement/{eid}/link can mint a path-bound nonce that the
# subsequent GET /engagement/{eid}?nonce=… consumes — without the
# stricter router-level require_local_auth blocking the nonce path.
router = APIRouter(prefix="/reports", tags=["reports"])


def _slug(name: str) -> str:
    return ("".join(c if c.isalnum() else "-" for c in name)
            .strip("-").lower()[:60] or "engagement")


def _require_engagement(eid: str) -> dict[str, Any]:
    e = engagements.get_engagement(eid)
    if e is None:
        raise MhpError("engagement not found", code=ErrorCode.NOT_FOUND,
                       status_code=404, extra={"engagement_id": eid})
    return e


@router.get("/engagement/{eid}/preview")
def preview(eid: str) -> dict[str, Any]:
    """Structured report payload as JSON.

    The frontend renders this verbatim as the on-screen preview, so the
    user sees the same structure that would land in markdown or PDF. The
    one cosmetic difference: this endpoint also returns a list of
    severity labels so the UI can render badges without duplicating the
    palette.
    """
    e = _require_engagement(eid)
    payload = report_lib.build_report_payload(eid)
    aid = audit_log.start(
        tool="report-export", target=e["name"],
        argv=["preview"], engagement_id=eid,
    )
    audit_log.complete(aid, summary="preview")
    return payload


@router.post("/engagement/{eid}/link")
def export_link(
    eid: str,
    format: Literal["markdown", "pdf"] = Query(default="markdown"),
) -> dict[str, str]:
    """Mint a one-shot 30s URL for a system-browser report open.

    See engagements.report_link for the why; same shape.
    """
    _require_engagement(eid)
    path = f"/reports/engagement/{eid}"
    nonce = mint_report_nonce(path)
    return {"url": f"{path}?format={format}&nonce={nonce}"}


@router.get("/engagement/{eid}")
def export(
    eid: str,
    format: Literal["markdown", "pdf"] = Query(default="markdown"),
) -> Response:
    e = _require_engagement(eid)
    payload = report_lib.build_report_payload(eid)
    slug = _slug(e["name"])

    if format == "markdown":
        body = report_lib.render_markdown(payload).encode("utf-8")
        media = "text/markdown; charset=utf-8"
        filename = f"{slug}.md"
    else:
        body = report_lib.render_pdf(payload)
        media = "application/pdf"
        filename = f"{slug}.pdf"

    aid = audit_log.start(
        tool="report-export", target=e["name"],
        argv=[format], engagement_id=eid,
    )
    audit_log.complete(aid, summary=f"format={format} bytes={len(body)}")

    return Response(
        content=body, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
