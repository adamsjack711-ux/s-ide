"""Audit Log — read-only HTTP surface over `lib/audit_log.py`.

Mounted at `/audit-log` (not `/audit`, which already belongs to the
Network Audit WS in `routers/audit.py`). The frontend page is at
`/audit` on the React side; the path collision is API-vs-UI only.

Endpoints are intentionally read-only — actions get logged automatically
by the tools themselves (via `lib.audit_log.start/complete/error`). Even
admin can't mutate or delete rows through the API; the table is the
trust anchor for the engagement report.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query

from lib import audit_log
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/audit-log",
    tags=["audit-log"],
    dependencies=[Depends(require_local_auth)],
)


@router.get("")
def list_actions(
    engagement_id: str | None = Query(None, max_length=64),
    tool: str | None = Query(None, max_length=120),
    status: str | None = Query(None, pattern="^(started|completed|error|stopped)$"),
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    rows = audit_log.list_actions(
        engagement_id=engagement_id, tool=tool, status=status, limit=limit,
    )
    return {"count": len(rows), "actions": rows}


@router.get("/stats")
def stats() -> dict[str, Any]:
    """Per-tool invocation counts + status breakdown."""
    return {"tools": audit_log.tool_counts()}


@router.get("/{action_id}")
def get_one(action_id: str) -> dict[str, Any]:
    if not action_id or len(action_id) > 64:
        raise MhpError(
            "invalid action id",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    row = audit_log.get_action(action_id)
    if not row:
        raise MhpError(
            "audit action not found",
            code=ErrorCode.NOT_FOUND,
            status_code=404,
        )
    return row
