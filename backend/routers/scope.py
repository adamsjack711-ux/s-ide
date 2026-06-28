"""Scope-check preview endpoint.

The frontend hits this *before* kicking off a scan so it can render an
in-scope / out-of-scope banner next to the target input. Tools also
call `lib.scope.check_combined` themselves at scan start — the endpoint
exists so the UI can preview without having to round-trip through a
half-started scan.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from lib import scope
from lib.auth import require_local_auth
from lib.mode import get_mode

router = APIRouter(
    prefix="/scope",
    tags=["scope"],
    dependencies=[Depends(require_local_auth)],
)


@router.get("/check")
def check(
    request: Request,
    target: str = Query(..., min_length=1, max_length=400),
    engagement_id: str | None = Query(None, max_length=64),
) -> dict[str, Any]:
    """Combined target-policy + engagement-scope check for a single target."""
    mode = get_mode(request)
    verdict, reason, layers = scope.check_combined(target, engagement_id, mode)
    return {
        "target":        target,
        "engagement_id": engagement_id,
        "mode":          mode,
        "verdict":       verdict,    # "allow" | "warn" | "deny"
        "reason":        reason,
        "layers":        layers,     # {"policy": "...", "scope": "..."}
    }


@router.post("/check-bulk")
def check_bulk(request: Request, body: dict[str, Any]) -> dict[str, Any]:
    """Run the combined check against a list of targets in one round-trip.

    Used by tools that take a multi-line target box (LAN Scan, Nmap) so
    the user can see which rows are in scope before kicking off a scan.
    Cap at 256 to keep this endpoint cheap.
    """
    targets = [str(t).strip() for t in body.get("targets") or [] if str(t).strip()]
    engagement_id = body.get("engagement_id") or None
    mode = get_mode(request)
    results: list[dict[str, Any]] = []
    for t in targets[:256]:
        verdict, reason, layers = scope.check_combined(t, engagement_id, mode)
        results.append({
            "target": t, "verdict": verdict, "reason": reason, "layers": layers,
        })
    deny_count = sum(1 for r in results if r["verdict"] == "deny")
    warn_count = sum(1 for r in results if r["verdict"] == "warn")
    return {
        "engagement_id": engagement_id,
        "mode":          mode,
        "count":         len(results),
        "deny_count":    deny_count,
        "warn_count":    warn_count,
        "results":       results,
    }
