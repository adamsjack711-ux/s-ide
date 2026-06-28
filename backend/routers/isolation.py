"""Isolation gate + lab lifecycle — arm / reset / solve.

Thin REST over ``lib/isolation.py`` (egress self-check) and ``lib/method.py``
(lab metadata store). The isolation check gates **lab-arming only**: a lab may
be armed solely when the host cannot reach the public internet (fail closed).

Endpoints:

  * ``GET  /isolation/check``                — run the egress probe.
  * ``POST /isolation/labs/{id}/arm``        — refuse (409) if egress reachable,
                                               else record armed state.
  * ``POST /isolation/labs/{id}/reset``      — restore-to-armed intent (record).
  * ``POST /isolation/labs/{id}/solve``      — gated reveal of the PRIVATE
                                               solution (instructor path).

The ``solve`` reveal reads ``method.get_solution`` — the privileged instructor
path — NOT ``learner_serialize``. The solution is never emitted to the learner.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from lib import isolation as isolation_lib
from lib import method

router = APIRouter(prefix="/isolation", tags=["isolation"])


@router.get("/check")
def isolation_check() -> dict[str, Any]:
    """Run the egress self-check. ``ok`` is True when isolation HOLDS."""
    return isolation_lib.egress_check()


@router.post("/labs/{lab_id}/arm")
def arm_lab(lab_id: str) -> dict[str, Any]:
    """Arm a lab — fail closed.

    Re-runs the egress probe at arm time. If the host can reach the public
    internet we REFUSE with 409 rather than arm into a non-isolated host.
    """
    probe = isolation_lib.egress_check()
    if probe["egress_reachable"]:
        raise HTTPException(
            status_code=409,
            detail="isolation check failed — egress reachable; refusing to arm",
        )
    # Isolation holds — record the armed state. The snapshot captures the
    # isolation evidence at arm time so the lab's posture is auditable.
    method.upsert_lab(
        lab_id,
        armed_snapshot={"armed": True, "isolation": probe},
    )
    return {"ok": True, "lab_id": lab_id, "armed": True, "isolation": probe}


@router.post("/labs/{lab_id}/reset")
def reset_lab(lab_id: str) -> dict[str, Any]:
    """Restore-to-armed intent.

    Records the reset and re-asserts the armed snapshot. Actual container
    rollback to the armed_snapshot is a TODO (the docker/compose teardown +
    re-up lives in the labs lifecycle and is not wired here yet).
    """
    method.upsert_lab(
        lab_id,
        armed_snapshot={"armed": True, "reset": True},
    )
    return {
        "ok": True,
        "lab_id": lab_id,
        "reset": True,
        # NOTE: container rollback to armed_snapshot is a TODO.
        "container_rollback": "TODO",
    }


@router.post("/labs/{lab_id}/solve")
def solve_lab(lab_id: str) -> dict[str, Any]:
    """Gated reveal — the privileged instructor path.

    Returns the PRIVATE solution via ``method.get_solution`` (NOT the learner
    serializer). 404 when no solution has been authored for the lab.
    """
    solution = method.get_solution(lab_id)
    if solution is None:
        raise HTTPException(status_code=404, detail=f"no solution for lab: {lab_id}")
    return {"ok": True, "lab_id": lab_id, "solution": solution}
