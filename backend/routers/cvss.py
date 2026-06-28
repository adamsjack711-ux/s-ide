"""Stateless CVSS v3.1 scoring endpoint.

`GET /cvss/calculate` powers the live calculator UI — accepts either an
explicit vector string in `?vector=` or per-metric query params
(`?AV=N&AC=L&PR=N&UI=N&S=U&C=H&I=H&A=H`). Returns the canonical vector,
the base score, and the severity band. No engagement context, no DB
writes, no audit row — the in-finding scoring action lives at
`POST /findings/{fid}/cvss` in the findings router.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from lib import cvss as cvss_lib
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError

router = APIRouter(prefix="/cvss", tags=["cvss"],
                   dependencies=[Depends(require_local_auth)])


_METRIC_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


@router.get("/calculate")
def calculate(
    vector: str | None = Query(default=None, max_length=200),
    AV: str | None = Query(default=None, max_length=2),
    AC: str | None = Query(default=None, max_length=2),
    PR: str | None = Query(default=None, max_length=2),
    UI: str | None = Query(default=None, max_length=2),
    S:  str | None = Query(default=None, max_length=2),
    C:  str | None = Query(default=None, max_length=2),
    I:  str | None = Query(default=None, max_length=2),
    A:  str | None = Query(default=None, max_length=2),
) -> dict[str, Any]:
    if vector:
        metrics = cvss_lib.parse_vector(vector)
    else:
        params = {"AV": AV, "AC": AC, "PR": PR, "UI": UI,
                  "S": S, "C": C, "I": I, "A": A}
        missing = [k for k in _METRIC_KEYS if not params.get(k)]
        if missing:
            raise MhpError(
                f"missing required metrics: {', '.join(missing)}",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        metrics = {k: params[k] for k in _METRIC_KEYS}  # type: ignore[misc]
    return cvss_lib.score_from_metrics(metrics)
