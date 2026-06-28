"""CVSS v3.1 base-score calculation and vector parsing.

Pure module — no FastAPI, no DB. Raises `MhpError` (VALIDATION_ERROR, 400)
on malformed metric input or unsupported vector strings.
"""
from __future__ import annotations

import math
from typing import Any

from lib.errors import ErrorCode, MhpError

# Canonical metric order for the vector string output.
_METRIC_ORDER: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_AV_WEIGHTS: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS: dict[str, float] = {"L": 0.77, "H": 0.44}
_UI_WEIGHTS: dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.00}
_PR_WEIGHTS_UNCHANGED: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_S_VALUES: frozenset[str] = frozenset({"U", "C"})

_ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "AV": frozenset(_AV_WEIGHTS),
    "AC": frozenset(_AC_WEIGHTS),
    "PR": frozenset(_PR_WEIGHTS_UNCHANGED),  # same key set as changed
    "UI": frozenset(_UI_WEIGHTS),
    "S":  _S_VALUES,
    "C":  frozenset(_CIA_WEIGHTS),
    "I":  frozenset(_CIA_WEIGHTS),
    "A":  frozenset(_CIA_WEIGHTS),
}


def _roundup(x: float) -> float:
    int_input = round(x * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10


def _severity(score: float) -> str:
    if score <= 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def _validate_metrics(metrics: dict[str, str]) -> dict[str, str]:
    if not isinstance(metrics, dict):
        raise MhpError(
            "metrics must be a dict",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    cleaned: dict[str, str] = {}
    for key in _METRIC_ORDER:
        if key not in metrics:
            raise MhpError(
                f"missing CVSS metric: {key}",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        val = metrics[key]
        if not isinstance(val, str):
            raise MhpError(
                f"CVSS metric {key} must be a string",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        allowed = _ALLOWED_VALUES[key]
        if val not in allowed:
            raise MhpError(
                f"invalid value {val!r} for CVSS metric {key}; expected one of "
                f"{sorted(allowed)}",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        cleaned[key] = val
    return cleaned


def score_from_metrics(metrics: dict[str, str]) -> dict[str, Any]:
    m = _validate_metrics(metrics)

    av = _AV_WEIGHTS[m["AV"]]
    ac = _AC_WEIGHTS[m["AC"]]
    ui = _UI_WEIGHTS[m["UI"]]
    scope = m["S"]
    pr = (_PR_WEIGHTS_UNCHANGED if scope == "U" else _PR_WEIGHTS_CHANGED)[m["PR"]]
    c = _CIA_WEIGHTS[m["C"]]
    i = _CIA_WEIGHTS[m["I"]]
    a = _CIA_WEIGHTS[m["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    vector = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _METRIC_ORDER)

    return {
        "base_score": base_score,
        "severity": _severity(base_score),
        "vector": vector,
    }


def parse_vector(vector_string: str) -> dict[str, str]:
    if not isinstance(vector_string, str):
        raise MhpError(
            "CVSS vector must be a string",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    s = vector_string.strip()
    if not s:
        raise MhpError(
            "empty CVSS vector",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    parts = s.split("/")
    if len(parts) < 2:
        raise MhpError(
            "malformed CVSS vector",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    header = parts[0]
    if header == "CVSS:2.0":
        raise MhpError(
            "CVSS v2 vectors are not supported; expected CVSS:3.1",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    if header == "CVSS:4.0":
        raise MhpError(
            "CVSS v4 vectors are not supported; expected CVSS:3.1",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    if header != "CVSS:3.1":
        raise MhpError(
            f"unsupported CVSS version header {header!r}; expected CVSS:3.1",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )

    metrics: dict[str, str] = {}
    for chunk in parts[1:]:
        if ":" not in chunk:
            raise MhpError(
                f"malformed CVSS metric segment: {chunk!r}",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        key, _, val = chunk.partition(":")
        if not key or not val:
            raise MhpError(
                f"malformed CVSS metric segment: {chunk!r}",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        if key in metrics:
            raise MhpError(
                f"duplicate CVSS metric: {key}",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        if key not in _ALLOWED_VALUES:
            raise MhpError(
                f"unknown CVSS metric: {key}",
                code=ErrorCode.VALIDATION_ERROR,
                status_code=400,
            )
        metrics[key] = val

    # _validate_metrics enforces required-key presence + allowed values.
    return _validate_metrics(metrics)
