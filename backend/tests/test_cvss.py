"""Unit tests for CVSS v3.1 base-score calculation (`lib/cvss.py`)."""
from __future__ import annotations

import pytest

from lib import cvss
from lib.errors import MhpError


REFERENCE_VECTORS: list[tuple[str, float, str]] = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8,  "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5,  "Medium"),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 2.4,  "Low"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2,  "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0,  "None"),
]


@pytest.mark.parametrize("vector,expected_score,expected_band", REFERENCE_VECTORS)
def test_reference_vector_round_trip(vector, expected_score, expected_band):
    metrics = cvss.parse_vector(vector)
    result = cvss.score_from_metrics(metrics)
    assert result["vector"] == vector
    assert result["base_score"] == expected_score
    assert result["severity"] == expected_band


def test_parse_vector_tolerates_metric_reorder():
    reordered = "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U"
    metrics = cvss.parse_vector(reordered)
    result = cvss.score_from_metrics(metrics)
    # Canonical output ordering regardless of input ordering.
    assert result["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert result["base_score"] == 9.8
    assert result["severity"] == "Critical"


def test_severity_bands_at_boundaries():
    # Boundary cases per CVSS 3.1 severity bands.
    assert cvss._severity(0.0) == "None"
    assert cvss._severity(0.1) == "Low"
    assert cvss._severity(3.9) == "Low"
    assert cvss._severity(4.0) == "Medium"
    assert cvss._severity(6.9) == "Medium"
    assert cvss._severity(7.0) == "High"
    assert cvss._severity(8.9) == "High"
    assert cvss._severity(9.0) == "Critical"
    assert cvss._severity(10.0) == "Critical"


# ── Invalid input ───────────────────────────────────────────────────────────

def test_score_from_metrics_rejects_unknown_metric_value():
    bad = {
        "AV": "Z", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    }
    with pytest.raises(MhpError):
        cvss.score_from_metrics(bad)


def test_score_from_metrics_rejects_missing_metric():
    bad = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H",
        # missing A
    }
    with pytest.raises(MhpError):
        cvss.score_from_metrics(bad)


def test_score_from_metrics_rejects_non_dict():
    with pytest.raises(MhpError):
        cvss.score_from_metrics("CVSS:3.1/AV:N")  # type: ignore[arg-type]


def test_score_from_metrics_rejects_non_string_value():
    bad = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": 1,
    }
    with pytest.raises(MhpError):
        cvss.score_from_metrics(bad)  # type: ignore[arg-type]


def test_parse_vector_rejects_v2():
    with pytest.raises(MhpError):
        cvss.parse_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")


def test_parse_vector_rejects_v4():
    with pytest.raises(MhpError):
        cvss.parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


def test_parse_vector_rejects_garbage():
    with pytest.raises(MhpError):
        cvss.parse_vector("not-a-cvss-vector")


def test_parse_vector_rejects_empty():
    with pytest.raises(MhpError):
        cvss.parse_vector("")


def test_parse_vector_rejects_unknown_metric_key():
    with pytest.raises(MhpError):
        cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y")


def test_parse_vector_rejects_duplicate_metric():
    with pytest.raises(MhpError):
        cvss.parse_vector("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_parse_vector_rejects_malformed_segment():
    with pytest.raises(MhpError):
        cvss.parse_vector("CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
