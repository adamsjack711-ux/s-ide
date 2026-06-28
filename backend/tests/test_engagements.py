"""Unit tests for the SQLite engagement store (`lib/engagements.py`)."""
from __future__ import annotations

import pytest

from lib import engagements


def test_list_empty(temp_db):
    assert engagements.list_engagements() == []


def test_create_and_get_roundtrip(temp_db):
    e = engagements.create_engagement(
        name="ACME Q1",
        scope=["*.example.com", "10.0.0.0/24"],
        exclusions=["admin.example.com"],
        notes="kickoff: Mon",
    )
    assert e["name"] == "ACME Q1"
    assert e["scope"] == ["*.example.com", "10.0.0.0/24"]
    assert e["exclusions"] == ["admin.example.com"]
    assert e["notes"] == "kickoff: Mon"
    assert e["status"] == "active"
    assert e["created_at"] == e["updated_at"]

    got = engagements.get_engagement(e["id"])
    assert got == e


def test_list_excludes_archived_by_default(temp_db):
    e = engagements.create_engagement(name="alpha", scope=[], exclusions=[], notes="")
    engagements.create_engagement(name="bravo", scope=[], exclusions=[], notes="")
    engagements.update_engagement(e["id"], {"status": "archived"})

    active = engagements.list_engagements()
    assert {x["name"] for x in active} == {"bravo"}

    with_archived = engagements.list_engagements(include_archived=True)
    assert {x["name"] for x in with_archived} == {"alpha", "bravo"}


def test_update_engagement_patches_fields(temp_db):
    e = engagements.create_engagement(name="x", scope=[], exclusions=[], notes="")
    updated = engagements.update_engagement(e["id"], {
        "name": "renamed",
        "scope": ["foo.com"],
        "notes": "context",
    })
    assert updated is not None
    assert updated["name"] == "renamed"
    assert updated["scope"] == ["foo.com"]
    assert updated["notes"] == "context"
    assert updated["updated_at"] >= e["updated_at"]


def test_update_unknown_id_returns_none(temp_db):
    # update_engagement returns the row after patch; unknown id → no row.
    assert engagements.update_engagement("ghost", {"name": "y"}) is None


def test_delete_engagement_cascades_to_children(temp_db):
    e = engagements.create_engagement(name="x", scope=[], exclusions=[], notes="")
    engagements.record_result(
        engagement_id=e["id"], tool="ping", target="8.8.8.8",
        summary="ok", raw={"latency_ms": 12},
    )
    engagements.create_finding(
        engagement_id=e["id"], title="open ssh", severity="medium",
    )

    assert engagements.list_results(e["id"]) != []
    assert engagements.list_findings(e["id"]) != []

    engagements.delete_engagement(e["id"])
    assert engagements.get_engagement(e["id"]) is None
    # FK ON DELETE CASCADE — child rows are gone too.
    assert engagements.list_results(e["id"]) == []
    assert engagements.list_findings(e["id"]) == []


def test_record_result_persists_raw_as_json(temp_db):
    e = engagements.create_engagement(name="x", scope=[], exclusions=[], notes="")
    r = engagements.record_result(
        engagement_id=e["id"], tool="port_scanner", target="example.com",
        summary="3 open", raw={"ports": [22, 80, 443]},
    )
    listed = engagements.list_results(e["id"])
    assert len(listed) == 1
    assert listed[0]["id"] == r["id"]
    assert listed[0]["tool"] == "port_scanner"
    assert listed[0]["target"] == "example.com"
    full = engagements.get_result(r["id"])
    assert full is not None
    assert full["raw"] == {"ports": [22, 80, 443]}


def test_finding_severity_validation(temp_db):
    e = engagements.create_engagement(name="x", scope=[], exclusions=[], notes="")
    # Valid severities pass.
    for sev in ("info", "low", "medium", "high", "critical"):
        f = engagements.create_finding(
            engagement_id=e["id"], title="t", severity=sev,
        )
        assert f["severity"] == sev


def test_update_finding_changes_status(temp_db):
    e = engagements.create_engagement(name="x", scope=[], exclusions=[], notes="")
    f = engagements.create_finding(
        engagement_id=e["id"], title="t", severity="high",
    )
    assert f["status"] == "open"
    updated = engagements.update_finding(f["id"], {"status": "triaged"})
    assert updated is not None
    assert updated["status"] == "triaged"


def test_list_results_orders_newest_first(temp_db):
    import time

    e = engagements.create_engagement(name="x", scope=[], exclusions=[], notes="")
    r1 = engagements.record_result(
        engagement_id=e["id"], tool="ping", target="a", summary="", raw=None,
    )
    # The `ts` column uses second-precision strftime — sleep a tick so the
    # two rows get distinct timestamps for the ORDER BY.
    time.sleep(1.05)
    r2 = engagements.record_result(
        engagement_id=e["id"], tool="ping", target="b", summary="", raw=None,
    )
    listed = engagements.list_results(e["id"])
    assert [x["id"] for x in listed] == [r2["id"], r1["id"]]
