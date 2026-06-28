"""Unit tests for `lib/audit_log.py` — the append-only action log."""
from __future__ import annotations

import pytest

from lib import audit_log, engagements


def test_start_returns_id_and_persists(temp_db):
    aid = audit_log.start(
        tool="port_scanner",
        target="example.com",
        argv=["nmap", "-sT", "example.com"],
        engagement_id=None,
    )
    assert isinstance(aid, str) and len(aid) >= 16

    row = audit_log.get_action(aid)
    assert row is not None
    assert row["tool"] == "port_scanner"
    assert row["target"] == "example.com"
    assert row["argv"] == ["nmap", "-sT", "example.com"]
    assert row["status"] == "started"
    assert row["ts_end"] is None
    # No engagement → mode defaults to "lab".
    assert row["mode"] == "lab"


def test_start_with_engagement_defaults_to_engagement_mode(temp_db):
    e = engagements.create_engagement(name="x", scope=[], exclusions=[], notes="")
    aid = audit_log.start(tool="dns", target="example.com",
                           engagement_id=e["id"])
    assert audit_log.get_action(aid)["mode"] == "engagement"


def test_complete_marks_status_and_summary(temp_db):
    aid = audit_log.start(tool="dns", target="example.com")
    audit_log.complete(aid, summary="42 records returned")

    row = audit_log.get_action(aid)
    assert row["status"] == "completed"
    assert row["ts_end"] is not None
    assert row["summary"] == "42 records returned"


def test_error_marks_status_and_message(temp_db):
    aid = audit_log.start(tool="dns", target="example.com")
    audit_log.error(aid, "NXDOMAIN", summary="lookup failed")

    row = audit_log.get_action(aid)
    assert row["status"] == "error"
    assert row["error"] == "NXDOMAIN"
    assert row["summary"] == "lookup failed"


def test_complete_is_no_op_for_unknown_id(temp_db):
    """Idempotent — must not raise if the id was never started or already finalised."""
    audit_log.complete("does-not-exist", summary="")  # no exception


def test_complete_does_not_reopen_completed_row(temp_db):
    """Append-only contract: completing the same id twice doesn't overwrite."""
    aid = audit_log.start(tool="dns", target="example.com")
    audit_log.complete(aid, summary="first")
    audit_log.complete(aid, summary="second")  # ignored — WHERE status='started'

    row = audit_log.get_action(aid)
    assert row["summary"] == "first"


def test_action_context_manager_records_completion(temp_db):
    with audit_log.action(tool="dns", target="example.com") as a:
        a.summary = "ok"

    rows = audit_log.list_actions(tool="dns")
    assert len(rows) == 1
    assert rows[0]["status"] == "completed"
    assert rows[0]["summary"] == "ok"


def test_action_context_manager_records_error_on_raise(temp_db):
    with pytest.raises(RuntimeError):
        with audit_log.action(tool="dns", target="example.com"):
            raise RuntimeError("simulated failure")

    rows = audit_log.list_actions(tool="dns")
    assert len(rows) == 1
    assert rows[0]["status"] == "error"
    assert "RuntimeError" in rows[0]["error"]


def test_action_context_manager_records_stopped(temp_db):
    with audit_log.action(tool="port_scan", target="example.com") as a:
        a.summary = "user clicked Stop"
        a.mark_stopped()

    rows = audit_log.list_actions(tool="port_scan")
    assert rows[0]["status"] == "stopped"


def test_list_actions_filter_by_engagement(temp_db):
    e1 = engagements.create_engagement(name="a", scope=[], exclusions=[], notes="")
    e2 = engagements.create_engagement(name="b", scope=[], exclusions=[], notes="")
    audit_log.start(tool="x", target="t", engagement_id=e1["id"])
    audit_log.start(tool="x", target="t", engagement_id=e2["id"])
    audit_log.start(tool="x", target="t", engagement_id=None)

    only_e1 = audit_log.list_actions(engagement_id=e1["id"])
    assert len(only_e1) == 1
    assert only_e1[0]["engagement_id"] == e1["id"]


def test_list_actions_filter_by_status(temp_db):
    a1 = audit_log.start(tool="x", target="t")
    audit_log.complete(a1)
    audit_log.start(tool="x", target="t")  # leave as 'started'

    completed = audit_log.list_actions(status="completed")
    started   = audit_log.list_actions(status="started")
    assert len(completed) == 1
    assert len(started) == 1


def test_list_actions_invalid_status_filter_is_ignored(temp_db):
    """`status` is whitelisted to known values — anything else returns all rows."""
    audit_log.start(tool="x", target="t")
    audit_log.start(tool="x", target="t")
    rows = audit_log.list_actions(status="bogus")
    assert len(rows) == 2


def test_tool_counts_aggregates_by_tool_and_status(temp_db):
    a1 = audit_log.start(tool="dns", target="t")
    audit_log.complete(a1)
    a2 = audit_log.start(tool="dns", target="t")
    audit_log.error(a2, "boom")
    audit_log.start(tool="nmap", target="t")  # leave started

    counts = {c["tool"]: c for c in audit_log.tool_counts()}
    assert counts["dns"]["completed"] == 1
    assert counts["dns"]["error"]     == 1
    assert counts["dns"]["total"]     == 2
    assert counts["nmap"]["started"]  == 1
    assert counts["nmap"]["total"]    == 1
