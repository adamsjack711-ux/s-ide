"""Tests for the engagement coverage matrix (lib/coverage + the endpoint).

Coverage is a read-only projection over audit_log / scan_results / findings,
so each test seeds those real tables (via the same libs the app uses) and
asserts the matrix reflects them. Tool naming is deliberately varied across
seeds to pin the alias-matching that handles the app's heterogeneous names.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lib import audit_log, coverage, engagements


AUTH = {"X-MHP-Token": "testing-token"}


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setenv("MHP_BACKEND_HOST", "127.0.0.1")
    from lib import auth as auth_mod
    monkeypatch.setattr(auth_mod, "AUTH_TOKEN", "testing-token")
    monkeypatch.setattr(
        auth_mod, "_LOOPBACK_HOSTS",
        auth_mod._LOOPBACK_HOSTS | {"testclient"},
    )
    from main import app
    return TestClient(app)


def _eng() -> str:
    return engagements.create_engagement(
        name="Cov Eng", scope=["example.com"], exclusions=[], notes="",
    )["id"]


def _ran(eid: str, tool: str, target: str = "example.com") -> None:
    """Record a completed audit-log run, the way a gated tool would."""
    aid = audit_log.start(tool=tool, target=target, engagement_id=eid)
    audit_log.complete(aid, summary="ok")


def _area(cov: dict, key: str) -> dict:
    return next(a for a in cov["areas"] if a["key"] == key)


def test_fresh_engagement_has_no_coverage(temp_db):
    cov = coverage.compute_coverage(_eng())
    assert cov["total"] == 6
    assert cov["covered_count"] == 0
    assert {a["key"] for a in cov["areas"]} == {
        "dns", "tls", "headers", "services", "findings", "report",
    }
    assert all(a["covered"] is False for a in cov["areas"])


def test_audit_runs_light_up_recon_areas(temp_db):
    eid = _eng()
    # Heterogeneous names: adapter-style and router-style both map to areas.
    _ran(eid, "dns_recon")
    _ran(eid, "tls_audit")
    _ran(eid, "port_scanner")
    cov = coverage.compute_coverage(eid)
    assert _area(cov, "dns")["covered"] is True
    assert _area(cov, "tls")["covered"] is True
    assert _area(cov, "services")["covered"] is True
    assert _area(cov, "headers")["covered"] is False
    assert cov["covered_count"] == 3


def test_scan_results_also_count_and_runs_accumulate(temp_db):
    eid = _eng()
    _ran(eid, "dns")                       # audit-log alias for DNS
    engagements.record_result(             # results-timeline row, same area
        engagement_id=eid, tool="whois", target="example.com",
        summary="registrar=…", raw="{}",
    )
    dns = _area(coverage.compute_coverage(eid), "dns")
    assert dns["covered"] is True
    assert dns["runs"] == 2
    assert set(dns["tools_seen"]) == {"dns", "whois"}


def test_findings_and_report_areas(temp_db):
    eid = _eng()
    assert _area(coverage.compute_coverage(eid), "findings")["covered"] is False

    engagements.create_finding(
        engagement_id=eid, title="open redirect", severity="medium",
        tool="http_probe", target="example.com",
    )
    # report-export logs tool="report-export", which normalizes to report_export.
    _ran(eid, "report-export", target="Cov Eng")

    cov = coverage.compute_coverage(eid)
    assert _area(cov, "findings")["covered"] is True
    assert _area(cov, "findings")["runs"] == 1
    assert _area(cov, "report")["covered"] is True
    # Recon areas reflect actual runs (audit log + results timeline), not a
    # finding's stored tool — promoting a finding isn't a "header check ran".
    assert _area(cov, "headers")["covered"] is False


def test_unrelated_tool_buckets_nowhere(temp_db):
    # A tool name in none of the alias sets must not falsely cover an area.
    eid = _eng()
    _ran(eid, "stego")
    cov = coverage.compute_coverage(eid)
    assert cov["covered_count"] == 0


def test_endpoint_returns_matrix(client):
    eid = _eng()
    _ran(eid, "tls_audit")
    r = client.get(f"/engagements/{eid}/coverage", headers=AUTH)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["engagement_id"] == eid
    assert body["covered_count"] == 1
    assert next(a for a in body["areas"] if a["key"] == "tls")["covered"] is True


def test_endpoint_404_for_unknown_engagement(client):
    r = client.get("/engagements/ghost/coverage", headers=AUTH)
    assert r.status_code == 404, r.text
