"""Audit-logging tests for the Lateral Movement Planner (``/lateral``).

LateralMove was the one attack-family tool that touched engagement data
(an uploaded BloodHound dump) without writing to the append-only audit
log. Its six peers (ad_spray, s3_scanner, kerberoast, …) all log
start/complete/error; these tests pin the same contract for ``/load`` and
``/path`` so the "every action is auditable" story holds for AD analysis
too.

The graph is process-global in the router, so each test loads its own
fixture; ``temp_db`` gives every test a fresh audit log.
"""
from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from lib import audit_log, engagements


AUTH = {"X-MHP-Token": "testing-token"}

# A two-node BloodHound graph: ALICE is a member of DOMAIN ADMINS, so the
# default-target path query (any Domain Admins-like group) finds one hop.
_ALICE_SID = "S-1-5-21-1-1-1-1001"
_DA_SID = "S-1-5-21-1-1-1-512"
_USERS = {
    "data": [{
        "ObjectIdentifier": _ALICE_SID,
        "Properties": {"name": "ALICE@CORP.LOCAL", "objectid": _ALICE_SID},
        "PrimaryGroupSid": [_DA_SID],
    }],
}
_GROUPS = {
    "data": [{
        "ObjectIdentifier": _DA_SID,
        "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "objectid": _DA_SID},
        "Members": [],
    }],
}


@pytest.fixture
def client(temp_db, monkeypatch):
    """Real ASGI app with a pinned auth token and temp DB.

    Mirrors ``test_labs_attach.client`` so this file is independent of the
    smoke-test fixture wiring.
    """
    monkeypatch.setenv("MHP_BACKEND_HOST", "127.0.0.1")
    from lib import auth as auth_mod
    monkeypatch.setattr(auth_mod, "AUTH_TOKEN", "testing-token")
    monkeypatch.setattr(
        auth_mod, "_LOOPBACK_HOSTS",
        auth_mod._LOOPBACK_HOSTS | {"testclient"},
    )
    from main import app
    return TestClient(app)


def _bloodhound_zip() -> bytes:
    """Pack the users+groups fixtures into a SharpHound-style ZIP."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("20240101_corp_users.json", json.dumps(_USERS))
        zf.writestr("20240101_corp_groups.json", json.dumps(_GROUPS))
    return buf.getvalue()


def _engagement() -> str:
    eng = engagements.create_engagement(
        name="Lateral Eng", scope=["corp.local"], exclusions=[], notes="",
    )
    return eng["id"]


def _eng_headers(eng_id: str) -> dict[str, str]:
    # Supplying the engagement id puts the request in Engagement mode (see
    # lib/mode.py) so the audit row binds to the engagement.
    return {**AUTH, "X-MHP-Engagement-Id": eng_id}


# ── /load ─────────────────────────────────────────────────────────────────────


def test_load_writes_completed_audit_row(client):
    eng_id = _engagement()
    r = client.post(
        "/lateral/load",
        headers=_eng_headers(eng_id),
        files={"file": ("dump.zip", _bloodhound_zip(), "application/zip")},
        data={"confirm_auth": "true"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["stats"]["nodes"] == 2

    actions = audit_log.list_actions(engagement_id=eng_id, tool="lateral")
    loads = [a for a in actions if "load" in a["argv"]]
    assert len(loads) == 1, actions
    assert loads[0]["status"] == "completed"
    assert loads[0]["engagement_id"] == eng_id
    # Summary captures what was ingested.
    assert "nodes" in (loads[0]["summary"] or "")


def test_load_failure_writes_error_audit_row(client):
    eng_id = _engagement()
    # Valid JSON but an unclassifiable filename → the endpoint 400s *after*
    # the audit row is opened, so the failure must be recorded, not orphaned.
    r = client.post(
        "/lateral/load",
        headers=_eng_headers(eng_id),
        files={"file": ("mystery.json", json.dumps({"data": []}), "application/json")},
        data={"confirm_auth": "true"},
    )
    assert r.status_code == 400, r.text

    actions = audit_log.list_actions(engagement_id=eng_id, tool="lateral")
    assert len(actions) == 1, actions
    assert actions[0]["status"] == "error"
    assert actions[0]["error"]


def test_load_without_auth_writes_no_audit_row(client):
    # The confirm_auth gate fires before the audit row is opened, so a
    # missing-authorization attempt leaves the log clean.
    eng_id = _engagement()
    r = client.post(
        "/lateral/load",
        headers=_eng_headers(eng_id),
        files={"file": ("dump.zip", _bloodhound_zip(), "application/zip")},
        data={"confirm_auth": "false"},
    )
    assert r.status_code == 403, r.text
    assert audit_log.list_actions(engagement_id=eng_id, tool="lateral") == []


# ── /path ─────────────────────────────────────────────────────────────────────


def test_path_writes_completed_audit_row(client):
    eng_id = _engagement()
    load = client.post(
        "/lateral/load",
        headers=_eng_headers(eng_id),
        files={"file": ("dump.zip", _bloodhound_zip(), "application/zip")},
        data={"confirm_auth": "true"},
    )
    assert load.status_code == 200, load.text

    r = client.post(
        "/lateral/path",
        headers=_eng_headers(eng_id),
        json={"source": "ALICE@CORP.LOCAL", "confirm_auth": True},
    )
    assert r.status_code == 200, r.text
    assert len(r.json()["paths"]) == 1  # ALICE → DOMAIN ADMINS

    actions = audit_log.list_actions(engagement_id=eng_id, tool="lateral")
    paths = [a for a in actions if "path" in a["argv"]]
    assert len(paths) == 1, actions
    assert paths[0]["status"] == "completed"
    assert "path" in (paths[0]["summary"] or "")
