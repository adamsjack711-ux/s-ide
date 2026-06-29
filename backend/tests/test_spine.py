"""End-to-end tests for the engagement-spine domain model + arm gate.

Walks the acceptance criteria over the real FastAPI app:

  1. A newly-declared sub-target is un-armed; running a tool against it is
     refused server-side with a clear message.
  2. Attaching an engagement arms the sub-target; the same tool now runs and its
     writes carry the engagement id.
  3. Detaching returns it to inert; running is refused again.
  4. One engagement arms two sub-targets; both run; each finding is tagged with
     the correct engagement × sub-target.
  5. A Target's findings view shows the union of its sub-targets' findings.
  6. A local-only engagement can arm localhost sub-targets and nothing outside
     its scope.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setenv("MHP_BACKEND_HOST", "127.0.0.1")
    from lib import auth as auth_mod
    monkeypatch.setattr(auth_mod, "AUTH_TOKEN", "testing-token")
    monkeypatch.setattr(
        auth_mod, "_LOOPBACK_HOSTS", auth_mod._LOOPBACK_HOSTS | {"testclient"},
    )
    from main import app
    return TestClient(app)


AUTH = {"X-MHP-Token": "testing-token"}


def _target(client, name, provenance="lab"):
    r = client.post("/spine/targets", headers=AUTH,
                    json={"name": name, "provenance": provenance})
    assert r.status_code == 200, r.text
    return r.json()


def _sub(client, tid, type, address, label=""):
    r = client.post(f"/spine/targets/{tid}/subtargets", headers=AUTH,
                    json={"type": type, "address": address, "label": label})
    assert r.status_code == 200, r.text
    return r.json()


def _engagement(client, name, scope=None, provenance="lab"):
    r = client.post("/engagements", headers=AUTH, json={
        "name": name, "scope": scope or [], "exclusions": [], "notes": "",
        "provenance": provenance,
    })
    assert r.status_code in (200, 201), r.text
    return r.json()


def test_unarmed_subtarget_run_refused(client):
    t = _target(client, "Lab box")
    s = _sub(client, t["id"], "service", "127.0.0.1:8765")
    assert s["armed"] is False
    r = client.post("/spine/run", headers=AUTH, json={"sub_target_id": s["id"]})
    assert r.status_code == 403, r.text
    # Clear, machine-readable refusal.
    body = r.json()
    detail = body.get("detail") if isinstance(body, dict) else None
    blob = str(body)
    assert "SUBTARGET_UNARMED" in blob or (isinstance(detail, dict) and detail.get("code") == "SUBTARGET_UNARMED")


def test_arm_runs_and_carries_engagement_id_then_disarm_refuses(client):
    t = _target(client, "Lab box")
    s = _sub(client, t["id"], "service", "127.0.0.1:8765")
    e = _engagement(client, "Pentest A")

    # Arm.
    r = client.post(f"/spine/subtargets/{s['id']}/arm", headers=AUTH,
                    json={"engagement_id": e["id"]})
    assert r.status_code == 200, r.text
    assert r.json()["sub_target"]["armed"] is True

    # Same tool now runs, and the run carries the arming engagement id.
    r = client.post("/spine/run", headers=AUTH, json={"sub_target_id": s["id"]})
    assert r.status_code == 200, r.text
    run = r.json()
    assert run["engagement_id"] == e["id"]
    assert run["status"] in ("completed", "error")

    # Detach → inert → refused again.
    r = client.post(f"/spine/subtargets/{s['id']}/disarm", headers=AUTH)
    assert r.status_code == 200 and r.json()["disarmed"] is True
    r = client.post("/spine/run", headers=AUTH, json={"sub_target_id": s["id"]})
    assert r.status_code == 403


def test_one_engagement_two_subtargets_findings_tagged_and_rolled_up(client):
    t = _target(client, "Lab box")
    s1 = _sub(client, t["id"], "service", "127.0.0.1:8765", "svc")
    s2 = _sub(client, t["id"], "host", "127.0.0.1", "host")
    e = _engagement(client, "Pentest B")
    for s in (s1, s2):
        r = client.post(f"/spine/subtargets/{s['id']}/arm", headers=AUTH,
                        json={"engagement_id": e["id"]})
        assert r.status_code == 200, r.text

    f1 = client.post("/spine/findings", headers=AUTH, json={
        "sub_target_id": s1["id"], "title": "F1", "severity": "high",
    }).json()
    f2 = client.post("/spine/findings", headers=AUTH, json={
        "sub_target_id": s2["id"], "title": "F2", "severity": "low",
    }).json()

    # Each finding tagged with the correct engagement × sub-target.
    assert f1["engagement_id"] == e["id"] and f1["sub_target_id"] == s1["id"]
    assert f2["engagement_id"] == e["id"] and f2["sub_target_id"] == s2["id"]
    assert f1["target_id"] == t["id"] and f2["target_id"] == t["id"]

    # Target roll-up = union across its sub-targets.
    roll = client.get(f"/spine/targets/{t['id']}/findings", headers=AUTH).json()
    titles = sorted(f["title"] for f in roll["findings"])
    assert titles == ["F1", "F2"]

    # Per-sub-target filter narrows correctly.
    only_s1 = client.get(f"/spine/findings?sub_target_id={s1['id']}", headers=AUTH).json()
    assert [f["title"] for f in only_s1["findings"]] == ["F1"]


def test_finding_on_unarmed_subtarget_refused(client):
    t = _target(client, "Lab box")
    s = _sub(client, t["id"], "host", "127.0.0.1")
    r = client.post("/spine/findings", headers=AUTH, json={
        "sub_target_id": s["id"], "title": "X", "severity": "low",
    })
    assert r.status_code == 403


def test_arm_conflict_when_already_armed_by_other_engagement(client):
    t = _target(client, "Lab box")
    s = _sub(client, t["id"], "host", "127.0.0.1")
    e1 = _engagement(client, "E1")
    e2 = _engagement(client, "E2")
    assert client.post(f"/spine/subtargets/{s['id']}/arm", headers=AUTH,
                       json={"engagement_id": e1["id"]}).status_code == 200
    # Second engagement on the same sub-target → 409 (detach first).
    r = client.post(f"/spine/subtargets/{s['id']}/arm", headers=AUTH,
                    json={"engagement_id": e2["id"]})
    assert r.status_code == 409
    # Same engagement is idempotent.
    assert client.post(f"/spine/subtargets/{s['id']}/arm", headers=AUTH,
                       json={"engagement_id": e1["id"]}).status_code == 200


def test_local_only_engagement_scope_boundary(client):
    """A local-only engagement arms localhost sub-targets and runs them, but
    cannot reach a sub-target outside its scope."""
    local = _engagement(client, "Local only", scope=["127.0.0.1", "localhost"],
                        provenance="lab")
    t = _target(client, "Mixed", provenance="external")
    loop = _sub(client, t["id"], "host", "127.0.0.1")
    ext = _sub(client, t["id"], "url", "https://example.com")

    # localhost armed by local-only engagement → runs.
    assert client.post(f"/spine/subtargets/{loop['id']}/arm", headers=AUTH,
                       json={"engagement_id": local["id"]}).status_code == 200
    r = client.post("/spine/run", headers=AUTH, json={"sub_target_id": loop["id"]})
    assert r.status_code == 200, r.text
    assert r.json()["engagement_id"] == local["id"]

    # external sub-target armed by the same local-only engagement → run refused
    # by scope (nothing outside the engagement's scope).
    assert client.post(f"/spine/subtargets/{ext['id']}/arm", headers=AUTH,
                       json={"engagement_id": local["id"]}).status_code == 200
    r = client.post("/spine/run", headers=AUTH, json={"sub_target_id": ext["id"]})
    assert r.status_code == 403, r.text
