"""Smoke + integration tests for ``POST /labs/{lab_id}/attach``.

The attach endpoint binds a running lab to an engagement: it upserts an
engagement-scoped ``targets`` row per published port AND appends the lab's
primary URL to the engagement's ``scope`` list. The report header reads
scope, so the lab URL surfaces in the export without any extra wiring.

Docker isn't reachable from the test env, so ``labs_lib.get_status`` is
monkey-patched to report the lab as running. Everything *downstream* of
that liveness check is real code — real engagements DB, real targets
upserts, real audit log writes — so the test exercises the contract end
to end.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lib import audit_log, engagements, labs as labs_lib, targets as targets_lib


AUTH = {"X-MHP-Token": "testing-token"}


@pytest.fixture
def client(temp_db, monkeypatch):
    """Real ASGI app with a pinned auth token and temp DB.

    Mirrors ``test_api_integration.client`` so the test file is independent
    of the smoke-test fixture wiring.
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


@pytest.fixture
def juice_shop_running(monkeypatch):
    """Pretend Juice Shop's container is up.

    The attach endpoint calls ``labs_lib.get_status`` to confirm liveness
    before mutating state. We replace it with a coroutine that returns the
    shape the endpoint reads from, scoped to the juice-shop lab def so the
    port/URL detail in the response still comes from the real registry.
    """
    lab = labs_lib.get_lab_def("juice-shop")
    assert lab is not None, "juice-shop missing from labs registry"

    async def _fake_status(lab_id: str):
        if lab_id != "juice-shop":
            raise RuntimeError(f"unexpected lab_id in test stub: {lab_id}")
        return {
            "lab":              {"id": lab.id, "name": lab.name},
            "docker_running":   True,
            "image_exists":     True,
            "container":        {"state": "running", "status": "Up 1 minute",
                                 "started_at": None, "exit_code": None},
            "build_status":     "built",
            "build_error":      None,
            "build_started_at": None,
            "build_finished_at": None,
            "build_log_tail":   [],
        }

    monkeypatch.setattr(labs_lib, "get_status", _fake_status)
    return lab


# ── happy path ──────────────────────────────────────────────────────────────


def test_attach_lab_writes_scope_and_target(client, juice_shop_running):
    """One round-trip should:
        * append the lab's primary URL to engagement.scope
        * insert an engagement-scoped targets row
        * leave the global pool (engagement_id IS NULL) untouched
        * write a `lab-attach` audit row tied to the engagement
    """
    eng = engagements.create_engagement(
        name="Smoke Eng",
        scope=["existing.example.com"],
        exclusions=[],
        notes="",
    )

    r = client.post(
        f"/labs/{juice_shop_running.id}/attach",
        headers=AUTH,
        json={"engagement_id": eng["id"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["attached"] is True
    assert body["lab_id"] == juice_shop_running.id
    assert body["engagement_id"] == eng["id"]
    assert body["targets_added"] == 1, body  # juice-shop publishes one port
    assert body["scope_entries_added"] == 1, body
    assert body["scope_entry"] == juice_shop_running.primary_url

    # Engagement scope was patched.
    after = engagements.get_engagement(eng["id"])
    assert after is not None
    assert juice_shop_running.primary_url in after["scope"]
    assert "existing.example.com" in after["scope"]  # original entries preserved

    # Engagement-bound target exists.
    bound = targets_lib.list_targets(engagement_id=eng["id"], kind="lab")
    assert len(bound) == 1, bound
    assert bound[0]["engagement_id"] == eng["id"]
    assert bound[0]["source_meta"]["lab_id"] == juice_shop_running.id

    # Global pool unaffected — engagement-scoped attach is a parallel copy,
    # not a move, so the auto-register hook's global rows stay where they are.
    globals_ = [t for t in targets_lib.list_targets(kind="lab")
                if t["engagement_id"] is None
                and t["source_meta"].get("lab_id") == juice_shop_running.id]
    assert globals_ == []  # nothing was auto-registered in this test setup

    # Audit row landed and is complete.
    actions = audit_log.list_actions(engagement_id=eng["id"], tool="lab-attach")
    assert len(actions) == 1
    assert actions[0]["status"] == "completed"
    assert actions[0]["target"] == juice_shop_running.id


# ── idempotency ─────────────────────────────────────────────────────────────


def test_attach_lab_is_idempotent(client, juice_shop_running):
    """Second attach for the same (lab, engagement) must not duplicate state."""
    eng = engagements.create_engagement(
        name="Idempotent Eng", scope=[], exclusions=[], notes="",
    )

    first = client.post(
        f"/labs/{juice_shop_running.id}/attach",
        headers=AUTH, json={"engagement_id": eng["id"]},
    ).json()
    second = client.post(
        f"/labs/{juice_shop_running.id}/attach",
        headers=AUTH, json={"engagement_id": eng["id"]},
    ).json()

    assert first["targets_added"] == 1
    assert first["scope_entries_added"] == 1
    assert second["targets_added"] == 0, second
    assert second["scope_entries_added"] == 0, second

    after = engagements.get_engagement(eng["id"])
    assert after is not None
    assert after["scope"].count(juice_shop_running.primary_url) == 1
    bound = targets_lib.list_targets(engagement_id=eng["id"], kind="lab")
    assert len(bound) == 1


# ── error envelope ──────────────────────────────────────────────────────────


def test_attach_unknown_lab_returns_404(client):
    r = client.post(
        "/labs/does-not-exist/attach",
        headers=AUTH, json={"engagement_id": "anything"},
    )
    assert r.status_code == 404
    assert r.json()["code"] == "NOT_FOUND"


def test_attach_unknown_engagement_returns_404(client, juice_shop_running):
    r = client.post(
        f"/labs/{juice_shop_running.id}/attach",
        headers=AUTH, json={"engagement_id": "ghost-engagement"},
    )
    assert r.status_code == 404
    body = r.json()
    assert body["code"] == "NOT_FOUND"
    assert body["engagement_id"] == "ghost-engagement"


def test_attach_when_lab_not_running_returns_409(client, monkeypatch):
    """Lab status reports `exited`. Attach must refuse before mutating state."""
    lab = labs_lib.get_lab_def("juice-shop")
    assert lab is not None

    async def _fake_status(lab_id: str):
        return {
            "container": {"state": "exited", "status": "Exited (0)",
                          "started_at": None, "exit_code": 0},
        }
    monkeypatch.setattr(labs_lib, "get_status", _fake_status)

    eng = engagements.create_engagement(
        name="Stopped Eng", scope=[], exclusions=[], notes="",
    )

    r = client.post(
        f"/labs/{lab.id}/attach",
        headers=AUTH, json={"engagement_id": eng["id"]},
    )
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "CONFLICT"

    # Nothing was written.
    after = engagements.get_engagement(eng["id"])
    assert after is not None
    assert lab.primary_url not in after["scope"]
    assert targets_lib.list_targets(engagement_id=eng["id"], kind="lab") == []
