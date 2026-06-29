"""Typed engagement creation + encrypted auth secrets.

Covers the acceptance tests for the typed-create flow:
  * local-app requires a valid, readable directory (bad path → 400, no create)
  * web-app requires ≥1 valid URL; auth optional and, when given, encrypted
    and never echoed in plaintext anywhere (response / audit / secret meta)
  * created engagement exposes its source root / primary target as defaults
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lib import audit_log, engagement_secrets, engagements, targets as targets_lib


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


# ── local-app path validation ────────────────────────────────────────────────

def test_local_app_requires_existing_readable_dir(client, tmp_path):
    r = client.post("/engagements", headers=AUTH, json={
        "name": "Code review", "type": "local-app", "provenance": "owned",
        "source_root": str(tmp_path),
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "local-app"
    assert body["provenance"] == "owned"
    assert body["source_root"] == str(tmp_path.resolve())
    # source root is the engagement's default target for tools
    assert body["primary_target"] == str(tmp_path.resolve())


def test_local_app_bad_path_400_and_no_engagement(client):
    before = len(engagements.list_engagements(include_archived=True))
    r = client.post("/engagements", headers=AUTH, json={
        "name": "bad", "type": "local-app",
        "source_root": "/no/such/directory/anywhere",
    })
    assert r.status_code == 400
    assert "does not exist" in r.json().get("detail", "").lower() \
        or "does not exist" in r.text.lower()
    after = len(engagements.list_engagements(include_archived=True))
    assert after == before  # nothing created on a bad path


def test_local_app_file_is_not_a_directory(client, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    r = client.post("/engagements", headers=AUTH, json={
        "name": "f", "type": "local-app", "source_root": str(f),
    })
    assert r.status_code == 400


# ── web-app URL validation ────────────────────────────────────────────────────

def test_web_app_requires_a_valid_url(client):
    before = len(engagements.list_engagements(include_archived=True))
    r = client.post("/engagements", headers=AUTH, json={
        "name": "no urls", "type": "web-app", "targets": [],
    })
    assert r.status_code == 400
    assert len(engagements.list_engagements(include_archived=True)) == before


def test_web_app_rejects_malformed_url(client):
    r = client.post("/engagements", headers=AUTH, json={
        "name": "bad url", "type": "web-app", "targets": ["not a url"],
    })
    assert r.status_code == 400


def test_web_app_creates_primary_target_and_registers_it(client):
    r = client.post("/engagements", headers=AUTH, json={
        "name": "Web target", "type": "web-app", "provenance": "owned",
        "targets": ["https://app.example.com/login", "https://api.example.com"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["primary_target"] == "https://app.example.com/login"
    assert body["primary_target_id"]
    # declared target hosts folded into scope (strengthens engagement scope)
    assert "app.example.com" in body["scope"]
    # registered in the targets registry, bound to the engagement
    regd = targets_lib.list_targets(engagement_id=body["id"])
    addrs = {t["address"] for t in regd}
    assert "https://app.example.com/login" in addrs
    assert "https://api.example.com" in addrs


# ── Auth: encrypted at rest, redacted everywhere ──────────────────────────────

def test_web_app_auth_bearer_is_encrypted_and_redacted(client):
    secret = "supersecrettoken1234ABCD"
    r = client.post("/engagements", headers=AUTH, json={
        "name": "Auth eng", "type": "web-app",
        "targets": ["https://app.example.com"],
        "auth": {"kind": "bearer", "token": secret},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    eid = body["id"]

    # Response carries a redacted reference, never the secret.
    assert secret not in r.text
    assert body["auth"]["kind"] == "bearer"
    assert body["auth"]["last4"] == secret[-4:]
    assert "token" not in body["auth"]

    # The redacted meta endpoint also never leaks the secret.
    m = client.get(f"/engagements/{eid}/auth", headers=AUTH)
    assert m.status_code == 200
    assert secret not in m.text
    assert m.json()["auth"]["last4"] == secret[-4:]

    # Stored ciphertext is NOT the plaintext, but decrypts server-side.
    with engagements.cursor() as c:
        row = c.execute(
            "SELECT ciphertext FROM engagement_secrets WHERE engagement_id = ?",
            (eid,),
        ).fetchone()
    assert row is not None
    assert secret not in row["ciphertext"]
    assert engagement_secrets.get_auth(eid)["token"] == secret


def test_auth_secret_never_in_audit_log(client):
    secret = "cookieVALUE_zzz9999"
    r = client.post("/engagements", headers=AUTH, json={
        "name": "Audit redaction", "type": "web-app",
        "targets": ["https://app.example.com"],
        "auth": {"kind": "cookie", "cookie": f"session={secret}"},
    })
    assert r.status_code == 200, r.text
    blob = repr(audit_log.list_actions(limit=100))
    assert secret not in blob


def test_auth_optional_none_stores_nothing(client):
    r = client.post("/engagements", headers=AUTH, json={
        "name": "no auth", "type": "web-app",
        "targets": ["https://app.example.com"],
        "auth": {"kind": "none"},
    })
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    assert engagement_secrets.get_auth(eid) is None
    assert r.json()["auth"] is None


def test_credentials_redaction_shows_username_hides_password(client):
    r = client.post("/engagements", headers=AUTH, json={
        "name": "creds", "type": "web-app",
        "targets": ["https://app.example.com"],
        "auth": {"kind": "credentials", "username": "alice",
                 "password": "hunter2secret", "login_url": "https://app.example.com/login"},
    })
    assert r.status_code == 200, r.text
    assert "hunter2secret" not in r.text
    auth = r.json()["auth"]
    assert auth["kind"] == "credentials"
    assert auth["username"] == "alice"
    assert auth["has_secret"] is True
    assert "password" not in auth


# ── Quick-create path stays backward-compatible ───────────────────────────────

def test_generic_quick_create_unchanged(client):
    r = client.post("/engagements", headers=AUTH, json={"name": "quick"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "generic"
    assert body["provenance"] == "external"
    assert body["source_root"] == ""
    assert body["primary_target"] == ""
    assert body["primary_target_id"] is None
