"""End-to-end integration via FastAPI's TestClient.

These tests run the real ASGI app — they exercise the full request
pipeline (auth dep, header parsing, scope check, router handler)
without booting uvicorn.

Network-touching code paths are intentionally not exercised here; we
test the *gating* (deny in Engagement mode without an engagement, allow
in Lab mode, etc.) so the assertion targets the response status before
any outbound request happens.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lib import engagements


@pytest.fixture
def client(temp_db, monkeypatch):
    """Boot the real app against the temp DB, with a known auth token."""
    monkeypatch.setenv("MHP_BACKEND_HOST", "127.0.0.1")
    # Force a deterministic auth token so we don't have to fetch /auth/token.
    from lib import auth as auth_mod
    monkeypatch.setattr(auth_mod, "AUTH_TOKEN", "testing-token")
    # TestClient reports `client.host == "testclient"`, which the loopback
    # guard would reject. Treat it as loopback for the test process only.
    monkeypatch.setattr(
        auth_mod, "_LOOPBACK_HOSTS",
        auth_mod._LOOPBACK_HOSTS | {"testclient"},
    )

    from main import app
    return TestClient(app)


AUTH = {"X-MHP-Token": "testing-token"}


# ── auth + health ───────────────────────────────────────────────────────────

def test_health_open_no_auth(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_auth_gated_endpoint_rejects_missing_token(client):
    """Tool endpoints carrying `require_local_auth` reject requests without
    the `X-MHP-Token` header. `/whois/...` is the cheapest example —
    `/engagements` is intentionally open to localhost callers."""
    r = client.get("/whois/example.com")
    assert r.status_code == 403


# ── engagements CRUD via the API ────────────────────────────────────────────

def test_engagements_crud_roundtrip(client):
    r = client.post("/engagements", headers=AUTH, json={
        "name": "ACME Q1",
        "scope": ["*.example.com"],
        "exclusions": ["admin.example.com"],
        "notes": "",
    })
    assert r.status_code == 200, r.text
    eid = r.json()["id"]

    listed = client.get("/engagements", headers=AUTH).json()
    assert any(e["id"] == eid for e in listed["engagements"])

    patched = client.patch(f"/engagements/{eid}", headers=AUTH,
                           json={"name": "ACME Q1 — external"}).json()
    assert patched["name"] == "ACME Q1 — external"

    client.delete(f"/engagements/{eid}", headers=AUTH)
    assert client.get(f"/engagements/{eid}", headers=AUTH).status_code == 404


# ── scope gating in the live request pipeline ───────────────────────────────

def test_scope_denied_with_stale_engagement_id(client, permissive_policy):
    """A stale engagement_id puts the request in Engagement mode (mode is
    derived from id presence per `lib/mode.py`) and the scope layer must
    refuse the lookup. `permissive_policy` holds the policy layer at
    warn-on-external so this test exercises the *scope* deny path rather
    than tripping the default deny-external-by-default policy first."""
    r = client.get("/ct/search/example.com", headers={
        **AUTH, "X-MHP-Engagement-Id": "ghost",
    })
    assert r.status_code == 403
    body = r.json()
    assert body["code"] == "TARGET_DENIED"
    # Verify the scope layer is what fired (not policy), so this test really
    # exercises engagement-mode gating rather than the deny-external safety net.
    assert body["layers"]["scope"].startswith("deny:"), body["layers"]
    assert "not found" in body["layers"]["scope"].lower()


def test_scope_allowed_in_engagement_mode_when_target_in_scope(
    client, temp_db, permissive_policy,
):
    """In-scope target should pass the scope check. External targets still
    trip the target_policy 'warn' layer (RFC1918 / loopback guard), so we
    pass `confirm=true` to acknowledge that and isolate the scope gate.
    permissive_policy holds the policy layer at the older warn-on-external
    semantic so the test exercises the scope check rather than tripping the
    config's deny-external-by-default safety net.
    Downstream call may fail on network — we accept anything *but* 403/409."""
    eng = engagements.create_engagement(
        name="acme", scope=["example.com"], exclusions=[], notes="",
    )
    r = client.get("/ct/search/example.com?confirm=true", headers={
        **AUTH, "X-MHP-Engagement-Id": eng["id"],
    })
    assert r.status_code not in (403, 409), \
        f"expected scope to allow; got {r.status_code}: {r.text[:200]}"


def test_scope_blocks_out_of_scope_target(client, temp_db, permissive_policy):
    """`permissive_policy` keeps the policy layer at warn-on-external so the
    test isolates the *scope* layer's verdict (otherwise `attacker.com`
    would be denied by the default deny-external-by-default policy first
    and we'd never know if the scope check actually fired)."""
    eng = engagements.create_engagement(
        name="acme", scope=["example.com"], exclusions=[], notes="",
    )
    r = client.get("/ct/search/attacker.com", headers={
        **AUTH, "X-MHP-Engagement-Id": eng["id"],
    })
    assert r.status_code == 403
    body = r.json()
    assert body["code"] == "TARGET_DENIED"
    assert body["layers"]["scope"].startswith("deny:"), body["layers"]


def test_scope_exclusion_blocks_even_inside_scope(client, temp_db, permissive_policy):
    """Like the out-of-scope test above, `permissive_policy` is required so the
    policy layer doesn't pre-empt scope and mask whether exclusions actually
    fire."""
    eng = engagements.create_engagement(
        name="acme",
        scope=["example.com"],
        exclusions=["admin.example.com"],
        notes="",
    )
    r = client.get("/ct/search/admin.example.com", headers={
        **AUTH, "X-MHP-Engagement-Id": eng["id"],
    })
    assert r.status_code == 403
    body = r.json()
    assert body["layers"]["scope"].startswith("deny:"), body["layers"]
    assert "exclusion" in body["layers"]["scope"].lower() or \
           "admin.example.com" in body["layers"]["scope"]


# ── engagement-present gates on non-target tools ────────────────────────────
#
# Routers wired with `scope.enforce_engagement_present` (no concrete network
# target, but active actions that must attach to an engagement record).
#
# Mode is derived from the presence of an engagement_id (see lib/mode.py)
# since the security tightening — the X-MHP-Mode header is ignored to
# remove the mode-spoof gap. So the only way to construct
# "engagement mode without a real engagement" is to send a stale id, which
# the gate must still reject. This test exercises that path; the gate fires
# before any platform check in every wired router, so the parametrized cases
# pass regardless of host OS.

# Each case names the router *module key* (see lib/exposure.py) it lives
# behind. The capability re-scope dropped several of these routers from the
# exposed set, so their routes now 404 rather than reaching the gate. We derive
# the expectation from `exposure.is_exposed(...)` so an exposed router asserts
# the 403 gate verdict while an unexposed one asserts the 404 — and the test
# self-corrects if the exposed set changes again.
@pytest.mark.parametrize("method,path,body,key", [
    # Active actions on the first wave (network-target-ish tools).
    ("POST", "/shodan-censys/query", {"service": "shodan", "query": "test"}, "shodan_censys"),
    ("POST", "/terminal/exec",       {"command": "echo hi"}, "terminal"),
    ("POST", "/processes/kill",      {"pid": 99999, "signal": "TERM",
                                      "admin": False, "confirm": True}, "processes"),
    ("POST", "/processes/kill_bulk", {"pids": [99999], "signal": "TERM",
                                      "admin": False, "confirm": True}, "processes"),
    ("GET",  "/bt/devices",          None, "bt_recon"),
    # Evidence-producing local-host audits — gated to match wifi.py precedent.
    ("GET",  "/linux/posture",       None, "linux_posture"),
    ("GET",  "/macos/posture",       None, "macos_posture"),
    ("GET",  "/windows/posture",     None, "windows_posture"),
    ("GET",  "/users/audit",         None, "users_audit"),
    ("GET",  "/firewall/rules",      None, "firewall_rules"),
    ("GET",  "/cred-harvest/scan",   None, "cred_harvest"),
    # Stateful BloodHound graph + offline crack — also evidence-producing.
    ("POST", "/lateral/clear",       None, "lateral"),
    ("POST", "/hash/crack",          {"hash": "deadbeef"}, "hash_cracker"),
])
def test_engagement_present_gate_denies_with_stale_engagement(client, method, path, body, key):
    from lib import exposure

    # A stale frontend id puts the request in engagement mode (via mode.py).
    # An exposed router reaches the gate, which fails the lookup → 403
    # TARGET_DENIED. An unexposed router's route isn't registered → 404.
    headers = {**AUTH, "X-MHP-Engagement-Id": "ghost-engagement-id"}
    if method == "POST":
        r = client.post(path, headers=headers, json=body)
    else:
        r = client.get(path, headers=headers)

    if not exposure.is_exposed(key):
        assert r.status_code == 404, \
            f"{path}: unexposed router expected 404, got {r.status_code}: {r.text[:200]}"
        return

    assert r.status_code == 403, f"{path}: expected 403, got {r.status_code}: {r.text[:200]}"
    assert r.json()["code"] == "TARGET_DENIED", r.text[:200]


def test_engagement_present_gate_allows_in_lab_mode(client):
    """Lab mode is the default — no X-MHP-Engagement-Id ⇒ mode resolves to
    lab and the gate is a no-op. Pick a cheap endpoint that IS exposed and
    carries `enforce_engagement_present` (`/hash/crack`, an offline crack)
    and verify we sail past the gate. In lab mode the handler runs to
    completion (200, hash not cracked) rather than being rejected by the
    gate, proving the gate was a no-op."""
    r = client.post("/hash/crack", headers=AUTH, json={"hash": "deadbeef"})
    assert r.status_code != 403
    # The gate didn't fire, so we don't get a TARGET_DENIED code. The offline
    # crack simply runs and returns a normal 200 payload (no error `code`).
    assert r.json().get("code") not in ("TARGET_DENIED",)


# ── chat provider resolution ────────────────────────────────────────────────

def test_chat_config_reports_provider_when_no_key(client, monkeypatch):
    """With no API key and `claude` CLI present (dev environment), the
    auto-resolver should pick claude-cli. CI without the CLI on PATH should
    still parse the response — only the `provider` field changes."""
    r = client.get("/chat/config", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] in ("claude-cli", "anthropic")
    assert "usable" in body
