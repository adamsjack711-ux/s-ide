"""Tests for the chat "Suggest checks" feature.

Two layers: the pure normalization in lib/suggested_checks (the data contract
the cards depend on — fully covered here), and the /chat/suggest-checks
endpoint's plumbing (no-key error, and the parse → normalize path with the
Anthropic call stubbed so we never hit the network).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lib import suggested_checks


AUTH = {"X-MHP-Token": "testing-token"}


# ── pure normalization ────────────────────────────────────────────────────────


def test_normalize_canonicalizes_aliases_and_attaches_nav():
    out = suggested_checks.normalize_checks(
        [{"tool": "tls", "target": "example.com", "rationale": "https is up"}],
    )
    assert out == [{
        "tool": "tls_audit", "nav_id": "tls", "label": "TLS audit",
        "target": "example.com", "rationale": "https is up",
    }]


def test_normalize_drops_offcatalog_tools():
    out = suggested_checks.normalize_checks(
        [{"tool": "launch_nukes", "target": "example.com"}],
    )
    assert out == []


def test_normalize_fills_default_target_and_drops_targetless():
    out = suggested_checks.normalize_checks(
        [
            {"tool": "dns"},                       # inherits default
            {"tool": "whois", "target": "  "},     # blank → default
        ],
        default_target="acme.test",
    )
    assert {c["tool"] for c in out} == {"dns_recon", "whois"}
    assert all(c["target"] == "acme.test" for c in out)


def test_normalize_drops_targetless_when_no_default():
    assert suggested_checks.normalize_checks([{"tool": "dns"}]) == []


def test_normalize_dedupes_and_caps():
    raw = [{"tool": "dns", "target": "a.com"}, {"tool": "dns_recon", "target": "A.COM"}]
    out = suggested_checks.normalize_checks(raw)
    assert len(out) == 1  # same check + case-insensitive same target

    many = [{"tool": t, "target": "a.com"} for t in
            ["dns", "whois", "ct", "subdom", "tls", "http", "nmap", "fingerprint"]]
    assert len(suggested_checks.normalize_checks(many)) == suggested_checks.MAX_CHECKS


def test_normalize_ignores_non_dict_items():
    out = suggested_checks.normalize_checks(["nope", {"tool": "tls", "target": "x"}])  # type: ignore[list-item]
    assert [c["tool"] for c in out] == ["tls_audit"]


def test_catalog_for_prompt_is_id_label_pairs():
    cat = suggested_checks.catalog_for_prompt()
    assert {"id": "tls_audit", "label": "TLS audit"} in cat
    assert all(set(c) == {"id", "label"} for c in cat)


# ── endpoint ──────────────────────────────────────────────────────────────────


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


def test_endpoint_401_without_api_key(client, monkeypatch):
    import routers.suggest_checks as sc
    monkeypatch.setattr(sc, "keychain_get", lambda *a, **k: None)
    r = client.post("/chat/suggest-checks", headers=AUTH,
                    json={"messages": [{"role": "user", "content": "scan example.com"}]})
    assert r.status_code == 401, r.text


def test_endpoint_parses_and_normalizes_model_output(client, monkeypatch):
    import routers.suggest_checks as sc

    monkeypatch.setattr(sc, "keychain_get", lambda *a, **k: "sk-ant-test")

    # Stub the Anthropic client so no network call happens. The model returns
    # JSON in a fenced block with one off-catalog entry that must be dropped.
    class _Block:
        type = "text"
        text = (
            '```json\n{"checks": ['
            '{"tool": "tls", "target": "example.com", "rationale": "https up"},'
            '{"tool": "make_coffee", "target": "example.com"}'
            ']}\n```'
        )

    class _Msg:
        content = [_Block()]

    class _Stub:
        def __init__(self, *a, **k): ...
        class messages:  # noqa: N801
            @staticmethod
            def create(*a, **k):
                return _Msg()

    monkeypatch.setattr(sc.anthropic, "Anthropic", _Stub)

    r = client.post("/chat/suggest-checks", headers=AUTH, json={
        "messages": [{"role": "user", "content": "look at example.com"}],
        "target": "example.com",
    })
    assert r.status_code == 200, r.text
    checks = r.json()["checks"]
    assert len(checks) == 1
    assert checks[0]["tool"] == "tls_audit"
    assert checks[0]["nav_id"] == "tls"
    assert checks[0]["target"] == "example.com"
