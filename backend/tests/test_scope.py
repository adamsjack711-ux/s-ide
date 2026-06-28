"""Unit tests for `lib/scope.py`.

The scope module is the load-bearing v1.0 safety control — every
target-accepting router calls into it before shelling out. Coverage
here splits into:

  - Pure pattern matching (`check_against`) — no DB
  - Verdict combining (`combine`) — no DB
  - Mode + engagement gating (`check`, `check_combined`) — needs DB
  - Enforcer side-effects (`enforce_rest`, `enforce_engagement_present`) — needs DB
"""
from __future__ import annotations

import pytest

from lib import engagements, scope
from lib.errors import ErrorCode, MhpError


# ── combine: deny > warn > allow ────────────────────────────────────────────

@pytest.mark.parametrize("a, b, expected_verdict", [
    (("allow", "ok"),  ("allow", "ok"),  "allow"),
    (("allow", "ok"),  ("warn",  "iffy"), "warn"),
    (("warn",  "x"),   ("deny",  "no"),   "deny"),
    (("deny",  "no"),  ("allow", "ok"),   "deny"),
    (("warn",  "a"),   ("warn",  "b"),   "warn"),  # tie → a wins
])
def test_combine_picks_most_restrictive(a, b, expected_verdict):
    v, _ = scope.combine(a, b)
    assert v == expected_verdict


def test_combine_tie_prefers_a_reason():
    """Tie-break on `a` so policy-layer reasons surface first when both warn."""
    v, r = scope.combine(("warn", "policy reason"), ("warn", "scope reason"))
    assert v == "warn"
    assert r == "policy reason"


# ── check_against: pure scope-list matcher ──────────────────────────────────

def test_check_against_empty_scope_is_permissive():
    """No scope set ⇒ allow with reason 'no scope set' — standard pentest contract."""
    v, r = scope.check_against("example.com", scope_list=[], exclusions=[])
    assert v == "allow"
    assert "no scope" in r.lower()


def test_check_against_empty_target_denies():
    v, r = scope.check_against("", scope_list=["example.com"], exclusions=[])
    assert v == "deny"
    assert "empty" in r.lower()


@pytest.mark.parametrize("target, entry, expected", [
    ("example.com",      "example.com",   True),   # exact
    ("sub.example.com",  "example.com",   True),   # bare host matches subdomain
    ("sub.example.com",  "*.example.com", True),   # wildcard matches subdomain
    ("example.com",      "*.example.com", False),  # wildcard does NOT match apex
    ("attacker.com",     "*.example.com", False),  # totally unrelated
    ("EXAMPLE.com",      "example.com",   True),   # case-insensitive
])
def test_check_against_hostname_matching(target, entry, expected):
    v, _ = scope.check_against(target, scope_list=[entry], exclusions=[])
    assert (v == "allow") == expected


def test_check_against_exclusion_overrides_scope():
    """A target inside scope still denies if it matches an exclusion entry."""
    v, r = scope.check_against(
        "admin.example.com",
        scope_list=["example.com"],
        exclusions=["admin.example.com"],
    )
    assert v == "deny"
    assert "admin.example.com" in r


def test_check_against_cidr_match():
    """CIDR entry should match any IP literal inside the network."""
    v, _ = scope.check_against("10.1.2.3", scope_list=["10.0.0.0/8"], exclusions=[])
    assert v == "allow"


def test_check_against_cidr_outside_denies():
    v, _ = scope.check_against("11.0.0.1", scope_list=["10.0.0.0/8"], exclusions=[])
    assert v == "deny"


def test_check_against_url_scope_entry_extracts_host():
    """A URL in the scope list should be treated as its hostname."""
    v, _ = scope.check_against(
        "shop.example.com",
        scope_list=["https://example.com/path"],
        exclusions=[],
    )
    assert v == "allow"


def test_check_against_target_with_port_stripped():
    """Host:port targets should match host-based scope entries."""
    v, _ = scope.check_against(
        "example.com:8080",
        scope_list=["example.com"],
        exclusions=[],
    )
    assert v == "allow"


# ── check / check_combined: mode + engagement gating (needs DB) ─────────────

def test_check_lab_mode_always_allows(temp_db):
    """Lab is the experiment-freely mode — scope is never enforced."""
    v, r = scope.check("anything.example", None, mode="lab")
    assert v == "allow"
    assert "lab" in r.lower()


def test_check_engagement_mode_requires_engagement_id(temp_db):
    v, r = scope.check("example.com", None, mode="engagement")
    assert v == "deny"
    assert "engagement" in r.lower()


def test_check_engagement_mode_with_unknown_id_denies(temp_db):
    """Stale frontend ids must NOT silently bypass scope."""
    v, r = scope.check("example.com", "nonexistent-id", mode="engagement")
    assert v == "deny"
    assert "not found" in r.lower()


def test_check_engagement_mode_with_real_engagement(temp_db):
    eng = engagements.create_engagement(
        name="acme",
        scope=["*.example.com"],
        exclusions=["admin.example.com"],
        notes="",
    )
    v_in,  _ = scope.check("api.example.com",   eng["id"], mode="engagement")
    v_out, _ = scope.check("attacker.com",      eng["id"], mode="engagement")
    v_excl,_ = scope.check("admin.example.com", eng["id"], mode="engagement")
    assert v_in   == "allow"
    assert v_out  == "deny"
    assert v_excl == "deny"


def test_check_combined_layers_surface_in_response(temp_db):
    """`check_combined` should report both policy and scope verdicts in `layers`."""
    eng = engagements.create_engagement(
        name="acme", scope=["example.com"], exclusions=[], notes="",
    )
    v, r, layers = scope.check_combined(
        "example.com", eng["id"], mode="engagement",
    )
    assert "policy" in layers
    assert "scope"  in layers
    # Reason prefix tells you which layer triggered the final verdict.
    assert r.startswith("policy:") or r.startswith("scope:")


# ── enforce_rest: deny / warn / allow side-effects ──────────────────────────

def test_enforce_rest_deny_raises_403(temp_db):
    with pytest.raises(MhpError) as exc:
        scope.enforce_rest("example.com", None, mode="engagement")
    assert exc.value.status_code == 403
    assert exc.value.code == ErrorCode.TARGET_DENIED.value


def test_enforce_rest_warn_without_confirm_raises_409(temp_db, permissive_policy):
    """An external target gets a target_policy warn — enforce_rest converts
    that to NEED_CONFIRM unless the caller passed confirm=True. Production
    config.json now defaults to deny-external; permissive_policy pins the
    older warn-on-external semantic so we can exercise the warn path."""
    with pytest.raises(MhpError) as exc:
        scope.enforce_rest("example.com", None, mode="lab")  # lab → scope allow
    # policy layer still warns on external targets → 409 NEED_CONFIRM.
    assert exc.value.status_code == 409
    assert exc.value.code == ErrorCode.NEED_CONFIRM.value


def test_enforce_rest_warn_with_confirm_allows(temp_db, permissive_policy):
    v, r, _ = scope.enforce_rest("example.com", None, mode="lab", confirm=True)
    assert v in ("allow", "warn")  # warn proceeds when confirm=True


def test_enforce_rest_deny_only_passive_tool_passes_warn(temp_db, permissive_policy):
    """Passive tools (TLS audit, WHOIS) use deny_only=True — warn proceeds."""
    v, r, _ = scope.enforce_rest("example.com", None, mode="lab", deny_only=True)
    assert v in ("allow", "warn")


# ── enforce_engagement_present: non-target tools ────────────────────────────

def test_enforce_engagement_present_lab_is_no_op(temp_db):
    """Lab mode bypasses the engagement-present requirement entirely."""
    scope.enforce_engagement_present(None, mode="lab")  # must not raise


def test_enforce_engagement_present_engagement_without_id_denies(temp_db):
    with pytest.raises(MhpError) as exc:
        scope.enforce_engagement_present(None, mode="engagement")
    assert exc.value.status_code == 403
    assert exc.value.code == ErrorCode.TARGET_DENIED.value


def test_enforce_engagement_present_unknown_id_denies(temp_db):
    with pytest.raises(MhpError):
        scope.enforce_engagement_present("ghost-id", mode="engagement")


def test_enforce_engagement_present_valid_engagement_passes(temp_db):
    eng = engagements.create_engagement(
        name="acme", scope=[], exclusions=[], notes="",
    )
    # Must not raise.
    scope.enforce_engagement_present(eng["id"], mode="engagement")
