"""Adversarial tests for the authorization-attestation hard gate.

`test_spine.py` covers the happy path (arm → run → finding) and the scope
boundary. The *security* value is in the negative paths — proving the gate
actually refuses. These target `lib.safety.require_active_allowed`, the
non-bypassable server-side gate that every active run passes through:

  * a lab-class target needs no attestation (the sandbox is the default-safe path);
  * a non-lab (external) target is REFUSED (403) without a covering attestation;
  * an attestation authorizes only the engagement it was written for — it cannot
    be replayed under a different engagement id;
  * an expired attestation does not authorize;
  * an attestation authorizes only the targets it lists.

Testing the gate directly (rather than only through /spine/run) is deliberate:
the run path denies an external target at the target-policy layer first, so the
attestation gate must be proven at its own boundary — the layer the nmap / active
tool paths call into.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from lib import safety
from lib import engagements

# A public IP literal: classifies as "external" provenance, and needs no DNS so
# the test is deterministic.
EXTERNAL = "1.1.1.1"
OTHER_EXTERNAL = "8.8.8.8"
LAB = "127.0.0.1"

ACTIVE = ("2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z")
EXPIRED = ("2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z")


@pytest.fixture(autouse=True)
def _fresh_safety_schema(temp_db, monkeypatch):
    # `temp_db` gives each test a fresh DB, but safety caches `_schema_ready`
    # module-globally — so reset it (after temp_db swaps the connection) or the
    # attestations table is never (re)created on the new DB.
    monkeypatch.setattr(safety, "_schema_ready", False)
    yield


def _engagement(name="Engagement"):
    # A real engagement row — attestations.engagement_id is a FK into engagements.
    return engagements.create_engagement(name, [], [], "", provenance="external")["id"]


def _attest(engagement_id, targets, window=ACTIVE):
    return safety.create_attestation(
        engagement_id=engagement_id,
        targets=targets,
        window_start=window[0],
        window_end=window[1],
        authority_note="test",
        attested_by="tester",
    )


def test_external_provenance_is_not_lab(temp_db):
    # Guards the premise: the gate only engages for non-lab targets.
    assert safety.provenance(EXTERNAL) == "external"
    assert safety.provenance(LAB) == "lab"


def test_lab_target_needs_no_attestation(temp_db):
    # No attestation exists; a lab-class target is still allowed (returns None).
    assert safety.require_active_allowed(LAB, _engagement()) is None


def test_external_run_blocked_without_attestation(temp_db):
    with pytest.raises(HTTPException) as ei:
        safety.require_active_allowed(EXTERNAL, _engagement())
    assert ei.value.status_code == 403


def test_attestation_authorizes_its_external_target(temp_db):
    eng = _engagement()
    att = _attest(eng, [EXTERNAL])
    # Now the same target under the same engagement is allowed, and the gate
    # returns the covering attestation's id (recorded into the audit ledger).
    assert safety.require_active_allowed(EXTERNAL, eng) == att["id"]


def test_attestation_does_not_replay_across_engagements(temp_db):
    eng_a, eng_b = _engagement("A"), _engagement("B")
    _attest(eng_a, [EXTERNAL])
    # Authorized under the engagement it was written for…
    assert safety.require_active_allowed(EXTERNAL, eng_a) is not None
    # …but NOT under a different engagement, even for the same target.
    with pytest.raises(HTTPException) as ei:
        safety.require_active_allowed(EXTERNAL, eng_b)
    assert ei.value.status_code == 403


def test_expired_attestation_does_not_authorize(temp_db):
    eng = _engagement()
    _attest(eng, [EXTERNAL], window=EXPIRED)
    with pytest.raises(HTTPException) as ei:
        safety.require_active_allowed(EXTERNAL, eng)
    assert ei.value.status_code == 403


def test_attestation_only_covers_listed_targets(temp_db):
    eng = _engagement()
    _attest(eng, [EXTERNAL])
    # A different external target under the same engagement is still refused.
    with pytest.raises(HTTPException) as ei:
        safety.require_active_allowed(OTHER_EXTERNAL, eng)
    assert ei.value.status_code == 403
