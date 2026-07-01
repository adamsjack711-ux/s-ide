"""Engagement self-assessment — "is this engagement ready to report?"

A read-only readiness projection layered on top of the coverage matrix
(``lib.coverage``). Coverage answers *what did I run*; self-assess answers
*what still needs doing before this engagement is defensible* — recon gaps,
findings that lack evidence or CVSS, unresolved triage, an un-exported report,
and external targets acted upon without a covering authorization attestation.

No new storage. Every check is derived from existing rows (audit log, results
timeline, findings, evidence, attestations) so the assessment is always
consistent with the engagement's real state.
"""
from __future__ import annotations

from typing import Any

from lib import audit_log, coverage, engagements, safety

# Severities for which an un-scored (no CVSS) finding is a real gap. `info`/`low`
# don't strictly need a vector to be defensible.
_CVSS_EXPECTED = frozenset({"medium", "high", "critical"})
# Canonical "still needs a verdict" status (legacy `triaged` also counts as
# resolved-enough; `open` is the unresolved state).
_UNRESOLVED_STATUS = "open"


def _check(cid: str, label: str, status: str, detail: str,
           *, count: int = 0, items: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": cid, "label": label, "status": status, "detail": detail,
        "count": count, "items": items or [],
    }


def _distinct_targets(engagement_id: str) -> list[str]:
    """Non-empty targets actually acted upon in this engagement (audit + results)."""
    seen: set[str] = set()
    for a in audit_log.list_actions(engagement_id=engagement_id, limit=1000):
        t = (a.get("target") or "").strip()
        if t:
            seen.add(t)
    for r in engagements.list_results(engagement_id, limit=1000):
        t = (r.get("target") or "").strip()
        if t:
            seen.add(t)
    return sorted(seen)


def assess(engagement_id: str) -> dict[str, Any]:
    """Compute the readiness report for one engagement."""
    cov = coverage.compute_coverage(engagement_id)
    areas = {a["key"]: a for a in cov["areas"]}
    findings = engagements.list_findings(engagement_id)
    checks: list[dict[str, Any]] = []

    # 1 — Recon coverage. Gap when any recon area was never exercised.
    recon_keys = ("dns", "tls", "headers", "services")
    uncovered = [areas[k]["label"] for k in recon_keys if k in areas and not areas[k]["covered"]]
    checks.append(_check(
        "recon_coverage", "Recon coverage",
        "ok" if not uncovered else "gap",
        "All recon areas exercised." if not uncovered
        else f"{len(uncovered)} recon area(s) never run.",
        count=len(uncovered), items=uncovered,
    ))

    # 2 — Findings recorded at all.
    checks.append(_check(
        "findings_recorded", "Findings recorded",
        "ok" if findings else "warn",
        f"{len(findings)} finding(s) promoted." if findings
        else "No findings promoted to this engagement yet.",
        count=len(findings),
    ))

    # 3 — Findings missing evidence (list_evidence folds in the legacy blob).
    no_ev = [f for f in findings if not engagements.list_evidence(f["id"])]
    checks.append(_check(
        "findings_evidence", "Findings have evidence",
        "ok" if not no_ev else "warn",
        "Every finding carries evidence." if not no_ev
        else f"{len(no_ev)} finding(s) have no evidence attached.",
        count=len(no_ev), items=[f.get("title", f["id"]) for f in no_ev],
    ))

    # 4 — Medium+ findings missing a CVSS score.
    no_cvss = [
        f for f in findings
        if (f.get("severity") or "").lower() in _CVSS_EXPECTED and f.get("cvss") is None
    ]
    checks.append(_check(
        "findings_cvss", "Medium+ findings scored",
        "ok" if not no_cvss else "warn",
        "All medium+ findings have CVSS." if not no_cvss
        else f"{len(no_cvss)} medium+ finding(s) lack a CVSS score.",
        count=len(no_cvss), items=[f.get("title", f["id"]) for f in no_cvss],
    ))

    # 5 — Unresolved findings (still open / untriaged).
    unresolved = [f for f in findings if (f.get("status") or "").lower() == _UNRESOLVED_STATUS]
    checks.append(_check(
        "findings_triage", "Findings triaged",
        "ok" if not unresolved else "warn",
        "No findings left open." if not unresolved
        else f"{len(unresolved)} finding(s) still open (unconfirmed).",
        count=len(unresolved), items=[f.get("title", f["id"]) for f in unresolved],
    ))

    # 6 — External targets acted upon without a covering attestation.
    external_unattested = [
        t for t in _distinct_targets(engagement_id)
        if safety.provenance(t) == "external"
        and safety.attestation_for(t, engagement_id) is None
    ]
    checks.append(_check(
        "target_attestation", "External targets attested",
        "ok" if not external_unattested else "gap",
        "No unattested external targets." if not external_unattested
        else f"{len(external_unattested)} external target(s) acted on without attestation.",
        count=len(external_unattested), items=external_unattested,
    ))

    # 7 — Report exported.
    report = areas.get("report", {})
    checks.append(_check(
        "report_exported", "Report exported",
        "ok" if report.get("covered") else "warn",
        "A report has been generated." if report.get("covered")
        else "No engagement report exported yet.",
    ))

    ok = sum(1 for c in checks if c["status"] == "ok")
    warn = sum(1 for c in checks if c["status"] == "warn")
    gap = sum(1 for c in checks if c["status"] == "gap")
    return {
        "engagement_id": engagement_id,
        "checks": checks,
        "summary": {"ok": ok, "warn": warn, "gap": gap, "total": len(checks)},
        "score": round(100 * ok / len(checks)) if checks else 0,
        "ready": gap == 0 and warn == 0,
    }
