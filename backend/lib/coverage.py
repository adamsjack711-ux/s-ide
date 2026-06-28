"""Engagement coverage matrix — "what's been checked for this engagement".

A read-only projection over the data the app already tracks per engagement
(``audit_log`` actions, ``scan_results``, ``findings``). It answers the
question a tester asks before writing the report: *did I actually look at
DNS / TLS / headers / services here, did I record any findings, and have I
exported a report?*

No new storage. Every area's status is derived from existing rows, so the
matrix is always consistent with the audit log and results timeline. Tool
naming is heterogeneous across the app (the scope-gated routers log
``port_scanner``, the playbook adapters use ``tls_audit`` / ``dns_recon``,
the requirements registry uses short ids like ``tls`` / ``ports``), so each
area matches a curated set of normalized aliases rather than one canonical
id — deterministic, and no greedy substring matching that would mis-bucket
unrelated tools.
"""
from __future__ import annotations

from typing import Any

from lib import audit_log, engagements


def _norm(tool: str) -> str:
    """Normalize a tool name for alias matching: lowercase, hyphens→underscores."""
    return (tool or "").strip().lower().replace("-", "_")


# Ordered so the matrix reads as a natural recon → evidence → deliverable flow.
# `aliases` are matched against the normalized tool name by exact membership.
_RECON_AREAS: list[dict[str, Any]] = [
    {
        "key": "dns",
        "label": "DNS & domain recon",
        "description": "DNS records, certificate-transparency, subdomains, WHOIS.",
        "aliases": frozenset({
            "dns", "dns_recon", "ct", "ct_log", "subdom", "subdomain_enum",
            "whois", "reverse_ip", "wayback", "takeover", "dorking",
        }),
    },
    {
        "key": "tls",
        "label": "TLS / certificate",
        "description": "TLS versions, cipher suites, certificate chain and expiry.",
        "aliases": frozenset({"tls", "tls_audit"}),
    },
    {
        "key": "headers",
        "label": "HTTP security headers",
        "description": "Security headers, server fingerprint, CMS detection.",
        "aliases": frozenset({
            "http", "http_probe", "http_get", "http_post", "headers",
            "fingerprint", "cms", "cms_fingerprint",
        }),
    },
    {
        "key": "services",
        "label": "Exposed services / ports",
        "description": "Open ports, service/version detection, LAN sweep.",
        "aliases": frozenset({
            "ports", "port_scanner", "nmap", "lan", "lan_scan", "ping",
        }),
    },
]

# Aliases the report-export path logs (see routers/reports.py).
_REPORT_ALIASES = frozenset({"report", "report_export"})


def _gather_activity(engagement_id: str) -> list[dict[str, Any]]:
    """Unified (tool, ts, target) activity stream for an engagement.

    Merges audit-log actions (every gated tool run) with scan_results (the
    evidence timeline). A tool can appear in both; that's fine — coverage
    counts each recorded run and reports the most recent timestamp.
    """
    activity: list[dict[str, Any]] = []
    for a in audit_log.list_actions(engagement_id=engagement_id, limit=1000):
        activity.append({
            "tool": a["tool"], "ts": a.get("ts_start", ""),
            "target": a.get("target", ""),
        })
    for r in engagements.list_results(engagement_id, limit=1000):
        activity.append({
            "tool": r["tool"], "ts": r.get("ts", ""),
            "target": r.get("target", ""),
        })
    return activity


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse matching activity rows into an area status block."""
    if not rows:
        return {"covered": False, "runs": 0, "last_ts": None,
                "last_tool": None, "last_target": None, "tools_seen": []}
    latest = max(rows, key=lambda r: r["ts"] or "")
    tools_seen = sorted({r["tool"] for r in rows if r["tool"]})
    return {
        "covered": True,
        "runs": len(rows),
        "last_ts": latest["ts"] or None,
        "last_tool": latest["tool"] or None,
        "last_target": latest["target"] or None,
        "tools_seen": tools_seen,
    }


def compute_coverage(engagement_id: str) -> dict[str, Any]:
    """Build the coverage matrix for one engagement.

    Returns six ordered areas (the four recon checks, plus findings and
    report) each with a `covered` flag and supporting counts/timestamps,
    plus a roll-up `covered_count` / `total`.
    """
    activity = _gather_activity(engagement_id)

    areas: list[dict[str, Any]] = []
    for spec in _RECON_AREAS:
        matched = [a for a in activity if _norm(a["tool"]) in spec["aliases"]]
        areas.append({
            "key": spec["key"], "label": spec["label"],
            "description": spec["description"], **_summarize(matched),
        })

    # Findings — derived from the findings table, not the activity stream.
    findings = engagements.list_findings(engagement_id)
    last_finding_ts = max((f.get("ts", "") for f in findings), default="") or None
    areas.append({
        "key": "findings",
        "label": "Findings recorded",
        "description": "At least one finding promoted to the engagement.",
        "covered": bool(findings),
        "runs": len(findings),
        "last_ts": last_finding_ts,
        "last_tool": None, "last_target": None, "tools_seen": [],
    })

    # Report — covered once a report has been exported (logged by the
    # report-export path to the audit log).
    report_rows = [a for a in activity if _norm(a["tool"]) in _REPORT_ALIASES]
    report = _summarize(report_rows)
    report.update({
        "key": "report",
        "label": "Report exported",
        "description": "An engagement report has been generated.",
    })
    areas.append(report)

    covered_count = sum(1 for a in areas if a["covered"])
    return {
        "engagement_id": engagement_id,
        "areas": areas,
        "covered_count": covered_count,
        "total": len(areas),
    }
