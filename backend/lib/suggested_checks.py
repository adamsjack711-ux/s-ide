"""Proposable security checks for the chat "Suggest checks" affordance.

The chat copilot proposes a handful of concrete next checks; the UI renders
each as an Approve / Skip / Modify card and, on approval, navigates to the
tool page with the target pre-filled. This module is the data contract for
that flow: the bounded catalog of checks the model is allowed to propose
(each maps to a real frontend nav id and takes a target), plus the pure
normalization that validates a raw model proposal into card-ready items.

Keeping the catalog bounded is deliberate — the copilot proposes, it never
executes, and it can only propose passive/standard recon that has a tool
page behind it. The normalization drops anything off-catalog so a model
hallucination can't produce a card that goes nowhere.
"""
from __future__ import annotations

from typing import Any

# Canonical check id → presentation + the frontend nav id its Approve button
# jumps to. Ordered roughly as a recon would proceed.
PROPOSABLE_CHECKS: dict[str, dict[str, str]] = {
    "dns_recon":       {"nav_id": "dns",         "label": "DNS recon"},
    "whois":           {"nav_id": "whois",       "label": "WHOIS / ASN"},
    "ct_log":          {"nav_id": "ct",          "label": "CT log search"},
    "subdomain_enum":  {"nav_id": "subdom",      "label": "Subdomain enum"},
    "tls_audit":       {"nav_id": "tls",         "label": "TLS audit"},
    "http_probe":      {"nav_id": "http",        "label": "HTTP probe"},
    "port_scan":       {"nav_id": "nmap",        "label": "Port scan"},
    "fingerprint":     {"nav_id": "fingerprint", "label": "Stack fingerprint"},
}

# Aliases the model (or a caller) might use for each canonical id. Matched
# against the normalized (lowercased, hyphen→underscore) proposed tool name.
_ALIASES: dict[str, str] = {
    "dns": "dns_recon", "dns_recon": "dns_recon", "dnsrecon": "dns_recon",
    "whois": "whois",
    "ct": "ct_log", "ct_log": "ct_log", "ctlog": "ct_log", "ct_logs": "ct_log",
    "subdom": "subdomain_enum", "subdomain": "subdomain_enum",
    "subdomain_enum": "subdomain_enum", "subdomains": "subdomain_enum",
    "tls": "tls_audit", "tls_audit": "tls_audit",
    "http": "http_probe", "http_probe": "http_probe", "headers": "http_probe",
    "ports": "port_scan", "port_scan": "port_scan", "portscan": "port_scan",
    "port_scanner": "port_scan", "nmap": "port_scan",
    "fingerprint": "fingerprint", "cms": "fingerprint", "stack": "fingerprint",
}

MAX_CHECKS = 6


def catalog_for_prompt() -> list[dict[str, str]]:
    """The check catalog as the model should see it — id + label only."""
    return [{"id": cid, "label": meta["label"]}
            for cid, meta in PROPOSABLE_CHECKS.items()]


def _canonical(tool: str) -> str | None:
    return _ALIASES.get((tool or "").strip().lower().replace("-", "_"))


def normalize_checks(
    raw_checks: list[dict[str, Any]],
    default_target: str = "",
) -> list[dict[str, Any]]:
    """Validate a raw model proposal into card-ready checks.

    Each input item is ``{tool, target?, rationale?}``. We canonicalize the
    tool against the catalog (dropping anything off-catalog), fill the target
    from the item or the conversation default (dropping checks with no usable
    target — a card with nothing to pre-fill is useless), trim the rationale,
    dedupe on (check, target), and cap the count. Returns items shaped for the
    UI: ``{tool, nav_id, label, target, rationale}``.
    """
    default_target = (default_target or "").strip()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for item in raw_checks:
        if not isinstance(item, dict):
            continue
        cid = _canonical(str(item.get("tool", "")))
        if cid is None:
            continue
        target = str(item.get("target", "") or "").strip() or default_target
        if not target:
            continue
        key = (cid, target.lower())
        if key in seen:
            continue
        seen.add(key)
        meta = PROPOSABLE_CHECKS[cid]
        out.append({
            "tool": cid,
            "nav_id": meta["nav_id"],
            "label": meta["label"],
            "target": target,
            "rationale": str(item.get("rationale", "") or "").strip()[:400],
        })
        if len(out) >= MAX_CHECKS:
            break

    return out
