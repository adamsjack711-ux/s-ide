"""Capability gate for the s-ide IDE.

The backend is vendored wholesale from s-ide, but s-ide only *exposes* the
zero-setup (Tier 1) toolset. Tier 2 (privilege/root/raw-socket) and Tier 3
(external setup: API keys / Docker / cloud SDKs / special hardware) routers ship
in the codebase but are NOT registered by default — their routes return 404 —
unless the operator opts in with ``RAMPART_EXPOSE_ALL=1``.

This enforces the slim-toolset promise *server-side*, not merely by omitting a
page from the UI. Re-exposing a tool later is a one-line change here.

Keys are the router *module* names (``routers/<key>.py``). Secondary routers in
a module (e.g. ``ip_checker.shodan_router``, ``dorking.osint_router``) inherit
their module's key.
"""
from __future__ import annotations

import os

# ── Tier 1: zero-setup — the slim set s-ide exposes ─────────────────────────
TIER1: frozenset[str] = frozenset(
    {
        # Engagement spine (pure SQLite — the differentiator).
        "engagements", "findings", "cvss", "reports", "scope", "targets",
        "audit_log", "triage", "suggest_checks",
        # Target / sub-target / engagement / pairing domain model + 4-tab spine.
        "spine",
        # Discovery / DNS / naming.
        "ip_checker", "dns_recon", "whois", "subdomain_enum", "reverse_ip",
        "local_discovery",
        # Web recon.
        "http_probe", "tls_audit", "ct_log", "fingerprint", "cms", "graphql",
        "takeover", "wayback", "urlscan", "email_security",
        # OSINT.
        "dorking", "email_harvest", "profile_finder", "people_enum",
        "github_leak", "breach",
        # Crypto / utility.
        "jwt_analyzer", "hash_cracker", "exploits",
        # Codebase SAST scan (local source → vulnerability findings).
        "codescan",
        # Recon connectivity (port_scanner exposes connect-mode; SYN gated in UI).
        "port_scanner", "ping", "system_info", "processes",
        # Cloud-lite (no credentials — probes link-local only).
        "imds",
        # Copilot (auto-detect provider, degrade gracefully — never a hard dep).
        "chat", "summarize",
        # Meta / settings.
        "tool_requirements", "basic_check", "settings", "presets",
        # Capability enablement API (control surface for the server-side
        # require_capability gate — see lib/capability.py).
        "capabilities",
        # Single-shot terminal — zero-setup (localhost + token + engagement
        # gated). Baked into the Workbench as a quick-run surface.
        "terminal",
        # Learning-sandbox data model + surfaces (assets/steps/labs/progress,
        # isolation self-check, lab-source fix-in-place, playbooks).
        "method", "isolation", "labfs", "playbook_run",
        # Safety layer — provenance + authorization attestations + audit.
        "safety",
        # Theme distribution — fetch/validate/cache .side themes (Tier 1).
        "themes",
    }
)

# ── Sandbox arsenal (re-scope 2026-06-28) ───────────────────────────────────
# The "open security-testing sandbox" exposes privileged / intrusive / external
# tools too, so they're REGISTERED here and callable. They remain OFF in the UI
# until the operator enables their capability group. Enablement is now enforced
# server-side: `main.py` attaches `capability.require_capability(group)` to each
# gated router (see lib/capability.py), so "off until enabled" holds against a
# direct API call, not just in the UI. Scope + authorization + audit remain
# separate hard gates on top. Web-exploit fuzzers are un-deferred here.
EXPOSED_EXTRA: frozenset[str] = frozenset(
    {
        # Recon (privileged).
        "nmap", "lan_scan",
        # Web exploit (intrusive, Tier-1 pure-python).
        "xss", "sqli", "cmdi", "lfi", "ssrf", "idor",
        # Active Directory (external: impacket/ldap3 + AD).
        "ldap_enum", "smb_enum", "ad_spray", "kerberos_roast",
        "bloodhound_ingest", "lateral",
        # Red-team core.
        "reverse_shell", "c2_beacon",
        # Labs — the colima/Docker-backed sandbox targets (the design's "Labs").
        "labs",
    }
)


def expose_all() -> bool:
    """True when the operator has opted into the full (ungated) toolset."""
    return os.environ.get("RAMPART_EXPOSE_ALL", "").strip() == "1"


def is_exposed(key: str) -> bool:
    """Whether the router keyed by ``key`` should be registered."""
    return expose_all() or key in TIER1 or key in EXPOSED_EXTRA
