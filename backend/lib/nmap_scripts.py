"""NSE script catalog, category index, and built-in presets.

Wraps the lower-level `nmap_runner.list_scripts()` / `scripts_dir()` with:

  * A cross-platform scripts-dir resolver that augments nmap_runner's
    candidate list with Windows install paths.
  * An in-memory cache for the parsed catalog — `script.db` parsing is
    cheap but builds a ~600-entry list and is called from the script-picker
    UI on every page load.
  * A risk grouping (`safe` / `moderate` / `intrusive`) the frontend uses
    to colour-code category badges and warn before running.
  * A small set of curated presets exposed via `GET /nmap/script-presets`.

Nothing in here actually invokes nmap — that's `lib/nmap_runner` and
`routers/nmap`. This module is pure metadata.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from lib import nmap_runner

# Risk buckets the frontend renders as coloured chips. A category that is
# absent from the index defaults to "moderate" so unknown NSE categories
# from future nmap releases get a neutral colour rather than a green pass.
RISK_BY_CATEGORY: dict[str, str] = {
    "auth":        "moderate",
    "broadcast":   "moderate",
    "brute":       "intrusive",
    "default":     "safe",
    "discovery":   "safe",
    "dos":         "intrusive",
    "exploit":     "intrusive",
    "external":    "moderate",
    "fuzzer":      "intrusive",
    "intrusive":   "intrusive",
    "malware":     "intrusive",
    "safe":        "safe",
    "version":     "safe",
    "vuln":        "intrusive",
}

# Curated NSE script presets. Each value is a self-contained recipe:
#   * `categories` and/or `scripts` are passed straight through to
#     `NmapOptions.nse_categories` / `NmapOptions.nse_scripts` so the
#     WS handshake stays a thin wrapper.
#   * `ports` is optional — when set, the handshake builds `port_spec`
#     for the scan.
#   * `service_version` mirrors the `-sV` flag and is set on presets
#     that depend on banner data.
PRESETS: dict[str, dict[str, Any]] = {
    "quick_vuln": {
        "name": "Quick Vulnerability Scan",
        "description": "Common CVEs and vulnerabilities (-sV --script vuln).",
        "categories": ["vuln"],
        "scripts": [],
        "ports": "",
        "service_version": True,
        "risk": "intrusive",
        "args_preview": "-sV --script vuln",
    },
    "web_enum": {
        "name": "Web Enumeration",
        "description": "Full HTTP/HTTPS enumeration on common web ports.",
        "categories": [],
        "scripts": ["http-*"],
        "ports": "80,443,8080,8443",
        "service_version": True,
        "risk": "moderate",
        "args_preview": "-sV -p 80,443,8080,8443 --script http-*",
    },
    "auth_check": {
        "name": "Default Credentials",
        "description": "Check for default/weak credentials.",
        "categories": ["auth", "brute"],
        "scripts": [],
        "ports": "",
        "service_version": False,
        "risk": "intrusive",
        "args_preview": "--script auth,brute",
    },
    "full_recon": {
        "name": "Full Recon",
        "description": "Comprehensive safe enumeration (-sV -sC -A).",
        "categories": ["default", "discovery", "safe"],
        "scripts": [],
        "ports": "",
        "service_version": True,
        "os_detect": True,
        "traceroute": True,
        "risk": "moderate",
        "args_preview": "-sV -sC -A",
    },
    "smb_enum": {
        "name": "SMB Enumeration",
        "description": "Windows SMB shares and users.",
        "categories": [],
        "scripts": ["smb-*"],
        "ports": "445,139",
        "service_version": True,
        "risk": "moderate",
        "args_preview": "-sV -p 445,139 --script smb-*",
    },
    "ssl_audit": {
        "name": "SSL/TLS Audit",
        "description": "Certificate and cipher analysis.",
        "categories": [],
        "scripts": ["ssl-*"],
        "ports": "443,8443",
        "service_version": True,
        "risk": "safe",
        "args_preview": "-sV -p 443,8443 --script ssl-*",
    },
}


# ── Cross-platform scripts-dir resolution ───────────────────────────────────
# `nmap_runner.scripts_dir()` only knows Unix paths. We extend the candidate
# list with Windows install directories.
_WINDOWS_CANDIDATES = (
    r"C:\Program Files (x86)\Nmap\scripts",
    r"C:\Program Files\Nmap\scripts",
)


def resolve_scripts_dir(binary: str | None = None) -> str | None:
    """Return the NSE scripts directory across macOS/Linux/Windows.

    Tries nmap_runner's Unix lookup first, then Windows fall-backs.
    """
    if binary is None:
        binary = nmap_runner.find_nmap()
    if binary:
        sdir = nmap_runner.scripts_dir(binary)
        if sdir and Path(sdir).is_dir():
            return sdir
    for cand in _WINDOWS_CANDIDATES:
        p = Path(cand)
        if p.is_dir():
            return str(p)
    return None


# ── In-memory catalog cache ─────────────────────────────────────────────────
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, Any] | None = None


def _categorise(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Group a flat scripts list into a category index + risk-bucketed view.

    Returned shape matches the contract documented in `routers/nmap.py`:

        {
          "categories": {<cat>: [<script name>, ...], ...},
          "risk_groups": {"safe":[...], "moderate":[...], "intrusive":[...]},
          "scripts": [{"name","category","categories","risk","description"}, ...]
        }
    """
    categories: dict[str, list[str]] = {}
    risk_groups: dict[str, list[str]] = {"safe": [], "moderate": [], "intrusive": []}
    enriched: list[dict[str, Any]] = []

    for it in items:
        name = it["name"]
        cats = it.get("categories", []) or []
        # Primary category = first one nmap declared (matches `--script-help`).
        primary = cats[0] if cats else ""
        # Risk = worst of all its categories ("intrusive" > "moderate" > "safe").
        worst = "safe"
        for c in cats:
            r = RISK_BY_CATEGORY.get(c, "moderate")
            if r == "intrusive":
                worst = "intrusive"
                break
            if r == "moderate" and worst != "intrusive":
                worst = "moderate"
        if not cats:
            worst = "moderate"

        for c in cats:
            categories.setdefault(c, []).append(name)
        risk_groups[worst].append(name)
        enriched.append({
            "name": name,
            "category": primary,
            "categories": cats,
            "risk": worst,
            "description": "",  # populated on demand via /nmap/script-help
        })

    # Stable ordering keeps the UI from re-flowing between requests.
    for v in categories.values():
        v.sort()
    for v in risk_groups.values():
        v.sort()
    enriched.sort(key=lambda d: d["name"])
    return {
        "categories": categories,
        "risk_groups": risk_groups,
        "scripts": enriched,
    }


def load_catalog(force: bool = False) -> dict[str, Any]:
    """Return the cached NSE catalog.

    Set `force=True` to invalidate (e.g. after the user upgrades nmap and
    the script.db on disk changed).
    """
    global _CACHE
    with _CACHE_LOCK:
        if _CACHE is not None and not force:
            return _CACHE
        sdir = resolve_scripts_dir()
        if not sdir:
            _CACHE = {
                "available": False,
                "scripts_dir": "",
                "count": 0,
                "categories": {},
                "risk_groups": {"safe": [], "moderate": [], "intrusive": []},
                "scripts": [],
            }
            return _CACHE
        items = nmap_runner.list_scripts(sdir)
        cat = _categorise(items)
        _CACHE = {
            "available": True,
            "scripts_dir": sdir,
            "count": len(items),
            **cat,
        }
        return _CACHE


def list_presets() -> dict[str, Any]:
    """Return the preset catalog with names suitable for an API response."""
    return {"presets": {k: {**v, "id": k} for k, v in PRESETS.items()}}


def get_preset(preset_id: str) -> dict[str, Any] | None:
    p = PRESETS.get(preset_id)
    if not p:
        return None
    return {**p, "id": preset_id}
