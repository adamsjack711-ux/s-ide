"""Google Dorking — dork generation + optional Custom Search execution.

Two modes:

  - **Manual** (no key): we generate dork strings for the target across
    selected categories and return `google.com/search?q=...` URLs the user
    opens in their own browser. Avoids Google's anti-bot blocks.
  - **CSE-backed** (key required): if `google_cse_api_key` and `google_cse_id`
    are configured in Keychain, we execute each dork via the Custom Search
    JSON API and return result snippets. CSE has a 100/day free tier.

We deliberately *don't* scrape google.com directly — it triggers CAPTCHAs and
hurts the user's real Google session.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from lib.auth import require_local_auth
from pydantic import BaseModel, Field

from lib import scope
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.validators import validate_domain

from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dorking", tags=["dorking"],
                   dependencies=[Depends(require_local_auth)])
# Separate router (no /dorking prefix) for the /osint/dorks/{domain} alias.
osint_router = APIRouter(tags=["dorking-osint"],
                         dependencies=[Depends(require_local_auth)])

UA = "HackingPal/0.1 dorking"

# Each category: a list of dork templates. `{t}` is the target domain.
CATEGORIES: dict[str, list[str]] = {
    "files": [
        'site:{t} filetype:pdf',
        'site:{t} filetype:doc OR filetype:docx',
        'site:{t} filetype:xls OR filetype:xlsx',
        'site:{t} filetype:ppt OR filetype:pptx',
        'site:{t} filetype:sql',
        'site:{t} filetype:bak OR filetype:old OR filetype:backup',
        'site:{t} filetype:log',
        'site:{t} filetype:env',
        'site:{t} filetype:conf OR filetype:config',
        'site:{t} filetype:json',
    ],
    "admin": [
        'site:{t} inurl:admin',
        'site:{t} inurl:login',
        'site:{t} inurl:dashboard',
        'site:{t} intitle:"admin login"',
        'site:{t} inurl:wp-admin',
        'site:{t} inurl:phpmyadmin OR inurl:adminer',
    ],
    "leaks": [
        'site:{t} "password"',
        'site:{t} "api_key" OR "apikey"',
        'site:{t} "secret"',
        'site:{t} "BEGIN RSA PRIVATE KEY"',
        'site:{t} "Index of /"',
        'site:pastebin.com "{t}"',
        'site:trello.com "{t}"',
        'site:github.com "{t}" password',
    ],
    "errors": [
        'site:{t} "fatal error"',
        'site:{t} "stack trace" OR "stacktrace"',
        'site:{t} "warning: mysql"',
        'site:{t} "Error establishing a database connection"',
        'site:{t} "Whitelabel Error Page"',
    ],
    "configs": [
        'site:{t} ext:env',
        'site:{t} ext:yml OR ext:yaml',
        'site:{t} inurl:.git',
        'site:{t} inurl:wp-config.php',
        'site:{t} ".htaccess"',
        'site:{t} "DB_PASSWORD"',
    ],
    "discovery": [
        'site:{t}',
        'site:*.{t} -www',
        'site:{t} inurl:test OR inurl:dev OR inurl:staging',
        'site:{t} intitle:"index of"',
        'site:{t} inurl:beta',
    ],
    "archives": [
        'site:web.archive.org/web/* "{t}"',
        'site:archive.org "{t}"',
        'site:cachedview.com "{t}"',
    ],
}


class GenerateBody(BaseModel):
    target: str = Field(..., min_length=1)
    categories: list[str] = Field(default_factory=lambda: list(CATEGORIES.keys()))
    execute: bool = False
    confirm: bool = False


@router.get("/categories")
def categories() -> dict[str, Any]:
    return {"categories": [{"id": k, "count": len(v)} for k, v in CATEGORIES.items()]}


@router.get("/status")
def status() -> dict[str, Any]:
    cse_key = keychain_get_named("google_cse_api_key")
    cse_id  = keychain_get_named("google_cse_id")
    return {
        "cse_configured": bool(cse_key and cse_id),
    }


def _dorks_for(target: str, picked: list[str]) -> list[dict[str, str]]:
    target = target.strip().lower()
    out: list[dict[str, str]] = []
    for cat in picked:
        if cat not in CATEGORIES:
            continue
        for tmpl in CATEGORIES[cat]:
            q = tmpl.replace("{t}", target)
            out.append({
                "category": cat,
                "query": q,
                "url": f"https://www.google.com/search?q={quote_plus(q)}",
            })
    return out


@router.post("/generate")
async def generate(body: GenerateBody, request: Request) -> dict[str, Any]:
    target = validate_domain(body.target, field="target")
    # Generating dork *strings* is passive; only enforce on the execute path.
    # In Engagement mode we still verify the engagement is valid so the user
    # can't accidentally craft dorks against an out-of-scope target.
    scope.enforce_rest(
        target, get_engagement_id(request), get_mode(request),
        confirm=body.confirm, deny_only=not body.execute,
    )
    dorks = _dorks_for(target, body.categories)
    if not body.execute:
        return {"dorks": dorks, "executed": False}

    cse_key = keychain_get_named("google_cse_api_key")
    cse_id  = keychain_get_named("google_cse_id")
    if not (cse_key and cse_id):
        raise HTTPException(
            401,
            "Google CSE not configured — set both `google_cse_api_key` and `google_cse_id` "
            "via POST /settings/keys, or run with execute=false to just generate dork URLs.",
        )

    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=15.0, headers={"User-Agent": UA},
    ) as client:
        for d in dorks:
            try:
                r = await client.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={
                        "key":  cse_key,
                        "cx":   cse_id,
                        "q":    d["query"],
                        "num":  10,
                    },
                )
                if r.status_code == 429 or r.status_code == 403:
                    # Quota exceeded — bail rather than burn through it
                    results.append({**d, "items": [], "error": f"CSE quota: {r.status_code}"})
                    break
                if not r.is_success:
                    results.append({**d, "items": [], "error": f"HTTP {r.status_code}"})
                    continue
                data = r.json()
                items = [
                    {"title": it.get("title", ""), "link": it.get("link", ""),
                     "snippet": it.get("snippet", "")}
                    for it in data.get("items", [])
                ]
                results.append({**d, "items": items})
            except Exception:
                logger.exception("dorking CSE call failed query=%r", d.get("query", ""))
                results.append({**d, "items": [], "error": "request failed"})

    return {"dorks": results, "executed": True}


# ── /osint/dorks/{domain} alias ─────────────────────────────────────────────
# Wraps the existing CATEGORIES into the spec'd shape (with per-engine
# search URLs) so the new "Dork Generator" OSINT page can talk to one
# stable endpoint rather than chaining /dorking/categories + /generate.

_DORK_DESCRIPTIONS: dict[str, str] = {
    "files":     "Public documents (PDF, XLSX, SQL, backups).",
    "admin":     "Admin panels and login pages.",
    "leaks":     "Exposed credentials, secrets, private keys.",
    "errors":    "Server errors that may leak stack traces.",
    "configs":   "Exposed config/.env/.git/yml/htaccess.",
    "discovery": "Subdomains and dev/staging endpoints.",
    "archives":  "Archived / cached copies (Wayback, archive.org).",
}


@osint_router.get("/osint/dorks/{domain}")
async def osint_dorks(domain: str, request: Request) -> dict[str, Any]:
    """Generate dork strings + per-engine search URLs for the target."""
    target = validate_domain(domain, field="domain")
    # Passive — generates strings only, no outbound calls. Engagement mode
    # still requires a valid active engagement so out-of-scope dorks can't
    # be enumerated without an authorized scope.
    scope.enforce_rest(
        target, get_engagement_id(request), get_mode(request), deny_only=True,
    )
    dorks: list[dict[str, str]] = []
    for cat, tmpls in CATEGORIES.items():
        for tmpl in tmpls:
            q = tmpl.replace("{t}", target)
            dorks.append({
                "category":    cat,
                "dork":        q,
                "description": _DORK_DESCRIPTIONS.get(cat, ""),
            })
    # Per-engine URL templates — populated once with the first dork query;
    # the frontend re-renders these for each item by replacing the URL prefix.
    return {
        "domain":     target,
        "count":      len(dorks),
        "dorks":      dorks,
        "engines": {
            "google":     "https://www.google.com/search?q=",
            "bing":       "https://www.bing.com/search?q=",
            "duckduckgo": "https://duckduckgo.com/?q=",
        },
    }
