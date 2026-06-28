"""Profile Finder — find people associated with a company across public sources.

This is the **honest** LinkedIn alternative. We do not log into LinkedIn or
hit any non-public LinkedIn API — that gets accounts banned. Instead we:

  - Generate Google dorks that surface LinkedIn / X / GitHub / company-website
    profiles for the target company.
  - If `google_cse_api_key` + `google_cse_id` are in Keychain, execute the
    dorks via CSE and extract `{name, title, source_url}` from result
    snippets/titles.
  - Optionally cross-reference with /people/enum's email-pattern inference
    to suggest plausible emails for each discovered name.

The frontend always shows the dork URLs (clickable) regardless of whether CSE
is configured — so the user can fall back to manual browsing.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Depends, Request

from lib import scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode
from pydantic import BaseModel, Field

from lib.errors import MhpError
from lib.validators import validate_domain
from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/profile-finder", tags=["profile-finder"],
                   dependencies=[Depends(require_local_auth)])

UA = "HackingPal/0.1 profile-finder"

# Per-source dork templates. {c} = company name, {d} = domain (optional).
SOURCES: list[dict[str, Any]] = [
    {
        "id": "linkedin", "label": "LinkedIn profiles",
        "templates": [
            'site:linkedin.com/in "{c}"',
            'site:linkedin.com/in "{c}" "{d}"',
        ],
    },
    {
        "id": "linkedin-company", "label": "LinkedIn company page + jobs",
        "templates": [
            'site:linkedin.com/company "{c}"',
            'site:linkedin.com/jobs "{c}"',
        ],
    },
    {
        "id": "github", "label": "GitHub profiles & orgs",
        "templates": [
            'site:github.com "{c}"',
            '"{c}" "@{d}" site:github.com',
        ],
    },
    {
        "id": "x", "label": "X (Twitter) profiles",
        "templates": [
            'site:x.com "{c}"',
            'site:twitter.com "{c}"',
        ],
    },
    {
        "id": "company-team", "label": '"Team / About" pages on the company site',
        "templates": [
            'site:{d} "team" OR "about us" OR "leadership"',
            'site:{d} inurl:team OR inurl:about OR inurl:leadership',
        ],
    },
]


# Heuristic: "Name - Title at Company | LinkedIn" → ("Name", "Title at Company")
LINKEDIN_TITLE_RE = re.compile(
    r"^(?P<name>[A-Z][\w'.-]+(?:\s+[A-Z][\w'.-]+){1,4})\s*[-–|·]\s*(?P<title>.{3,200}?)(?:\s*\|\s*LinkedIn)?$",
    re.MULTILINE,
)


class FindBody(BaseModel):
    company: str = Field(..., min_length=1, max_length=200)
    domain: str = Field(default="", max_length=253)
    sources: list[str] = Field(default_factory=lambda: [s["id"] for s in SOURCES], max_length=32)
    execute: bool = False
    confirm: bool = False


def _build_dorks(company: str, domain: str, picked: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for source in SOURCES:
        if source["id"] not in picked:
            continue
        for tmpl in source["templates"]:
            # Skip templates that reference {d} when no domain provided
            if "{d}" in tmpl and not domain:
                continue
            q = tmpl.replace("{c}", company).replace("{d}", domain)
            out.append({
                "source": source["id"],
                "label":  source["label"],
                "query":  q,
                "url":    f"https://www.google.com/search?q={quote_plus(q)}",
            })
    return out


def _parse_profile(title: str, snippet: str, url: str, source: str) -> dict[str, str] | None:
    """Try to extract {name, title} from a search result. Returns None if we
    can't identify a person."""
    if source.startswith("linkedin"):
        # LinkedIn titles look like "Name - Title at Company | LinkedIn"
        m = LINKEDIN_TITLE_RE.match(title.strip())
        if m:
            return {"name": m.group("name").strip(),
                    "title": m.group("title").strip(),
                    "url": url, "source": source}
    if source == "github":
        # GitHub profile titles look like "Name (handle)" or "handle - Overview"
        m = re.match(r"^([A-Z][\w'.-]+(?:\s+[A-Z][\w'.-]+){1,3})\s*\(([^)]+)\)", title.strip())
        if m:
            return {"name": m.group(1).strip(),
                    "title": f"GitHub: {m.group(2).strip()}",
                    "url": url, "source": source}
    # Fallback: try snippet first line if it starts with a name-like token
    first = (snippet or "").split("\n")[0]
    m = re.match(r"^([A-Z][\w'.-]+(?:\s+[A-Z][\w'.-]+){1,4})\s*[-–|·]\s*(.+)", first)
    if m and 3 < len(m.group(2)) < 200:
        return {"name": m.group(1).strip(),
                "title": m.group(2).strip()[:200],
                "url": url, "source": source}
    return None


def _name_to_locals(name: str) -> list[str]:
    """Given 'Jane Doe', return [jane.doe, jdoe, janed, jane_doe, doej, jane]"""
    parts = [p.lower() for p in re.split(r"\s+", name.strip()) if p]
    if len(parts) < 2:
        return [parts[0]] if parts else []
    first, last = parts[0], parts[-1]
    return list(dict.fromkeys([        # ordered-dedupe
        f"{first}.{last}",  f"{first[0]}{last}",  f"{first}{last[0]}",
        f"{first}_{last}",  f"{last}{first[0]}",  first,
    ]))


PATTERN_TO_LOCAL = {
    "first.last":  lambda f, l: f"{f}.{l}",
    "first_last":  lambda f, l: f"{f}_{l}",
    "first-last":  lambda f, l: f"{f}-{l}",
    "initials":    lambda f, l: f"{f[0]}{l[0]}",
    "flast or first": lambda f, l: f"{f[0]}{l}",
    "other":       lambda f, l: f"{f}.{l}",
}


def _guess_email(name: str, domain: str, pattern: str | None) -> str | None:
    if not domain:
        return None
    parts = [p.lower() for p in re.split(r"\s+", name.strip()) if p]
    if len(parts) < 2:
        return None
    first, last = parts[0], parts[-1]
    if pattern and pattern in PATTERN_TO_LOCAL:
        return f"{PATTERN_TO_LOCAL[pattern](first, last)}@{domain}"
    return f"{first}.{last}@{domain}"   # default


@router.post("/find")
async def find(body: FindBody, request: Request) -> dict[str, Any]:
    company = body.company.strip()
    raw_domain = body.domain.strip().lower().lstrip("@")
    if raw_domain:
        domain = validate_domain(raw_domain, field="domain")
    else:
        domain = ""
    # Scope-check on the domain when provided. When only the company name
    # is supplied (no domain), fall back to scope-checking the company
    # string itself — engagement scope of "acme" will match, scope of
    # "*.acme.com" will not (by design, same trade-off as s3_scanner).
    scope_target = domain or company.lower()
    # Generating dork strings is passive; executing them via CSE is active.
    scope.enforce_rest(
        scope_target, get_engagement_id(request), get_mode(request),
        confirm=body.confirm, deny_only=not body.execute,
    )
    picked = set(body.sources)
    dorks = _build_dorks(company, domain, picked)

    cse_key = keychain_get_named("google_cse_api_key")
    cse_id  = keychain_get_named("google_cse_id")
    will_execute = body.execute and cse_key and cse_id

    profiles: list[dict[str, Any]] = []
    if will_execute:
        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": UA}) as client:
            for d in dorks:
                try:
                    r = await client.get(
                        "https://www.googleapis.com/customsearch/v1",
                        params={"key": cse_key, "cx": cse_id, "q": d["query"], "num": 10},
                    )
                except Exception as e:
                    logger.info("profile_finder CSE request failed: %s", type(e).__name__)
                    d["error"] = f"CSE request failed: {type(e).__name__}"
                    continue
                if r.status_code in (403, 429):
                    d["error"] = f"CSE quota: {r.status_code}"
                    break
                if not r.is_success:
                    d["error"] = f"HTTP {r.status_code}"
                    continue
                data = r.json()
                d["item_count"] = len(data.get("items", []))
                for it in data.get("items", []):
                    parsed = _parse_profile(
                        it.get("title", ""), it.get("snippet", ""),
                        it.get("link", ""), d["source"],
                    )
                    if parsed:
                        profiles.append(parsed)

    # Dedupe by (name, source)
    seen: set[tuple[str, str]] = set()
    unique_profiles: list[dict[str, Any]] = []
    for p in profiles:
        key = (p["name"].lower(), p["source"])
        if key in seen:
            continue
        seen.add(key)
        unique_profiles.append(p)

    # Optional email guessing: use people_enum pattern if available
    email_guesses: list[dict[str, str]] = []
    if domain and unique_profiles:
        pattern = None
        try:
            # Best-effort: call our own people_enum to infer pattern
            from . import people_enum
            r = await people_enum.enum(people_enum.EnumBody(
                target=domain, sources=["duckduckgo", "crtsh", "hackertarget"],
            ))
            pattern = (r.get("pattern_guess") or {}).get("pattern")
        except Exception:
            pattern = None
        for p in unique_profiles[:50]:
            guess = _guess_email(p["name"], domain, pattern)
            if guess:
                email_guesses.append({"name": p["name"], "email": guess,
                                      "pattern": pattern or "first.last (default)"})

    return {
        "dorks":   dorks,
        "executed": bool(will_execute),
        "profiles": unique_profiles,
        "email_guesses": email_guesses,
        "cse_configured": bool(cse_key and cse_id),
    }
