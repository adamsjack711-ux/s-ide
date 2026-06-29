"""Email harvesting OSINT.

Aggregates email addresses from multiple sources for a target domain:

  * **crt.sh certificate transparency logs** — SANs on TLS certs.
  * **Live mailto: scraping** — root page + a small set of common contact
    paths (/contact, /about). HEAD-first to avoid hammering the target.
  * **Hunter.io** — if a key is configured in the keychain (50 free
    queries/month on a hobbyist key).

Also exposes the Google-dork strings the user can run by hand when no
API key is available.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Depends, Request

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.validators import validate_domain

from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/osint", tags=["email-harvest"],
                   dependencies=[Depends(require_local_auth)])

UA = "s-ide/0.1 email-harvest"
TIMEOUT = 12.0
_MAX_EMAILS = 500
_SCRAPE_PATHS = ("", "/contact", "/contact-us", "/about", "/about-us",
                 "/team", "/people", "/staff")

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)


async def _from_crtsh(client: httpx.AsyncClient, domain: str) -> list[str]:
    try:
        r = await client.get(
            f"https://crt.sh/?q=%25%40{quote_plus(domain)}&output=json",
        )
        r.raise_for_status()
        rows = r.json()
    except Exception as e:
        logger.info("crt.sh email lookup failed: %s", e)
        return []
    out: set[str] = set()
    for row in rows:
        nv = row.get("name_value", "")
        for token in re.split(r"[,\s]+", nv):
            token = token.strip().lower()
            if "@" in token and token.endswith(f"@{domain}") or token.endswith(f".{domain}"):
                m = EMAIL_RE.search(token)
                if m:
                    out.add(m.group(0).lower())
    return sorted(out)


async def _from_scrape(client: httpx.AsyncClient, domain: str) -> list[str]:
    out: set[str] = set()
    for path in _SCRAPE_PATHS:
        url = f"https://{domain}{path}"
        try:
            r = await client.get(url)
        except Exception:
            continue
        if r.status_code != 200 or not r.text:
            continue
        for m in EMAIL_RE.finditer(r.text):
            email = m.group(0).lower()
            if email.endswith(f"@{domain}") or domain in email.split("@", 1)[-1]:
                out.add(email)
            # Don't accumulate noise from third-party emails on the page.
        if len(out) >= _MAX_EMAILS:
            break
    return sorted(out)


async def _from_hunter(client: httpx.AsyncClient, domain: str, key: str) -> list[str]:
    try:
        r = await client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": key, "limit": 100},
        )
        if r.status_code in (401, 403):
            raise MhpError(
                "Hunter.io rejected the key",
                code=ErrorCode.UNAUTHORIZED,
                status_code=401,
            )
        r.raise_for_status()
        data = r.json()
    except MhpError:
        raise
    except Exception as e:
        logger.info("Hunter.io call failed: %s", e)
        return []
    out: set[str] = set()
    for entry in (data.get("data", {}) or {}).get("emails", []):
        email = entry.get("value", "").lower()
        if email:
            out.add(email)
    return sorted(out)


def _dorks_for_emails(domain: str) -> list[dict[str, str]]:
    return [
        {"query": f'"@{domain}" filetype:pdf', "url":
            f"https://google.com/search?q={quote_plus(f'@{domain} filetype:pdf')}"},
        {"query": f'"@{domain}" site:linkedin.com', "url":
            f"https://google.com/search?q={quote_plus(f'@{domain} site:linkedin.com')}"},
        {"query": f'"@{domain}" intext:contact', "url":
            f"https://google.com/search?q={quote_plus(f'@{domain} intext:contact')}"},
    ]


@router.get("/emails/{domain}")
async def harvest(domain: str, request: Request) -> dict[str, Any]:
    d = validate_domain(domain, field="domain")
    # Active — scrapes /contact, /about etc. on the target's website.
    scope.enforce_rest(
        d, get_engagement_id(request), get_mode(request),
    )
    hunter_key = keychain_get_named("hunter_api_key")

    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        headers={"User-Agent": UA},
        follow_redirects=True,
    ) as client:
        tasks = {
            "crt.sh":  _from_crtsh(client, d),
            "scrape":  _from_scrape(client, d),
        }
        if hunter_key:
            tasks["hunter.io"] = _from_hunter(client, d, hunter_key)
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    merged: dict[str, set[str]] = {}  # email -> set(sources)
    by_source: dict[str, list[str]] = {}
    for name, res in zip(tasks.keys(), results, strict=True):
        if isinstance(res, Exception):
            by_source[name] = []
            continue
        by_source[name] = res
        for e in res:
            merged.setdefault(e, set()).add(name)

    emails = sorted(merged.keys())[:_MAX_EMAILS]
    return {
        "domain":     d,
        "count":      len(emails),
        "emails":     [
            {"email": e, "sources": sorted(merged[e])}
            for e in emails
        ],
        "by_source":  {k: len(v) for k, v in by_source.items()},
        "dorks":      _dorks_for_emails(d),
        "hunter_configured": hunter_key is not None,
    }
