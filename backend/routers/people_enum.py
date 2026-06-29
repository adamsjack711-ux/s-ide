"""People / Email Aggregator — theHarvester-style.

Aggregates emails referencing a target domain from multiple free sources:

  - **DuckDuckGo HTML scrape** — searches `"@target.com"` and extracts emails
    from result snippets. Works without an API key.
  - **crt.sh** — Certificate Transparency search; some certs have email SANs
    or contact emails in subjects (rare but high-signal when present).
  - **HackerTarget hostsearch** — DNS hosts (catches `mail.target.com`-style
    subdomains, useful for inferring email infrastructure).
  - **Hunter.io** — direct email-pattern + verified-email service. Requires
    `hunter_api_key` in Keychain (free tier: 25 searches/month).

We also do crude **email-pattern inference**: given the collected emails, we
detect the most common local-part format (e.g. `first.last`, `flast`, `first`)
so the user can predict additional valid addresses.
"""
from __future__ import annotations

import asyncio
import re
from collections import Counter
from typing import Any
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from lib import scope
from lib.mode import get_engagement_id, get_mode
from lib.validators import validate_domain

import logging

from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/people", tags=["people-enum"])

UA = "Mozilla/5.0 (Macintosh) s-ide/0.1"

EMAIL_RE = re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")


class EnumBody(BaseModel):
    target: str = Field(..., min_length=3)
    sources: list[str] = Field(
        default_factory=lambda: ["duckduckgo", "crtsh", "hackertarget", "hunter"],
    )
    confirm: bool = False


@router.get("/status")
def status() -> dict[str, Any]:
    return {
        "sources": [
            {"name": "duckduckgo",  "needs_key": False, "configured": True},
            {"name": "crtsh",       "needs_key": False, "configured": True},
            {"name": "hackertarget","needs_key": False, "configured": True},
            {"name": "hunter",      "needs_key": True,
             "configured": bool(keychain_get_named("hunter_api_key"))},
        ],
    }


@router.post("/enum")
async def enum(body: EnumBody, request: Request) -> dict[str, Any]:
    # `validate_domain` strips whitespace, enforces length (RFC 1035 cap),
    # rejects IP literals, and requires at least one dot.
    target = validate_domain(body.target, field="target")
    scope.enforce_rest(
        target, get_engagement_id(request), get_mode(request),
        confirm=body.confirm,
    )

    findings: dict[str, list[str]] = {
        "duckduckgo": [], "crtsh": [], "hackertarget": [], "hunter": [],
    }
    errors: dict[str, str] = {}

    async with httpx.AsyncClient(
        timeout=20.0, headers={"User-Agent": UA},
        follow_redirects=True,
    ) as client:
        tasks: list[asyncio.Task] = []

        async def run(name: str, coro):
            try:
                findings[name] = await coro
            except Exception as e:
                errors[name] = f"{type(e).__name__}: {e}"

        if "duckduckgo" in body.sources:
            tasks.append(asyncio.create_task(run("duckduckgo", _src_duckduckgo(client, target))))
        if "crtsh" in body.sources:
            tasks.append(asyncio.create_task(run("crtsh", _src_crtsh(client, target))))
        if "hackertarget" in body.sources:
            tasks.append(asyncio.create_task(run("hackertarget", _src_hackertarget(client, target))))
        if "hunter" in body.sources:
            key = keychain_get_named("hunter_api_key")
            if not key:
                errors["hunter"] = "hunter_api_key not configured"
                findings["hunter"] = []
            else:
                tasks.append(asyncio.create_task(run("hunter", _src_hunter(client, target, key))))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # Aggregate + dedupe (case-insensitive)
    seen: dict[str, dict[str, Any]] = {}
    for source, emails in findings.items():
        for e in emails:
            key = e.lower()
            if key in seen:
                if source not in seen[key]["sources"]:
                    seen[key]["sources"].append(source)
            else:
                seen[key] = {"email": e, "sources": [source]}

    emails = sorted(seen.values(), key=lambda x: x["email"])
    pattern_guess = _infer_pattern([e["email"] for e in emails], target)

    return {
        "target": target,
        "emails": emails,
        "by_source": {k: len(v) for k, v in findings.items()},
        "errors": errors,
        "pattern_guess": pattern_guess,
    }


# ── Sources ─────────────────────────────────────────────────────────────────

async def _src_duckduckgo(client: httpx.AsyncClient, target: str) -> list[str]:
    # DuckDuckGo's HTML endpoint — no key, no JS required.
    r = await client.get(
        "https://html.duckduckgo.com/html/",
        params={"q": f'"@{target}"'},
    )
    r.raise_for_status()
    found = set()
    for m in EMAIL_RE.finditer(r.text):
        e = m.group(1)
        if e.lower().endswith(f"@{target}") or e.lower().endswith(f".{target}"):
            found.add(e)
    return sorted(found)


async def _src_crtsh(client: httpx.AsyncClient, target: str) -> list[str]:
    r = await client.get(f"https://crt.sh/?q={quote_plus(target)}&output=json")
    r.raise_for_status()
    data = r.json()
    found = set()
    for row in data:
        # Some certs have emails in the subject CN or SANs (rare)
        for field in ("name_value", "common_name", "issuer_name"):
            v = row.get(field, "") or ""
            for m in EMAIL_RE.finditer(str(v)):
                e = m.group(1)
                if e.lower().endswith(f"@{target}"):
                    found.add(e)
    return sorted(found)


async def _src_hackertarget(client: httpx.AsyncClient, target: str) -> list[str]:
    # hostsearch gives us hostname,IP pairs. We extract any that look like
    # mail / smtp / mx / webmail subdomains as hints (returned as fake emails
    # like `mail@target.com` to signal "mail infrastructure exists").
    r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={target}")
    r.raise_for_status()
    text = r.text or ""
    if "API count exceeded" in text:
        raise RuntimeError("HackerTarget quota exceeded")
    out: set[str] = set()
    interesting_prefixes = ("mail.", "smtp.", "mx.", "mx1.", "mx2.",
                            "webmail.", "exchange.", "outlook.")
    for line in text.splitlines():
        host = line.split(",", 1)[0].strip().lower()
        if not host.endswith(target):
            continue
        for prefix in interesting_prefixes:
            if host.startswith(prefix):
                local = prefix.rstrip(".")
                out.add(f"{local}@{target}")
                break
    return sorted(out)


async def _src_hunter(client: httpx.AsyncClient, target: str, key: str) -> list[str]:
    r = await client.get(
        "https://api.hunter.io/v2/domain-search",
        params={"domain": target, "api_key": key, "limit": 100},
    )
    if r.status_code == 401:
        raise RuntimeError("Hunter.io rejected the API key")
    r.raise_for_status()
    data = (r.json() or {}).get("data", {})
    found = set()
    for entry in data.get("emails", []):
        v = entry.get("value", "")
        if v:
            found.add(v)
    return sorted(found)


# ── Pattern inference ──────────────────────────────────────────────────────

def _infer_pattern(emails: list[str], target: str) -> dict[str, Any] | None:
    locals_: list[str] = []
    for e in emails:
        if "@" not in e:
            continue
        local, _, dom = e.partition("@")
        if dom.lower() == target.lower():
            locals_.append(local)
    if len(locals_) < 2:
        return None

    counter: Counter[str] = Counter()
    for local in locals_:
        counter[_classify_local(local)] += 1
    most_common, count = counter.most_common(1)[0]
    return {
        "pattern": most_common,
        "confidence": round(count / len(locals_), 2),
        "sample_size": len(locals_),
        "all": dict(counter),
    }


def _classify_local(local: str) -> str:
    if "." in local:
        return "first.last"
    if "_" in local:
        return "first_last"
    if "-" in local:
        return "first-last"
    # heuristics on length
    if len(local) <= 4:
        return "initials"
    if local.isalpha() and local.islower() and 5 <= len(local) <= 8:
        return "flast or first"
    return "other"
