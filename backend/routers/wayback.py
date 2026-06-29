"""Wayback Machine OSINT — historical URL discovery via the CDX API.

The Internet Archive's CDX endpoint is free, no-auth, and supports prefix
queries with `url=*.{domain}`. We pull a capped set of unique URLs and
categorise the interesting ones (JS bundles, API endpoints, exposed
configs, backups) so the UI can surface them without the user scrolling
a 5000-row table.

Two endpoints:

  * GET /wayback/urls/{domain}  — bucket the archive's historical URLs.
  * GET /wayback/diff/{domain}  — flag URLs gone-but-not-forgotten vs.
                                  new since 6 months ago.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Query, Request

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.validators import validate_domain

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/wayback", tags=["wayback"],
                   dependencies=[Depends(require_local_auth)])

UA = "s-ide/0.1 wayback"
TIMEOUT = 30.0
CDX_URL = "https://web.archive.org/cdx/search/cdx"
_HARD_LIMIT = 5000


# Patterns the UI surfaces in the "interesting" tray.
_INTERESTING_PATTERNS = (
    re.compile(r"\.(zip|tar\.gz|tgz|7z|rar|bak|old|backup|swp|orig)$", re.IGNORECASE),
    re.compile(r"\.(sql|db|sqlite|dump)$", re.IGNORECASE),
    re.compile(r"\.(env|conf|config|ini|yml|yaml)$", re.IGNORECASE),
    re.compile(r"/\.git/", re.IGNORECASE),
    re.compile(r"/\.svn/", re.IGNORECASE),
    re.compile(r"/\.DS_Store", re.IGNORECASE),
    re.compile(r"/(?:admin|administrator|wp-admin|phpmyadmin|adminer)\b", re.IGNORECASE),
    re.compile(r"/(?:debug|trace|console)\b", re.IGNORECASE),
)
_JS_PATTERN  = re.compile(r"\.js(\?|$)", re.IGNORECASE)
_API_PATTERN = re.compile(r"/api/|/v\d+/|\.json(\?|$)|\.xml(\?|$)|/graphql\b", re.IGNORECASE)


async def _fetch_cdx(domain: str, from_: str = "", to: str = "",
                     limit: int = _HARD_LIMIT) -> list[str]:
    params: dict[str, Any] = {
        "url":      f"*.{domain}/*",
        "output":   "json",
        "fl":       "original",
        "collapse": "urlkey",
        "limit":    min(limit, _HARD_LIMIT),
    }
    if from_:
        params["from"] = from_
    if to:
        params["to"] = to
    async with httpx.AsyncClient(
        timeout=TIMEOUT, headers={"User-Agent": UA},
        follow_redirects=True,
    ) as client:
        try:
            r = await client.get(CDX_URL, params=params)
        except httpx.HTTPError as e:
            # Some httpx exception classes (Timeout, ConnectError) have an
            # empty str(). Surface the class name so the UI can show a
            # useful "Timeout" instead of bare "Wayback CDX request failed:".
            detail = str(e) or type(e).__name__
            raise MhpError(
                f"Wayback CDX request failed: {detail}",
                code=ErrorCode.UPSTREAM_FAILED,
                status_code=502,
            ) from None
    if not r.is_success:
        raise MhpError(
            f"Wayback CDX returned {r.status_code}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        )
    try:
        data = r.json()
    except Exception:
        return []
    # First row is a header — strip it. Remaining rows are single-element
    # arrays because we asked for `fl=original` only.
    rows = data[1:] if data and isinstance(data[0], list) else data
    out: list[str] = []
    seen: set[str] = set()
    for row in rows:
        url = row[0] if isinstance(row, list) and row else str(row)
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _bucket(urls: list[str]) -> dict[str, Any]:
    interesting: list[str] = []
    js_files:    list[str] = []
    api_eps:     list[str] = []
    for u in urls:
        if any(p.search(u) for p in _INTERESTING_PATTERNS):
            interesting.append(u)
        if _JS_PATTERN.search(u):
            js_files.append(u)
        if _API_PATTERN.search(u):
            api_eps.append(u)
    return {
        "interesting":   interesting[:500],
        "js_files":      js_files[:500],
        "api_endpoints": api_eps[:500],
    }


@router.get("/urls/{domain}")
async def urls(
    domain: str,
    request: Request,
    limit: int = Query(_HARD_LIMIT, ge=10, le=_HARD_LIMIT),
) -> dict[str, Any]:
    d = validate_domain(domain, field="domain")
    # Passive — Wayback Machine archive lookup, no live probe of the target.
    scope.enforce_rest(
        d, get_engagement_id(request), get_mode(request), deny_only=True,
    )
    all_urls = await _fetch_cdx(d, limit=limit)
    buckets = _bucket(all_urls)
    return {
        "domain": d,
        "total":  len(all_urls),
        **buckets,
        "all":    all_urls,
    }


@router.get("/diff/{domain}")
async def diff(domain: str, request: Request) -> dict[str, Any]:
    """Compare URLs seen in the last 6 months vs. those seen before that.

    "Gone but not forgotten" = ever-seen historically but not in the last
    6 months. "New" = only seen recently. Useful for finding endpoints
    the team thought they retired.
    """
    d = validate_domain(domain, field="domain")
    scope.enforce_rest(
        d, get_engagement_id(request), get_mode(request), deny_only=True,
    )
    cutoff = (datetime.utcnow() - timedelta(days=180)).strftime("%Y%m%d")
    # Two CDX calls back-to-back with the hard cap routinely hits the
    # CDX server's per-request budget. Halve the limit for the diff so
    # the pair returns within the 30s timeout.
    limit = _HARD_LIMIT // 2
    historical = await _fetch_cdx(d, to=cutoff, limit=limit)
    recent     = await _fetch_cdx(d, from_=cutoff, limit=limit)
    h_set = set(historical)
    r_set = set(recent)
    gone = sorted(h_set - r_set)
    new_ = sorted(r_set - h_set)
    return {
        "domain":            d,
        "cutoff":            cutoff,
        "historical_count":  len(historical),
        "recent_count":      len(recent),
        "gone":              gone[:1000],
        "new":               new_[:1000],
    }
