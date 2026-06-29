"""GitHub Leak Scanner — search public GitHub code for credentials referencing a target.

Uses the GitHub Code Search API (`/search/code`). A token is strongly
recommended — unauthenticated, the rate limit is 10 req/min and the search
results are quite restricted. Authenticated, you get 30 req/min and broader
results. Tokens go in Keychain as `github_token`.

We auto-generate a set of leak-finding queries combining the target with
common secret-bearing patterns ("password", "api_key", "BEGIN RSA PRIVATE KEY",
etc.). The frontend can also supply ad-hoc queries.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode

from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/github-leak", tags=["github-leak"],
                   dependencies=[Depends(require_local_auth)])

UA = "s-ide/0.1 gh-leak"
GH_BASE = "https://api.github.com"

# Each entry: (label, query-template). `{t}` is the target.
LEAK_PATTERNS: list[tuple[str, str]] = [
    ("password",         '"{t}" password'),
    ("api-key",          '"{t}" api_key'),
    ("secret",           '"{t}" secret'),
    ("token",            '"{t}" token'),
    ("aws-key",          '"{t}" "AKIA"'),
    ("private-key",      '"{t}" "BEGIN RSA PRIVATE KEY"'),
    ("ssh-key",          '"{t}" "BEGIN OPENSSH PRIVATE KEY"'),
    ("db-conn",          '"{t}" "DB_PASSWORD"'),
    ("env",              '"{t}" extension:env'),
    ("config-yaml",      '"{t}" extension:yml password'),
    ("config-json",      '"{t}" extension:json apiKey'),
    ("htpasswd",         '"{t}" extension:htpasswd'),
    ("smtp",             '"{t}" "SMTP_PASSWORD"'),
    ("jwt-secret",       '"{t}" "JWT_SECRET"'),
]


class ScanBody(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    patterns: list[str] | None = None  # subset of pattern labels, or None for all
    custom_queries: list[str] = Field(default_factory=list, max_length=20)
    per_query: int = Field(default=10, ge=1, le=30)
    confirm: bool = False


@router.get("/patterns")
def patterns() -> dict[str, Any]:
    return {"patterns": [{"label": p[0], "template": p[1]} for p in LEAK_PATTERNS]}


@router.get("/status")
def status() -> dict[str, Any]:
    token = keychain_get_named("github_token")
    return {
        "authenticated": bool(token),
        "rate_limit_hint": "30 req/min authenticated, 10 req/min unauthenticated",
    }


def _build_headers() -> dict[str, str]:
    headers = {
        "User-Agent": UA,
        "Accept": "application/vnd.github.text-match+json",
    }
    token = keychain_get_named("github_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@router.post("/search")
async def search(body: ScanBody, request: Request) -> dict[str, Any]:
    t = body.target.strip()
    if not t:
        raise MhpError("target is required", code=ErrorCode.INVALID_TARGET)
    if len(t) > 253:
        raise MhpError(
            "target is too long (max 253 chars)",
            code=ErrorCode.INVALID_TARGET,
        )
    # Reject newlines/control chars to prevent header injection into the upstream query
    if any(c in t for c in "\r\n\x00"):
        raise MhpError(
            "target contains invalid characters",
            code=ErrorCode.INVALID_TARGET,
        )

    scope.enforce_rest(
        t, get_engagement_id(request), get_mode(request), confirm=body.confirm,
    )

    chosen = body.patterns
    queries: list[tuple[str, str]] = []
    for label, tmpl in LEAK_PATTERNS:
        if chosen is None or label in chosen:
            queries.append((label, tmpl.replace("{t}", t)))
    for i, q in enumerate(body.custom_queries):
        queries.append((f"custom-{i}", q))

    results: list[dict[str, Any]] = []
    headers = _build_headers()

    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        for label, q in queries:
            try:
                r = await client.get(
                    f"{GH_BASE}/search/code",
                    params={"q": q, "per_page": body.per_query},
                )
            except httpx.HTTPError as e:
                results.append({"label": label, "query": q,
                                "items": [],
                                "error": f"HTTP error: {type(e).__name__}",
                                "code": type(e).__name__})
                continue

            if r.status_code == 403:
                # Rate-limit or auth-required. GitHub usually returns JSON
                # for these, but a hostile proxy or maintenance HTML page
                # would crash a bare r.json() — keep parsing defensive.
                try:
                    detail = (r.json() or {}).get("message", "")
                except Exception:
                    detail = (r.text or "")[:120]
                results.append({"label": label, "query": q, "items": [],
                                "error": f"GitHub 403: {detail}"})
                break  # don't keep hammering
            if r.status_code == 422:
                results.append({"label": label, "query": q, "items": [],
                                "error": "query rejected (422)"})
                continue
            if not r.is_success:
                results.append({"label": label, "query": q, "items": [],
                                "error": f"HTTP {r.status_code}"})
                continue

            try:
                data = r.json()
            except Exception:
                # GitHub returned 200 but the body wasn't JSON (rare —
                # usually a captive portal / proxy injection). Surface
                # the failure rather than crashing the loop.
                results.append({"label": label, "query": q, "items": [],
                                "error": "GitHub returned non-JSON response"})
                continue
            items = []
            for it in data.get("items", []):
                snippets: list[str] = []
                for m in it.get("text_matches", []):
                    frag = (m.get("fragment") or "").strip()
                    if frag:
                        snippets.append(frag[:400])
                items.append({
                    "name": it.get("name", ""),
                    "path": it.get("path", ""),
                    "html_url": it.get("html_url", ""),
                    "repository": {
                        "full_name": it.get("repository", {}).get("full_name", ""),
                        "html_url":  it.get("repository", {}).get("html_url", ""),
                        "stars":     it.get("repository", {}).get("stargazers_count", 0),
                    },
                    "snippets": snippets,
                })
            results.append({
                "label": label,
                "query": q,
                "items": items,
                "total_count": data.get("total_count", 0),
            })

    return {"results": results, "authenticated": "Authorization" in headers}
