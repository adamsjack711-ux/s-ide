"""Shodan + Censys query proxies.

Two services, one router, normalized result rows. Both APIs use very different
schemas — we flatten to a common `{ip, port, service, banner, country, org,
hostnames, raw}` row so the frontend can render a single table.

Auth:
  - Shodan:  `shodan_api_key` in Keychain (we already have this).
  - Censys:  `censys_api_id` + `censys_api_secret` (HTTP Basic).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request

from lib import scope
from lib.auth import require_local_auth

from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from pydantic import BaseModel, Field

from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/shodan-censys", tags=["shodan-censys"],
                   dependencies=[Depends(require_local_auth)])

UA = "s-ide/0.1 shodan-censys"


@router.get("/status")
def status() -> dict[str, Any]:
    return {
        "shodan_configured": bool(keychain_get_named("shodan_api_key")),
        "censys_configured": bool(
            keychain_get_named("censys_api_id") and keychain_get_named("censys_api_secret")
        ),
    }


class QueryBody(BaseModel):
    service: str = Field(..., pattern="^(shodan|censys)$")
    query: str = Field(..., min_length=1, max_length=2000)
    limit: int = Field(default=25, ge=1, le=100)
    page: int = Field(default=1, ge=1, le=20)


@router.post("/query")
async def query(body: QueryBody, request: Request) -> dict[str, Any]:
    # Shodan/Censys queries are arbitrary search strings (`port:22`, `org:Acme`,
    # bare IPs) — no single target to scope-match. Require an active engagement
    # under Engagement mode so the recon is attributable; Lab mode passes through.
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    if body.service == "shodan":
        return await _shodan(body.query, body.limit, body.page)
    return await _censys(body.query, body.limit, body.page)


async def _shodan(q: str, limit: int, page: int) -> dict[str, Any]:
    key = keychain_get_named("shodan_api_key")
    if not key:
        raise MhpError(
            "shodan_api_key not configured",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    async with httpx.AsyncClient(
        timeout=20.0, headers={"User-Agent": UA},
    ) as client:
        r = await client.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": q, "limit": limit, "page": page},
        )
    if r.status_code == 401:
        raise MhpError(
            "Shodan rejected the API key",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    if not r.is_success:
        try:
            detail = r.json().get("error", r.text[:200])
        except Exception:
            detail = r.text[:200]
        raise MhpError(
            f"Shodan {r.status_code}: {detail}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=r.status_code if 400 <= r.status_code < 600 else 502,
        )

    data = r.json()
    rows: list[dict[str, Any]] = []
    for m in data.get("matches", []):
        rows.append({
            "ip":        m.get("ip_str", ""),
            "port":      m.get("port"),
            "service":   m.get("_shodan", {}).get("module", "") or m.get("product", ""),
            "banner":    (m.get("data") or "")[:600],
            "country":   m.get("location", {}).get("country_code", ""),
            "org":       m.get("org", ""),
            "hostnames": m.get("hostnames", []),
            "timestamp": m.get("timestamp", ""),
        })
    return {
        "service": "shodan", "query": q, "total": data.get("total", 0),
        "rows": rows,
    }


async def _censys(q: str, limit: int, page: int) -> dict[str, Any]:
    api_id = keychain_get_named("censys_api_id")
    secret = keychain_get_named("censys_api_secret")
    if not (api_id and secret):
        raise MhpError(
            "censys_api_id + censys_api_secret not configured",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )

    # Censys uses cursor-based pagination, not pages — we'll just fetch the
    # first page (most useful). `limit` maps to per_page.
    async with httpx.AsyncClient(
        timeout=20.0, headers={"User-Agent": UA, "Accept": "application/json"},
        auth=(api_id, secret),
    ) as client:
        r = await client.post(
            "https://search.censys.io/api/v2/hosts/search",
            json={"q": q, "per_page": min(limit, 100)},
        )
    if r.status_code == 401:
        raise MhpError(
            "Censys rejected the API id/secret",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    if not r.is_success:
        try:
            detail = r.json().get("error", r.text[:200])
        except Exception:
            detail = r.text[:200]
        raise MhpError(
            f"Censys {r.status_code}: {detail}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=r.status_code if 400 <= r.status_code < 600 else 502,
        )

    data = r.json().get("result", {})
    rows: list[dict[str, Any]] = []
    for h in data.get("hits", []):
        services = h.get("services", []) or []
        ip = h.get("ip", "")
        country = h.get("location", {}).get("country_code", "")
        org = (h.get("autonomous_system") or {}).get("name", "")
        if not services:
            rows.append({"ip": ip, "port": None, "service": "", "banner": "",
                         "country": country, "org": org, "hostnames": h.get("names", [])})
            continue
        for s in services[:10]:  # cap to avoid massive row explosions
            rows.append({
                "ip": ip,
                "port": s.get("port"),
                "service": s.get("service_name", ""),
                "banner": (s.get("banner") or "")[:600],
                "country": country,
                "org": org,
                "hostnames": h.get("names", []),
                "transport": s.get("transport_protocol", ""),
            })
    return {
        "service": "censys", "query": q,
        "total": data.get("total", len(rows)),
        "rows": rows,
    }
