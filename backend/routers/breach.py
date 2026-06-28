"""Breach data lookup — HaveIBeenPwned (HIBP).

Two endpoints:

  - POST /breach/password — Pwned Passwords k-anonymity range check.
    *Free, no API key.* We send only the first 5 chars of the SHA-1 hash;
    HIBP returns all matching suffixes with counts. We compare the tail
    locally so the full password (and full hash) never leaves the machine.

  - GET /breach/email/{email} — breached-account lookup.
    *Requires `hibp_api_key` from Keychain*, paid ($3.95/month for HIBP API).
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, Request

from lib import scope
from lib.auth import require_local_auth
from pydantic import BaseModel, Field

from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode

from .settings import keychain_get_named

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/breach", tags=["breach"],
                   dependencies=[Depends(require_local_auth)])

# Reasonable cap so a runaway password value can't blow through hashing
# memory. Anything past 1024 chars is almost certainly junk.
_MAX_PASSWORD_LEN = 1024
_MAX_EMAIL_LEN = 254  # RFC 5321 max local+domain

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
PWND_PWD_BASE = "https://api.pwnedpasswords.com"
UA = "HackingPal/0.1 breach-lookup"


class PasswordCheck(BaseModel):
    password: str = Field(..., min_length=1, max_length=_MAX_PASSWORD_LEN)


@router.post("/password")
async def password_check(body: PasswordCheck) -> dict[str, Any]:
    """k-anonymity: SHA-1 the password, send first 5 chars, compare tail locally.

    No API key needed. The full password never crosses the network.
    """
    full = hashlib.sha1(body.password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = full[:5], full[5:]
    try:
        async with httpx.AsyncClient(
            timeout=10.0, headers={"User-Agent": UA, "Add-Padding": "true"},
        ) as client:
            r = await client.get(f"{PWND_PWD_BASE}/range/{prefix}")
        r.raise_for_status()
    except httpx.HTTPError as e:
        logger.warning("pwned passwords request failed: %s", e)
        raise MhpError(
            "Pwned Passwords request failed",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        ) from None

    count = 0
    for line in r.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        if parts[0].upper() == suffix:
            try:
                count = int(parts[1])
            except ValueError:
                count = 0
            break
    return {
        "pwned":  count > 0,
        "count":  count,
        "prefix": prefix,
        # We intentionally do NOT return the full hash, just to make it obvious
        # this is the k-anonymity flow.
    }


@router.get("/email/{email}")
async def email_check(email: str, request: Request,
                      truncate: bool = False) -> dict[str, Any]:
    # Strip + cap before passing into the HIBP URL. We don't run a full
    # RFC 5322 validator here because HIBP itself is the authoritative
    # validator — but rejecting obviously-malformed input early keeps
    # noisy 4xx traffic off their API.
    email = (email or "").strip()
    if not email or "@" not in email:
        raise MhpError(
            "email must contain an '@'",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )
    if len(email) > _MAX_EMAIL_LEN:
        raise MhpError(
            f"email too long (max {_MAX_EMAIL_LEN} chars)",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )

    # Scope-check the email's domain (the actual "target" of the lookup).
    # Passive — HIBP queries an archive, doesn't probe the live domain.
    email_domain = email.rsplit("@", 1)[-1].lower()
    scope.enforce_rest(
        email_domain, get_engagement_id(request), get_mode(request),
        deny_only=True,
    )

    key = keychain_get_named("hibp_api_key")
    if not key:
        raise MhpError(
            "HIBP API key not set. Add one via "
            "`POST /settings/keys/hibp_api_key` (paid, $3.95/month).",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    headers = {
        "hibp-api-key": key,
        "User-Agent":   UA,
    }
    url = f"{HIBP_BASE}/breachedaccount/{quote(email)}?truncateResponse=" \
          f"{'true' if truncate else 'false'}"
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
            r = await client.get(url)
    except httpx.HTTPError as e:
        logger.warning("HIBP request failed: %s", e)
        raise MhpError(
            "HIBP request failed",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        ) from None

    # HIBP returns 404 when the account isn't in any breach (intentional design)
    if r.status_code == 404:
        return {"email": email, "breaches": [], "count": 0}
    if r.status_code == 401:
        raise MhpError(
            "HIBP rejected the API key.",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    if r.status_code == 429:
        retry = r.headers.get("retry-after", "")
        raise MhpError(
            f"HIBP rate-limited; retry after {retry}s",
            code=ErrorCode.RATE_LIMITED,
            status_code=429,
            extra={"retry_after": retry},
        )
    if not r.is_success:
        raise MhpError(
            f"HIBP returned {r.status_code}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=r.status_code,
        )

    data = r.json()
    return {"email": email, "breaches": data, "count": len(data)}


@router.get("/domain/{domain}")
async def domain_check(domain: str) -> dict[str, Any]:
    """HIBP domain-wide breach search (paid HIBP API key required).

    Returns the full per-breach roll-up — counts of accounts exposed,
    data classes leaked, and breach timeline — so the UI can group by
    breach and show exposed data types.
    """
    d = (domain or "").strip().lower().lstrip(".")
    if not d or "." not in d:
        raise MhpError(
            "domain must contain a dot",
            code=ErrorCode.INVALID_DOMAIN,
            status_code=400,
        )

    key = keychain_get_named("hibp_api_key")
    if not key:
        raise MhpError(
            "HIBP API key not set. Add one via "
            "`POST /settings/keys/hibp_api_key` (paid, $3.95/month).",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    headers = {"hibp-api-key": key, "User-Agent": UA}
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
            r = await client.get(f"{HIBP_BASE}/breaches/domain/{quote(d)}")
    except httpx.HTTPError as e:
        logger.warning("HIBP domain request failed: %s", e)
        raise MhpError(
            "HIBP request failed",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        ) from None

    if r.status_code == 404:
        return {"domain": d, "breaches": [], "count": 0}
    if r.status_code == 401:
        raise MhpError(
            "HIBP rejected the API key.",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        )
    if r.status_code == 429:
        retry = r.headers.get("retry-after", "")
        raise MhpError(
            f"HIBP rate-limited; retry after {retry}s",
            code=ErrorCode.RATE_LIMITED,
            status_code=429,
            extra={"retry_after": retry},
        )
    if not r.is_success:
        raise MhpError(
            f"HIBP returned {r.status_code}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=r.status_code,
        )
    data = r.json()
    breaches = data if isinstance(data, list) else []
    return {"domain": d, "breaches": breaches, "count": len(breaches)}


@router.get("/status")
def status() -> dict[str, Any]:
    return {
        "password_check": True,            # always available (free k-anonymity)
        "email_check_available": keychain_get_named("hibp_api_key") is not None,
        "domain_check_available": keychain_get_named("hibp_api_key") is not None,
    }
