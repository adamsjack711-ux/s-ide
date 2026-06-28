"""Certificate Transparency log search via crt.sh.

REST  GET /ct/search/{domain}?confirm=true

Pulls all certs ever issued under {domain} from crt.sh. Each CT log entry has
a name_value field (potentially newline-separated multi-SAN); we flatten +
dedupe to produce a clean subdomain list. Often surfaces subdomains a
wordlist enum would never find (CI build hosts, internal-by-name services,
etc.).

Response shape:
  {
    "domain": "...",
    "total_records": int,        # from crt.sh
    "subdomains": ["a.x.com", ...],
    "wildcard_subdomains": ["*.foo.x.com", ...],
    "recent_certs": [
       { "name": "...", "issuer": "...", "not_before": "...", "not_after": "..." }, ...
    ],
    "findings": [...],
    "policy": { ... }
  }
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any
from urllib import parse as urlparse, request as urlrequest
from urllib.error import HTTPError, URLError

from fastapi import APIRouter, HTTPException, Query, Request

from lib import hids_notify, scope
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.target_policy import check_target
from lib.validators import validate_domain

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ct-log"])

CRT_SH = "https://crt.sh/"

# Small in-memory cache so the user clicking "Search" twice in a row doesn't
# hammer crt.sh. Key = domain, value = (timestamp, records, throttled).
_CACHE: dict[str, tuple[float, list[dict[str, Any]], bool]] = {}
_CACHE_TTL = 60.0


def _fetch_crtsh(domain: str, timeout: float = 60.0, retries: int = 2) -> tuple[list[dict[str, Any]], bool]:
    # crt.sh treats '%' as SQL-style wildcard. urlencode will URL-encode the
    # literal '%' for us — DO NOT pre-encode (urlencode would double-encode).
    q = "%." + domain
    url = f"{CRT_SH}?{urlparse.urlencode({'q': q, 'output': 'json'})}"
    req = urlrequest.Request(url, headers={
        "User-Agent": "network-tools/0.1 (+ct-search)",
        "Accept": "application/json",
    })
    cached = _CACHE.get(domain)
    if cached and time.time() - cached[0] < _CACHE_TTL:
        return cached[1], cached[2]

    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urlrequest.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
            records = json.loads(body)
            _CACHE[domain] = (time.time(), records, False)
            return records, False
        except HTTPError as exc:
            last_err = exc
            # 5xx is transient — retry. 4xx is not.
            if exc.code < 500 or attempt == retries:
                if exc.code in (502, 504):
                    # Throttle / no-results case. Cache short-term to back off.
                    _CACHE[domain] = (time.time(), [], True)
                    return [], True
                raise
            time.sleep(0.6 * (attempt + 1))
        except (TimeoutError, OSError) as exc:
            last_err = exc
            if attempt == retries:
                raise
            time.sleep(0.6 * (attempt + 1))
    if last_err is None:
        raise RuntimeError("ct_log retry loop exited without success or error")
    raise last_err


def _parse_dt(s: str) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@router.get("/ct/search/{domain}")
async def ct_search(domain: str, request: Request,
                    confirm: bool = Query(default=False)) -> dict[str, Any]:
    domain = validate_domain(domain)

    verdict, reason, _ = scope.enforce_rest(
        domain, get_engagement_id(request), get_mode(request), confirm=confirm,
    )

    t0 = time.monotonic()
    throttled = False
    try:
        records, throttled = await asyncio.to_thread(_fetch_crtsh, domain)
    except HTTPError as exc:
        raise MhpError(
            f"crt.sh HTTP {exc.code}: {exc.reason}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        )
    except URLError as exc:
        raise MhpError(
            f"crt.sh unreachable: {exc.reason}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        )
    except json.JSONDecodeError:
        raise MhpError(
            "crt.sh returned non-JSON",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        )
    except (TimeoutError, OSError):
        logger.exception("crt.sh fetch failed domain=%r", domain)
        raise MhpError(
            "crt.sh timed out",
            code=ErrorCode.TIMEOUT,
            status_code=504,
        )

    # Flatten name_value (may contain multiple names separated by newline)
    subs: set[str] = set()
    wildcards: set[str] = set()
    for r in records:
        for name in (r.get("name_value", "") or "").split("\n"):
            name = name.strip().lower().rstrip(".")
            if not name:
                continue
            if not name.endswith(domain) and name != domain:
                continue   # crt.sh sometimes returns matches outside the query
            if "*" in name:
                wildcards.add(name)
            else:
                subs.add(name)

    sub_list = sorted(subs)
    wild_list = sorted(wildcards)

    # Recent certs: the 10 most recently issued
    by_not_before = sorted(
        records, key=lambda r: r.get("not_before", ""), reverse=True
    )[:10]
    recent = [
        {
            "name": r.get("common_name", ""),
            "issuer": r.get("issuer_name", ""),
            "not_before": r.get("not_before", ""),
            "not_after": r.get("not_after", ""),
        }
        for r in by_not_before
    ]

    # Cert burst: issued in last 7 days
    cutoff = datetime.now(timezone.utc).timestamp() - 7 * 86400
    recent_count = sum(
        1 for r in records
        if (d := _parse_dt(r.get("not_before", ""))) and d.timestamp() > cutoff
    )

    findings: list[dict[str, Any]] = []
    if len(sub_list) > 500:
        findings.append({"severity": "info",
                         "label": "Large attack surface",
                         "detail": f"{len(sub_list)} unique subdomains in CT logs"})
    if wild_list:
        findings.append({"severity": "info",
                         "label": "Wildcard certs present",
                         "detail": f"{len(wild_list)} wildcard SAN(s) issued"})
    if recent_count > 20:
        findings.append({"severity": "warn",
                         "label": "Recent cert issuance burst",
                         "detail": f"{recent_count} certs in the last 7 days"})
    if len(records) == 0:
        if throttled:
            findings.append({"severity": "warn",
                             "label": "crt.sh throttled",
                             "detail": "Got HTTP 502 from crt.sh. Result cached for 60s. "
                                       "Try again in a minute, or use a different network."})
        else:
            findings.append({"severity": "info",
                             "label": "No CT records",
                             "detail": "No publicly-logged certs for this domain"})

    elapsed = round(time.monotonic() - t0, 2)
    await hids_notify.notify(
        "info", "ct-log",
        f"CT search — {domain}: {len(sub_list)} subdomains, {len(records)} certs",
        {"domain": domain, "subdomain_count": len(sub_list),
         "cert_count": len(records), "elapsed_seconds": elapsed},
    )

    return {
        "domain": domain,
        "total_records": len(records),
        "subdomains": sub_list,
        "wildcard_subdomains": wild_list,
        "recent_certs": recent,
        "recent_7d_count": recent_count,
        "elapsed_seconds": elapsed,
        "throttled": throttled,
        "findings": findings,
        "policy": {"verdict": verdict, "reason": reason},
    }
