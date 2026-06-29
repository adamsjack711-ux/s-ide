"""IP Checker — blue-team triage lookup."""
from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from lib import ip_intel, scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.validators import validate_target

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ip", tags=["ip"], dependencies=[Depends(require_local_auth)])

# Separate router (no prefix collision) for Shodan InternetDB lookups so
# the path stays `/shodan/host/{ip}` per the spec instead of `/ip/shodan/...`.
shodan_router = APIRouter(
    prefix="/shodan", tags=["shodan-internetdb"],
    dependencies=[Depends(require_local_auth)],
)

_CACHE_TTL = 300.0  # 5 minutes
_CACHE: dict[str, tuple[float, "IpReport"]] = {}
_CACHE_LOCK = threading.Lock()
_BULK_MAX = 50
_BULK_WORKERS = 8

# Shodan InternetDB is no-auth but unmetered politeness asks us to cache
# (60-minute TTL — recommended by their docs).
_INTERNETDB_TTL = 3600.0
_INTERNETDB_CACHE: dict[str, tuple[float, dict]] = {}
_INTERNETDB_LOCK = threading.Lock()


class DnsblEntry(BaseModel):
    name: str
    status: str
    listed: bool


class IpReport(BaseModel):
    input: str
    ip: str
    ip_class: str
    is_internal: bool
    reverse_dns: str
    country: str | None = None
    org: str | None = None
    hosting: str | None = None
    geo_error: str | None = None
    dnsbl: list[DnsblEntry] = []
    abuse_contact: list[str] = []
    verdict_severity: str    # "clean" | "info" | "warn" | "high"
    verdict_text: str


def _classify_ip(ip: str) -> tuple[str, bool]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ("unknown", False)
    if addr.is_loopback:    return ("loopback",   True)
    if addr.is_private:     return ("private",    True)
    if addr.is_multicast:   return ("multicast",  True)
    if addr.is_link_local:  return ("link-local", True)
    if addr.is_reserved:    return ("reserved",   True)
    return ("public", False)


class BulkRequest(BaseModel):
    # Hard cap on the list length keeps a runaway client from blowing through
    # the thread pool. Per-item validation runs in the handler so we can
    # surface a precise error code (validators raising MhpError inside a
    # pydantic field_validator get wrapped into a generic ValidationError).
    targets: list[str] = Field(default_factory=list, max_length=_BULK_MAX)


class BulkResult(BaseModel):
    target: str
    ok: bool
    report: IpReport | None = None
    error: str | None = None


class BulkResponse(BaseModel):
    results: list[BulkResult]


def _cache_get(key: str) -> "IpReport | None":
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit is None:
            return None
        expires_at, report = hit
        if expires_at < time.time():
            _CACHE.pop(key, None)
            return None
        return report


def _cache_put(key: str, report: "IpReport") -> None:
    with _CACHE_LOCK:
        _CACHE[key] = (time.time() + _CACHE_TTL, report)


def _compute_report(target: str) -> IpReport:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        logger.info("ip resolve failed target=%r err=%s", target, exc)
        raise MhpError(
            f"Cannot resolve {target!r}",
            code=ErrorCode.RESOLVE_FAILED,
            status_code=404,
            extra={"target": target},
        ) from None

    ip_class, is_internal = _classify_ip(ip)

    try:
        reverse_dns = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        reverse_dns = ""

    country = org = hosting = None
    geo_error: str | None = None
    if not is_internal:
        try:
            data = json.loads(
                urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=6).read()
            )
            country = data.get("country") or None
            org     = data.get("org") or None
            hosting = ip_intel.classify_hosting(org or "") or None
        except Exception as exc:
            geo_error = str(exc)

    dnsbl: list[DnsblEntry] = []
    bl_hits = 0
    if not is_internal:
        for name, status in ip_intel.dnsbl_check_all(ip):
            listed = status.startswith("Listed")
            if listed:
                bl_hits += 1
            dnsbl.append(DnsblEntry(name=name, status=status, listed=listed))

    abuse: list[str] = []
    whois_bin = shutil.which("whois") or "/usr/bin/whois"
    try:
        proc = subprocess.run(
            [whois_bin, ip], capture_output=True, text=True, timeout=12,
        )
        abuse = ip_intel.whois_abuse_lines(proc.stdout)
    except Exception:
        pass

    if is_internal:
        severity = "info"
        verdict  = f"Internal IP ({ip_class}) — not routable on the public internet"
    elif bl_hits > 0:
        severity = "high"
        verdict  = f"Listed on {bl_hits} blocklist{'s' if bl_hits != 1 else ''} — investigate"
    elif hosting:
        severity = "warn"
        verdict  = f"{hosting} — likely server-to-server traffic, not a residential client"
    else:
        severity = "clean"
        verdict  = "No threat signals from reputation checks"

    return IpReport(
        input=target,
        ip=ip,
        ip_class=ip_class,
        is_internal=is_internal,
        reverse_dns=reverse_dns,
        country=country,
        org=org,
        hosting=hosting,
        geo_error=geo_error,
        dnsbl=dnsbl,
        abuse_contact=abuse,
        verdict_severity=severity,
        verdict_text=verdict,
    )


def _lookup_cached(target: str) -> IpReport:
    key = target.strip().lower()
    cached = _cache_get(key)
    if cached is not None:
        return cached
    report = _compute_report(target)
    _cache_put(key, report)
    return report


@router.get("/{target}", response_model=IpReport)
def lookup(target: str, request: Request) -> IpReport:
    # Path param validation. Strips whitespace, enforces length, rejects
    # malformed hostnames *before* we ever resolve them.
    target = validate_target(target)
    # Passive lookup (geoIP / DNSBL only — no probe of the target itself).
    scope.enforce_rest(
        target, get_engagement_id(request), get_mode(request), deny_only=True,
    )
    return _lookup_cached(target)


@router.post("/bulk", response_model=BulkResponse)
def bulk(req: BulkRequest, request: Request) -> BulkResponse:
    # Strip blanks + per-item validation. The first bad entry surfaces
    # an INVALID_TARGET error with the offending value so the UI can
    # highlight it; the rest of the batch is *not* run.
    seen: set[str] = set()
    targets: list[str] = []
    for raw in req.targets:
        if not isinstance(raw, str):
            raise MhpError(
                "target entries must be strings",
                code=ErrorCode.INVALID_TARGET,
            )
        s = raw.strip()
        if not s:
            continue
        normalised = validate_target(s)
        k = normalised.lower()
        if k in seen:
            continue
        seen.add(k)
        targets.append(normalised)
        if len(targets) >= _BULK_MAX:
            break

    if not targets:
        return BulkResponse(results=[])

    # Per-target scope check so a heterogeneous batch can have some entries
    # in scope and others out — out-of-scope ones surface as `ok=false` with
    # the scope reason instead of denying the whole batch.
    eid = get_engagement_id(request)
    mode = get_mode(request)

    def one(t: str) -> BulkResult:
        try:
            scope.enforce_rest(t, eid, mode, deny_only=True)
        except MhpError as exc:
            return BulkResult(target=t, ok=False, error=exc.message)
        try:
            return BulkResult(target=t, ok=True, report=_lookup_cached(t))
        except MhpError as exc:
            return BulkResult(target=t, ok=False, error=exc.message)
        except Exception as exc:
            logger.exception("ip bulk lookup failed target=%r", t)
            return BulkResult(target=t, ok=False, error=f"lookup failed: {type(exc).__name__}")

    with ThreadPoolExecutor(max_workers=_BULK_WORKERS) as pool:
        results = list(pool.map(one, targets))
    return BulkResponse(results=results)


# ── Shodan InternetDB (no API key) ───────────────────────────────────────────
# https://internetdb.shodan.io/{ip} — free, public, returns open ports + CVE
# list + hostnames + tags + CPEs. We cache per-IP for an hour so a LAN-Scan
# enrichment pass over /24 doesn't fire 254 requests every time the page reloads.

import httpx  # added for InternetDB only

INTERNETDB_UA = "s-ide/0.1 internetdb"


def _cached_internetdb(ip: str) -> dict | None:
    with _INTERNETDB_LOCK:
        hit = _INTERNETDB_CACHE.get(ip)
        if not hit:
            return None
        ts, body = hit
        if time.time() - ts > _INTERNETDB_TTL:
            _INTERNETDB_CACHE.pop(ip, None)
            return None
        return body


def _store_internetdb(ip: str, body: dict) -> None:
    with _INTERNETDB_LOCK:
        _INTERNETDB_CACHE[ip] = (time.time(), body)


@shodan_router.get("/host/{ip}")
async def shodan_internetdb(ip: str) -> dict:
    """Return Shodan InternetDB enrichment for a single IP (no API key)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise MhpError(
            "invalid IP address",
            code=ErrorCode.INVALID_IP,
            status_code=400,
        ) from None
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        # InternetDB only has public IPs — short-circuit so we don't waste a
        # request on a 404 for the user's LAN range.
        return {"ip": str(addr), "ports": [], "vulns": [], "hostnames": [],
                "tags": [], "cpes": [], "source": "skipped",
                "reason": "private/loopback IP"}
    cached = _cached_internetdb(str(addr))
    if cached is not None:
        return {**cached, "source": "cache"}
    try:
        async with httpx.AsyncClient(
            timeout=10.0, headers={"User-Agent": INTERNETDB_UA},
        ) as client:
            r = await client.get(f"https://internetdb.shodan.io/{addr}")
    except httpx.HTTPError as e:
        raise MhpError(
            f"InternetDB request failed: {e}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        ) from None
    if r.status_code == 404:
        body = {"ip": str(addr), "ports": [], "vulns": [], "hostnames": [],
                "tags": [], "cpes": [], "found": False}
        _store_internetdb(str(addr), body)
        return {**body, "source": "live"}
    if not r.is_success:
        raise MhpError(
            f"InternetDB returned {r.status_code}",
            code=ErrorCode.UPSTREAM_FAILED,
            status_code=502,
        )
    data = r.json()
    body = {
        "ip":        data.get("ip", str(addr)),
        "ports":     data.get("ports", []),
        "vulns":     data.get("vulns", []),
        "hostnames": data.get("hostnames", []),
        "tags":      data.get("tags", []),
        "cpes":      data.get("cpes", []),
        "found":     True,
    }
    _store_internetdb(str(addr), body)
    return {**body, "source": "live"}
