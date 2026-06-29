"""Basic security check — fast baseline scan for someone testing their own
home app.

POST /basic_check/run takes a target (URL or hostname) and runs a tight
~20-30 second baseline: DNS resolution, TLS handshake summary, security
headers, and a top-100-port scan. Everything is structured JSON; no
streaming, no live UI hooks — this is the "quick check" surface that
sits next to the Copilot suggester.

Each phase delegates to the same helpers the dedicated routers use so the
results stay consistent with the rest of the app.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from lib import scanner
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.validators import validate_target

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/basic_check", tags=["basic-check"],
                   dependencies=[Depends(require_local_auth)])


# Wall-clock budgets per phase so a slow target can't make the whole check
# hang. Combined, the basic check stays well under 30s.
DNS_TIMEOUT = 3.0
TLS_TIMEOUT = 4.0
HTTP_TIMEOUT = 5.0
PORT_SCAN_TIMEOUT = 1.0
PORT_SCAN_THREADS = 80

# Same six headers triage.py looks for — kept identical so users learn one
# vocabulary across the app.
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# nmap's top-100-by-frequency. Kept inline so the basic check works in
# environments where nmap itself isn't on PATH.
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]


class BasicCheckRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)


class DnsResult(BaseModel):
    host: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    resolved: bool


class TlsResult(BaseModel):
    attempted: bool
    handshake_ok: bool
    version: str | None = None
    cipher: str | None = None
    cert_cn: str | None = None
    cert_expiry: str | None = None
    error: str | None = None


class HeaderResult(BaseModel):
    attempted: bool
    status: int | None = None
    server: str | None = None
    headers_present: list[str] = Field(default_factory=list)
    headers_missing: list[str] = Field(default_factory=list)
    error: str | None = None


class OpenPort(BaseModel):
    port: int
    service: str
    banner: str


class PortResult(BaseModel):
    scanned: int
    open: list[OpenPort] = Field(default_factory=list)
    elapsed: float


class RiskItem(BaseModel):
    severity: str
    label: str
    detail: str


class RiskSummary(BaseModel):
    overall: str
    items: list[RiskItem] = Field(default_factory=list)


class BasicCheckResponse(BaseModel):
    target: str
    canonical: str
    elapsed_ms: int
    dns: DnsResult
    tls: TlsResult
    headers: HeaderResult
    ports: PortResult
    risk_summary: RiskSummary


# ── Parsers ─────────────────────────────────────────────────────────────────


def _parse(raw: str) -> tuple[str, str, int]:
    """Return (host, scheme, port). Defaults: scheme=https, port=443 unless
    the user typed a URL or host:port explicitly.
    """
    s = raw.strip()
    if "://" in s:
        u = urlparse(s)
        host = u.hostname or ""
        scheme = (u.scheme or "https").lower()
        port = u.port or (443 if scheme == "https" else 80)
    elif s.count(":") == 1 and not s.startswith("["):
        host, _, p = s.partition(":")
        try:
            port = int(p)
        except ValueError:
            port = 443
        scheme = "https" if port == 443 else ("http" if port == 80 else "https")
    else:
        host = s
        scheme = "https"
        port = 443
    if not host:
        raise MhpError("target missing hostname", code=ErrorCode.INVALID_TARGET)
    validate_target(host, field="target")
    return host, scheme, port


# ── Probes (each one is best-effort; errors land in the result, not 500) ────


async def _dns_probe(host: str) -> DnsResult:
    """A/AAAA via getaddrinfo. NS/MX via `dig` if available; we don't reach
    for a third-party DNS library to stay light. Best-effort: empty lists
    on failure rather than raising.
    """
    loop = asyncio.get_running_loop()
    a: list[str] = []
    aaaa: list[str] = []

    async def _resolve(fam: int) -> list[str]:
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=fam, type=socket.SOCK_STREAM),
                timeout=DNS_TIMEOUT,
            )
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            return []
        out: list[str] = []
        seen: set[str] = set()
        for entry in infos:
            ip = entry[4][0]
            if ip and ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out[:8]

    a = await _resolve(socket.AF_INET)
    aaaa = await _resolve(socket.AF_INET6)

    ns_records = await _dig(host, "NS")
    mx_records = await _dig(host, "MX")

    return DnsResult(
        host=host, a=a, aaaa=aaaa, ns=ns_records, mx=mx_records,
        resolved=bool(a or aaaa),
    )


async def _dig(domain: str, rtype: str) -> list[str]:
    import shutil
    dig = shutil.which("dig")
    if not dig:
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            dig, "+short", "+time=2", "+tries=1", domain, rtype,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=4.0)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            return []
    except (OSError, ValueError):
        return []
    text = stdout.decode("utf-8", errors="replace") if stdout else ""
    return [ln.strip() for ln in text.splitlines() if ln.strip()][:10]


async def _tls_probe(host: str, scheme: str, port: int) -> TlsResult:
    if scheme != "https":
        return TlsResult(attempted=False, handshake_ok=False)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port, ssl=ctx,
                                    server_hostname=host),
            timeout=TLS_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
        return TlsResult(attempted=True, handshake_ok=False, error=str(exc)[:200])
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return TlsResult(attempted=True, handshake_ok=False,
                             error="no ssl object")
        cipher = ssl_obj.cipher()
        cert = ssl_obj.getpeercert() or {}
        subj = dict(x[0] for x in cert.get("subject", []) if x)
        return TlsResult(
            attempted=True, handshake_ok=True,
            version=ssl_obj.version(),
            cipher=cipher[0] if cipher else None,
            cert_cn=subj.get("commonName"),
            cert_expiry=cert.get("notAfter"),
        )
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (asyncio.TimeoutError, Exception):
            pass


async def _headers_probe(host: str, scheme: str, port: int) -> HeaderResult:
    base_port = "" if (scheme == "https" and port == 443) or (scheme == "http" and port == 80) else f":{port}"
    url = f"{scheme}://{host}{base_port}/"
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT, follow_redirects=False, verify=False,
            headers={"User-Agent": "s-ide-BasicCheck/0.1"},
        ) as client:
            r = await client.head(url)
            # Some servers 405 a HEAD; fall back to GET so we still see headers.
            if r.status_code in (405, 501):
                r = await client.get(url)
    except (httpx.RequestError, httpx.HTTPError) as exc:
        return HeaderResult(attempted=True, error=str(exc)[:200])

    present: list[str] = []
    missing: list[str] = []
    for h in SECURITY_HEADERS:
        (present if h in r.headers else missing).append(h)
    return HeaderResult(
        attempted=True, status=r.status_code,
        server=r.headers.get("Server"),
        headers_present=present, headers_missing=missing,
    )


async def _port_probe(host: str) -> PortResult:
    """Top-100 TCP connect scan via the same lib/scanner the WS scanner uses."""
    loop = asyncio.get_running_loop()
    try:
        ip = await asyncio.to_thread(scanner.resolve_host, host)
    except (socket.gaierror, OSError):
        return PortResult(scanned=0, open=[], elapsed=0.0)

    found: list[OpenPort] = []
    t0 = time.monotonic()

    def on_open(port: int, service: str, banner: str) -> None:
        found.append(OpenPort(port=port, service=service, banner=banner))

    def on_progress(_done: int, _total: int) -> None:
        return

    def should_stop() -> bool:
        # Cap wall-clock for the whole scan so a heavily-firewalled host
        # can't blow our 30s budget.
        return time.monotonic() - t0 > 18.0

    await loop.run_in_executor(
        None,
        lambda: scanner.scan_stream(
            ip, TOP_100_PORTS, PORT_SCAN_TIMEOUT, PORT_SCAN_THREADS,
            on_open=on_open, on_progress=on_progress, should_stop=should_stop,
        ),
    )
    elapsed = round(time.monotonic() - t0, 2)
    return PortResult(scanned=len(TOP_100_PORTS), open=found, elapsed=elapsed)


# ── Risk summary ────────────────────────────────────────────────────────────


# Ports we flag as "verify this is intentional on a public surface". Most are
# fine on localhost; the risk summary is keyed off the user's own intent
# rather than blanket-flagging.
_RISKY_OPEN_PORTS = {
    21:    ("medium", "FTP open",     "Plaintext file transfer — prefer SFTP."),
    23:    ("high",   "Telnet open",  "Plaintext shell. Disable unless on a trusted, isolated LAN."),
    25:    ("low",    "SMTP open",    "Confirm relay restrictions; open relays are spam liability."),
    111:   ("medium", "RPC open",     "Portmapper exposes service enumeration."),
    135:   ("medium", "MSRPC open",   "Windows RPC — restrict to LAN."),
    139:   ("medium", "NetBIOS open", "Legacy file sharing — restrict to LAN."),
    445:   ("medium", "SMB open",     "Restrict to LAN; never expose to public internet."),
    1433:  ("high",   "MSSQL open",   "Database port reachable. Add firewall + auth."),
    1900:  ("low",    "SSDP open",    "UPnP discovery — fine on LAN, never on WAN."),
    2049:  ("medium", "NFS open",     "Restrict exports and bind to LAN."),
    3306:  ("high",   "MySQL open",   "Database port reachable. Add firewall + auth."),
    3389:  ("high",   "RDP open",     "Common brute-force target. Restrict to VPN."),
    5432:  ("high",   "Postgres open","Database port reachable. Add firewall + auth."),
    5900:  ("high",   "VNC open",     "Restrict to VPN; pair with strong auth."),
    6379:  ("high",   "Redis open",   "Often unauthenticated by default. Bind to loopback."),
    9200:  ("high",   "Elasticsearch open", "Often unauthenticated; restrict to LAN."),
    11211: ("medium", "memcached open", "UDP version often used in amplification — restrict."),
    27017: ("high",   "MongoDB open", "Often unauthenticated by default. Bind to loopback."),
}


def _summarize(dns: DnsResult, tls: TlsResult, headers: HeaderResult,
               ports: PortResult) -> RiskSummary:
    items: list[RiskItem] = []

    if not dns.resolved:
        items.append(RiskItem(
            severity="info",
            label="Target does not resolve",
            detail="No A/AAAA records — is the hostname right?",
        ))

    if tls.attempted and not tls.handshake_ok:
        items.append(RiskItem(
            severity="high",
            label="TLS handshake failed",
            detail=tls.error or "Connection refused on the TLS port.",
        ))
    elif tls.attempted and tls.handshake_ok:
        if tls.version in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"):
            items.append(RiskItem(
                severity="high",
                label=f"Legacy TLS in use ({tls.version})",
                detail="Disable TLS 1.0/1.1 — current browsers reject them.",
            ))

    if headers.attempted and headers.error:
        items.append(RiskItem(
            severity="medium",
            label="Could not fetch HTTP headers",
            detail=headers.error,
        ))
    elif headers.attempted and headers.headers_missing:
        for h in headers.headers_missing:
            sev = "medium" if h in ("Strict-Transport-Security",
                                    "Content-Security-Policy") else "low"
            items.append(RiskItem(
                severity=sev,
                label=f"Missing {h}",
                detail=f"Header not present on the root response.",
            ))

    for op in ports.open:
        risky = _RISKY_OPEN_PORTS.get(op.port)
        if risky:
            sev, label, detail = risky
            items.append(RiskItem(severity=sev, label=label, detail=detail))

    sev_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((sev_rank.get(i.severity, 0) for i in items), default=0)
    overall = ["clean", "low", "medium", "high"][worst]
    return RiskSummary(overall=overall, items=items)


# ── Endpoint ────────────────────────────────────────────────────────────────


@router.post("/run", response_model=BasicCheckResponse)
async def run_basic_check(req: BasicCheckRequest) -> BasicCheckResponse:
    host, scheme, port = _parse(req.target)
    canonical = f"{scheme}://{host}" + (
        f":{port}" if not ((scheme == "https" and port == 443) or
                           (scheme == "http" and port == 80)) else ""
    )

    t0 = time.monotonic()
    dns_task = asyncio.create_task(_dns_probe(host))
    tls_task = asyncio.create_task(_tls_probe(host, scheme, port))
    headers_task = asyncio.create_task(_headers_probe(host, scheme, port))
    port_task = asyncio.create_task(_port_probe(host))

    dns, tls, headers, ports = await asyncio.gather(
        dns_task, tls_task, headers_task, port_task,
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    return BasicCheckResponse(
        target=req.target.strip(),
        canonical=canonical,
        elapsed_ms=elapsed_ms,
        dns=dns,
        tls=tls,
        headers=headers,
        ports=ports,
        risk_summary=_summarize(dns, tls, headers, ports),
    )
