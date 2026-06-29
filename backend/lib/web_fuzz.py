"""Shared web-attack fuzzing utilities.

A request template carries a marker string (default `FUZZ`) — when a payload is
substituted in, we get a concrete request. The runner fires those concurrently
with a rate limit, analyzes each response against a baseline, and reports.

Used by the XSS / SQLi / CMDi / LFI / SSRF / IDOR routers.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx

DEFAULT_MARKER = "FUZZ"
DEFAULT_UA = "s-ide/0.1 (web-fuzz)"

# ── Scope guard ──────────────────────────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def check_scope(target_url: str, allow_private: bool) -> tuple[bool, str]:
    """Return (ok, reason). When allow_private=False, RFC1918/loopback/metadata
    targets are refused — guards against accidental same-host fuzzing."""
    try:
        u = urlparse(target_url if "://" in target_url else "http://" + target_url)
    except Exception as e:
        return False, f"invalid url: {e}"
    host = u.hostname
    if not host:
        return False, "no host in url"
    if allow_private:
        return True, "private targets allowed by explicit opt-in"
    ip_str = _resolve(host) if not _looks_like_ip(host) else host
    if not ip_str:
        return True, f"could not resolve {host} (allowing — DNS may catch up)"
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"non-IP host {host}"
    for net in _PRIVATE_NETS:
        if ip in net:
            return False, (
                f"{host} resolves to {ip} ({net}) — private/loopback/metadata; "
                "enable 'Allow internal targets' if you actually intend this"
            )
    return True, "external target"


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ── Request template ────────────────────────────────────────────────────────

@dataclass
class FuzzTemplate:
    """A request shape with one or more {marker} placeholders.

    `url`, `body`, `headers`, and `cookies` all support substitution. `method`
    defaults to GET unless `body` is non-empty.
    """
    url: str
    method: str = "GET"
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    marker: str = DEFAULT_MARKER

    def has_marker(self) -> bool:
        m = self.marker
        return (m in self.url or m in self.body
                or any(m in v for v in self.headers.values())
                or any(m in v for v in self.cookies.values()))

    def substitute(self, payload: str) -> "FuzzTemplate":
        m = self.marker
        return FuzzTemplate(
            url=self.url.replace(m, payload),
            method=self.method,
            body=self.body.replace(m, payload),
            headers={k: v.replace(m, payload) for k, v in self.headers.items()},
            cookies={k: v.replace(m, payload) for k, v in self.cookies.items()},
            marker=m,
        )


# ── Request executor ────────────────────────────────────────────────────────

@dataclass
class FuzzResponse:
    payload: str
    url: str
    status: int | None
    elapsed_ms: int
    length: int
    body: str          # truncated to ~64KB
    headers: dict[str, str]
    error: str = ""


def _client(timeout: float, verify_tls: bool, follow_redirects: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout, verify=verify_tls,
        follow_redirects=follow_redirects,
        headers={"User-Agent": DEFAULT_UA},
    )


async def send_one(
    client: httpx.AsyncClient, tmpl: FuzzTemplate, payload: str,
    *, body_limit: int = 64 * 1024,
) -> FuzzResponse:
    """Execute one templated request and capture timing + body."""
    rendered = tmpl.substitute(payload)
    method = rendered.method.upper() or ("POST" if rendered.body else "GET")
    headers = dict(rendered.headers)
    cookies = dict(rendered.cookies)
    t0 = time.monotonic()
    try:
        r = await client.request(
            method, rendered.url,
            content=rendered.body.encode() if rendered.body else None,
            headers=headers or None,
            cookies=cookies or None,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        body = r.text[:body_limit] if r.text is not None else ""
        return FuzzResponse(
            payload=payload, url=str(r.url), status=r.status_code,
            elapsed_ms=elapsed_ms, length=len(r.content),
            body=body, headers={k.lower(): v for k, v in r.headers.items()},
        )
    except httpx.RequestError as e:
        return FuzzResponse(
            payload=payload, url=rendered.url, status=None,
            elapsed_ms=int((time.monotonic() - t0) * 1000), length=0,
            body="", headers={}, error=f"{type(e).__name__}: {e}",
        )
    except Exception as e:
        return FuzzResponse(
            payload=payload, url=rendered.url, status=None,
            elapsed_ms=0, length=0, body="", headers={},
            error=f"{type(e).__name__}: {e}",
        )


async def baseline(
    tmpl: FuzzTemplate, *, timeout: float = 10.0,
    verify_tls: bool = False, follow_redirects: bool = False,
    sentinel: str = "MHPBASELINE0xff",
) -> FuzzResponse:
    """Issue a baseline request with a benign sentinel value substituted for
    the marker. Used as the comparison anchor for boolean/length/time-diff
    detection.

    `follow_redirects` defaults to False: with redirects on, a malicious
    target server can return `Location: http://169.254.169.254/...` and
    httpx will silently fetch it, bypassing the upstream `check_scope()`
    guard. Callers must opt in explicitly if they need redirect-following.
    """
    async with _client(timeout, verify_tls, follow_redirects) as client:
        return await send_one(client, tmpl, sentinel)


async def run_payloads(
    tmpl: FuzzTemplate,
    payloads: list[str],
    on_result: Callable[[FuzzResponse], Awaitable[None]],
    *,
    concurrency: int = 8,
    rate_per_sec: int = 10,
    timeout: float = 10.0,
    verify_tls: bool = False,
    follow_redirects: bool = False,
    stop: asyncio.Event | None = None,
) -> None:
    """Fire `payloads` concurrently, awaiting `on_result` for each response.

    `rate_per_sec` is a global ceiling implemented as a token bucket. Stops
    early if `stop` is set.
    """
    sem = asyncio.Semaphore(concurrency)
    interval = 1.0 / max(rate_per_sec, 1)
    last_send_time = [0.0]
    send_lock = asyncio.Lock()

    async with _client(timeout, verify_tls, follow_redirects) as client:

        async def one(p: str) -> None:
            if stop and stop.is_set():
                return
            async with sem:
                async with send_lock:
                    delta = time.monotonic() - last_send_time[0]
                    if delta < interval:
                        await asyncio.sleep(interval - delta)
                    last_send_time[0] = time.monotonic()
                if stop and stop.is_set():
                    return
                r = await send_one(client, tmpl, p)
                await on_result(r)

        await asyncio.gather(*(one(p) for p in payloads), return_exceptions=True)


# ── Response analysis helpers ───────────────────────────────────────────────

def length_diff_pct(a: int, b: int) -> float:
    if a == 0 and b == 0:
        return 0.0
    base = max(a, b)
    return 100.0 * abs(a - b) / base


def contains_any(haystack: str, needles: list[str]) -> str | None:
    """Return the first needle found in haystack (lowercased)."""
    h = haystack.lower()
    for n in needles:
        if n.lower() in h:
            return n
    return None


def regex_first(text: str, patterns: list[str]) -> str | None:
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(0)[:200]
    return None
