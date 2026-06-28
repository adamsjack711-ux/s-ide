"""Service fingerprinter — banner grab + protocol-aware probes per port.

REST  GET  /fingerprint/{host}/{port}
      Single host:port fingerprint.

REST  POST /fingerprint/bulk
      Body: { "host": "...", "ports": [22, 80, 443] }
      Probes all ports concurrently (~16 workers) and returns a list.

Response shape:
  {
    host, port, ip,
    open: bool,
    service_guess: "ssh" | "http" | ... | "unknown",
    version: "OpenSSH_8.4",     # may be empty
    banner_lines: ["..."],       # raw, redacted of nulls
    extras: { ... protocol-specific },
    elapsed_ms: 234,
    error: null | "timed out" | "refused"
  }
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import struct
import time
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from lib import scope
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.target_policy import check_target
from lib.validators import validate_port, validate_target

logger = logging.getLogger(__name__)

router = APIRouter(tags=["fingerprint"])


# ── Probes ────────────────────────────────────────────────────────────────────

def _read_all(sock: socket.socket, max_bytes: int = 4096, deadline: float = 2.5) -> bytes:
    """Read until quiet or deadline."""
    end = time.monotonic() + deadline
    chunks: list[bytes] = []
    sock.settimeout(0.4)
    while time.monotonic() < end:
        try:
            data = sock.recv(min(1024, max_bytes - sum(len(c) for c in chunks)))
        except (socket.timeout, BlockingIOError, TimeoutError):
            if chunks:
                break
            continue
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        if sum(len(c) for c in chunks) >= max_bytes:
            break
    return b"".join(chunks)


def _decode(raw: bytes) -> list[str]:
    text = raw.replace(b"\x00", b"").decode("utf-8", errors="replace")
    return [ln.rstrip("\r") for ln in text.split("\n") if ln.strip()][:12]


def _probe_ssh(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=512, deadline=2.0)
    lines = _decode(raw)
    version = ""
    for ln in lines:
        m = re.match(r"SSH-([\d.]+)-(.+)", ln)
        if m:
            version = m.group(2).strip()
            break
    return {"service_guess": "ssh", "version": version,
            "banner_lines": lines, "extras": {}}


def _probe_ftp(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=2048, deadline=2.0)
    lines = _decode(raw)
    version = ""
    for ln in lines:
        if ln.startswith("220"):
            version = ln[3:].strip(" -")
            break
    return {"service_guess": "ftp", "version": version[:120],
            "banner_lines": lines, "extras": {}}


def _probe_smtp(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=1024, deadline=2.0)
    lines = _decode(raw)
    try:
        sock.sendall(b"EHLO network-tools\r\n")
        raw2 = _read_all(sock, max_bytes=4096, deadline=2.0)
        lines.extend(_decode(raw2))
    except OSError:
        pass
    version = ""
    extras: dict[str, Any] = {"capabilities": []}
    for ln in lines:
        if ln.startswith("220"):
            version = ln[3:].strip(" -")
        elif ln.startswith("250"):
            cap = ln[3:].strip(" -")
            if cap and cap not in extras["capabilities"]:
                extras["capabilities"].append(cap)
    return {"service_guess": "smtp", "version": version[:120],
            "banner_lines": lines, "extras": extras}


def _probe_pop3(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=512, deadline=2.0)
    lines = _decode(raw)
    version = lines[0][3:].strip(" -") if lines and lines[0].startswith("+OK") else ""
    return {"service_guess": "pop3", "version": version[:120],
            "banner_lines": lines, "extras": {}}


def _probe_imap(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=512, deadline=2.0)
    lines = _decode(raw)
    version = ""
    if lines and lines[0].startswith("* OK"):
        version = lines[0][4:].strip(" -")
    return {"service_guess": "imap", "version": version[:120],
            "banner_lines": lines, "extras": {}}


def _probe_telnet(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=2048, deadline=2.0)
    # Strip IAC sequences
    cleaned = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == 0xFF and i + 2 < len(raw):
            i += 3
            continue
        cleaned.append(raw[i]); i += 1
    return {"service_guess": "telnet", "version": "",
            "banner_lines": _decode(bytes(cleaned)), "extras": {}}


def _probe_redis(sock: socket.socket) -> dict[str, Any]:
    try:
        sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
    except OSError:
        return {"service_guess": "redis", "version": "", "banner_lines": [],
                "extras": {"error": "send failed"}}
    raw = _read_all(sock, max_bytes=4096, deadline=2.0)
    lines = _decode(raw)
    version = ""
    for ln in lines:
        m = re.match(r"redis_version:(\S+)", ln)
        if m:
            version = m.group(1); break
    return {"service_guess": "redis", "version": version,
            "banner_lines": lines[:8], "extras": {}}


def _probe_mysql(sock: socket.socket) -> dict[str, Any]:
    """Read the MySQL Initial Handshake Packet (protocol 10)."""
    raw = _read_all(sock, max_bytes=512, deadline=2.0)
    if len(raw) < 5 or raw[4] != 10:
        return {"service_guess": "mysql?", "version": "",
                "banner_lines": _decode(raw), "extras": {}}
    # 3-byte length, 1-byte seq, 1-byte protocol, null-terminated version
    try:
        version_end = raw.index(b"\x00", 5)
        version = raw[5:version_end].decode("utf-8", "replace")
    except ValueError:
        version = ""
    return {"service_guess": "mysql", "version": version,
            "banner_lines": [f"MySQL handshake · protocol 10 · {version}"],
            "extras": {}}


def _probe_postgres(sock: socket.socket) -> dict[str, Any]:
    """Send a startup packet with an invalid version to get an error reply."""
    try:
        payload = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"  # SSLRequest packet
        sock.sendall(payload)
        raw = _read_all(sock, max_bytes=256, deadline=2.0)
        if raw == b"S":
            return {"service_guess": "postgres", "version": "(SSL supported)",
                    "banner_lines": [], "extras": {"ssl": True}}
        if raw == b"N":
            return {"service_guess": "postgres", "version": "(SSL refused)",
                    "banner_lines": [], "extras": {"ssl": False}}
        return {"service_guess": "postgres?", "version": "",
                "banner_lines": _decode(raw), "extras": {}}
    except OSError:
        return {"service_guess": "postgres?", "version": "",
                "banner_lines": [], "extras": {"error": "no reply"}}


def _probe_vnc(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=64, deadline=2.0)
    lines = _decode(raw)
    version = ""
    if lines and re.match(r"RFB \d{3}\.\d{3}", lines[0]):
        version = lines[0].strip()
    return {"service_guess": "vnc", "version": version,
            "banner_lines": lines, "extras": {}}


def _probe_http(sock: socket.socket, host: str, https: bool = False) -> dict[str, Any]:
    try:
        sock.sendall(
            f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: network-tools\r\n\r\n".encode()
        )
    except OSError:
        return {"service_guess": "http", "version": "", "banner_lines": [],
                "extras": {"error": "send failed"}}
    raw = _read_all(sock, max_bytes=4096, deadline=2.5)
    lines = _decode(raw)
    server = ""
    powered = ""
    status_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    return {
        "service_guess": "https" if https else "http",
        "version": server,
        "banner_lines": lines[:10],
        "extras": {
            "status_line": status_line,
            "server": server,
            "x_powered_by": powered,
            "headers": {k: v for k, v in headers.items() if k in (
                "server", "x-powered-by", "x-frame-options", "strict-transport-security",
                "content-security-policy", "x-content-type-options",
            )},
        },
    }


def _probe_https(host: str, port: int, timeout: float) -> dict[str, Any]:
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                return _probe_http(ssock, host, https=True)
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        return {"service_guess": "https", "version": "", "banner_lines": [],
                "extras": {"tls_error": str(exc)}}


def _probe_generic(sock: socket.socket) -> dict[str, Any]:
    raw = _read_all(sock, max_bytes=512, deadline=1.5)
    return {"service_guess": "unknown" if not raw else "banner",
            "version": "", "banner_lines": _decode(raw), "extras": {}}


# ── Dispatch ──────────────────────────────────────────────────────────────────

PORT_PROBES = {
    21:    ("ftp",      _probe_ftp),
    22:    ("ssh",      _probe_ssh),
    23:    ("telnet",   _probe_telnet),
    25:    ("smtp",     _probe_smtp),
    110:   ("pop3",     _probe_pop3),
    143:   ("imap",     _probe_imap),
    465:   ("smtps",    _probe_smtp),
    587:   ("smtp-submission", _probe_smtp),
    993:   ("imaps",    _probe_imap),
    995:   ("pop3s",    _probe_pop3),
    3306:  ("mysql",    _probe_mysql),
    5432:  ("postgres", _probe_postgres),
    5900:  ("vnc",      _probe_vnc),
    5901:  ("vnc",      _probe_vnc),
    6379:  ("redis",    _probe_redis),
}

HTTP_PORTS = {80, 81, 591, 2080, 2375, 4567, 5000, 7000, 7001, 8000, 8008, 8080,
              8081, 8088, 8090, 8181, 8443, 8765, 8770, 8888, 9000, 9090, 9200}
HTTPS_PORTS = {443, 4443, 8443, 9443}


def _fingerprint_one(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    t0 = time.monotonic()
    base = {"host": host, "port": port, "ip": "", "open": False,
            "service_guess": "unknown", "version": "", "banner_lines": [],
            "extras": {}, "elapsed_ms": 0, "error": None}
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        base["error"] = f"resolve: {exc}"
        base["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        return base
    base["ip"] = ip

    if port in HTTPS_PORTS:
        result = _probe_https(host, port, timeout=timeout)
        base.update(result, open=("tls_error" not in result["extras"]),
                    elapsed_ms=int((time.monotonic() - t0) * 1000))
        if not base["open"]:
            base["error"] = result["extras"].get("tls_error", "tls failed")
        return base

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            base["open"] = True
            if port in HTTP_PORTS:
                result = _probe_http(sock, host)
            elif port in PORT_PROBES:
                _, probe = PORT_PROBES[port]
                result = probe(sock)
            else:
                # Try a quick HTTP probe as a fallback (a lot of randoms speak HTTP)
                result = _probe_http(sock, host)
                if not result["banner_lines"] or not (
                    result["banner_lines"][0].startswith("HTTP/") if result["banner_lines"] else False
                ):
                    # Discard HTTP guess; re-read on a fresh socket as generic
                    try:
                        with socket.create_connection((host, port), timeout=timeout) as s2:
                            result = _probe_generic(s2)
                    except OSError:
                        pass
            base.update(result)
    except (socket.timeout, TimeoutError):
        base["error"] = "timed out"
    except ConnectionRefusedError:
        base["error"] = "refused"
    except OSError as exc:
        base["error"] = str(exc)

    base["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
    return base


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/fingerprint/{host}/{port}")
async def fingerprint_one(host: str, port: int, request: Request) -> dict[str, Any]:
    host = validate_target(host, field="host")
    port = validate_port(port)
    # Banner grab is passive — warn proceeds with verdict in response.
    verdict, reason, _ = scope.enforce_rest(
        host, get_engagement_id(request), get_mode(request), deny_only=True,
    )
    result = await asyncio.to_thread(_fingerprint_one, host, port)
    result["policy"] = {"verdict": verdict, "reason": reason}
    return result


class BulkRequest(BaseModel):
    host: str
    ports: list[int] = Field(..., max_length=100)
    confirm: bool = False


@router.post("/fingerprint/bulk")
async def fingerprint_bulk(req: BulkRequest, request: Request) -> dict[str, Any]:
    host = validate_target(req.host, field="host")
    if len(req.ports) == 0:
        raise MhpError("ports is required", code=ErrorCode.VALIDATION_ERROR)
    ports = [validate_port(p) for p in req.ports]
    verdict, reason, _ = scope.enforce_rest(
        host, get_engagement_id(request), get_mode(request), confirm=req.confirm,
    )

    sem = asyncio.Semaphore(16)

    async def run_one(p: int) -> dict[str, Any]:
        async with sem:
            return await asyncio.to_thread(_fingerprint_one, host, p)

    results = await asyncio.gather(*(run_one(p) for p in ports))
    return {
        "host": host,
        "results": results,
        "policy": {"verdict": verdict, "reason": reason},
    }
