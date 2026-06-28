"""Per-process auth token for privileged loopback endpoints.

The token is generated once at import time (i.e. once per backend launch)
and lives only in memory — it rotates every launch, so a stale token from
a previous run cannot be replayed.

Three FastAPI dependencies are exposed:

* `require_localhost` — accept only requests whose `client.host`
  is the IPv4/IPv6 loopback address. Used on `/auth/token` so the
  Electron renderer (which is the only thing that ever reaches the
  backend over loopback) can fetch the token without already possessing it.

* `require_local_auth` — same loopback check *plus* a constant-time
  comparison against the token. Used on endpoints that shell out /
  install sudoers entries / run privileged tools.

* `require_local_origin` — if the caller sent an `Origin:` header
  (i.e. it is a browser), reject anything outside the renderer
  allow-list. Browsers do NOT apply CORS to WebSocket handshakes, so
  without this an attacker website could `new WebSocket("ws://127.0.0.1:8765/...")`
  even after the loopback + token gates close. Non-browser clients
  (CLI, Python scripts, Electron native fetch) send no Origin and pass.

All three dependencies accept any `HTTPConnection` (the common parent of
`Request` and `WebSocket`), so the same function works for HTTP and WS
routes. For WS routes the token is read from the `?token=` query param
since browsers can't set custom headers on a WebSocket upgrade.
"""
from __future__ import annotations

import secrets
import threading
import time

from fastapi import HTTPException, WebSocketException, status
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocket

# Loopback addresses we trust. ::1 covers IPv6 loopback in case uvicorn is
# ever started with --host ::1 in development.
_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}

# Browser origins we trust. Matches the CORSMiddleware allow_origins in
# main.py — keep them in sync. CORS only protects HTTP; the same allow-list
# is enforced at the dependency layer so WS handshakes get the same gate.
_ALLOWED_ORIGINS = {
    "http://localhost:5173",   # Vite dev server
    "http://127.0.0.1:5173",
    "app://-",                 # Electron production scheme
}

# Rotated every launch. Module-level on purpose: a single import yields a
# single token for the lifetime of the process.
AUTH_TOKEN: str = secrets.token_hex(32)


def _is_loopback(conn: HTTPConnection) -> bool:
    client = conn.client
    return bool(client and client.host in _LOOPBACK_HOSTS)


def _reject(conn: HTTPConnection, detail: str) -> None:
    if isinstance(conn, WebSocket):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason=detail)
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def require_localhost(conn: HTTPConnection) -> None:
    """Reject anything that didn't come over loopback."""
    if not _is_loopback(conn):
        _reject(conn, "local access only")


def require_local_origin(conn: HTTPConnection) -> None:
    """Reject browser callers whose Origin is not in the allow-list.

    Missing Origin is allowed: that means the caller is not a browser
    (CLI, requests/httpx script, Electron's main-process fetch) and the
    other auth layers carry the load. Present but unlisted Origin =
    a malicious or unrelated web page, refuse the handshake.
    """
    origin = conn.headers.get("origin")
    if origin and origin not in _ALLOWED_ORIGINS:
        _reject(conn, "origin not allowed")


def require_local_auth(conn: HTTPConnection) -> None:
    """Loopback + token check for privileged endpoints.

    HTTP: token is read from the `X-MHP-Token` header.
    WS:   token is read from the `?token=` query param (header fallback
          still accepted for completeness).
    """
    if not _is_loopback(conn):
        _reject(conn, "local access only")
    presented = conn.headers.get("X-MHP-Token") or conn.query_params.get("token", "")
    if not presented or not secrets.compare_digest(presented, AUTH_TOKEN):
        _reject(conn, "missing or invalid X-MHP-Token")


# ── Short-lived nonces for system-browser report opens ────────────────────────
# The auth token is per-launch and long-lived. Putting it in a URL query string
# (so the system browser can fetch a report) leaks it into OS browser history,
# Referer headers, and DevTools panels — and the same token grants
# /terminal/exec, so leak = local RCE. Mitigation: mint a single-use, 30-second,
# path-bound nonce per report open. The renderer POSTs to mint, then opens the
# nonce URL via shell.openExternal; the report endpoint accepts the nonce as an
# alternative to the bearer token. Even if the nonce lands in browser history
# it's expired and burned within seconds.

_NONCE_TTL_SECONDS = 30.0
_NONCE_GC_AFTER = 300.0
_nonce_lock = threading.Lock()
_nonce_store: dict[str, tuple[str, float]] = {}


def mint_report_nonce(path: str) -> str:
    """Generate a one-shot, path-bound, 30-second nonce.

    The nonce is the only credential the system-browser tab will carry to
    the report endpoint. Path binding means a nonce minted for
    `/engagements/X/report` can't be replayed against `/engagements/X/findings`.
    """
    nonce = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _nonce_lock:
        _nonce_store[nonce] = (path, now + _NONCE_TTL_SECONDS)
        if len(_nonce_store) > 64:
            stale = [k for k, (_, exp) in _nonce_store.items() if exp < now - _NONCE_GC_AFTER]
            for k in stale:
                _nonce_store.pop(k, None)
    return nonce


def _consume_report_nonce(path: str, nonce: str) -> bool:
    if not nonce:
        return False
    with _nonce_lock:
        entry = _nonce_store.pop(nonce, None)
    if entry is None:
        return False
    stored_path, expires_at = entry
    if time.monotonic() > expires_at:
        return False
    return secrets.compare_digest(stored_path, path)


def require_local_auth_or_report_nonce(conn: HTTPConnection) -> None:
    """Pass if EITHER the bearer token is valid OR a path-bound nonce is.

    Used on the report-serving endpoints. Token still works for API callers
    (`authFetch` etc.). Nonce is the only path open to the system browser.
    """
    if not _is_loopback(conn):
        _reject(conn, "local access only")
    # Token path — same constant-time check as require_local_auth.
    presented = conn.headers.get("X-MHP-Token") or conn.query_params.get("token", "")
    if presented and secrets.compare_digest(presented, AUTH_TOKEN):
        return
    # Nonce fallback. Path is the request path (no query string).
    nonce = conn.query_params.get("nonce", "")
    if _consume_report_nonce(conn.url.path, nonce):
        return
    _reject(conn, "missing or invalid auth")
