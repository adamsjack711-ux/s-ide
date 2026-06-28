"""Fire-and-forget push of events into the HIDS agent's /ingest endpoint.

Both apps run on the same Mac, so we talk to HIDS on loopback. We read the
HIDS token from its config file (single source of truth) at process start.
Disable by setting NT_HIDS_NOTIFY=0 or by removing the config file.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import URLError

_HIDS_CONFIG = Path.home() / "hids" / "agent" / "config.json"
_DEFAULT_URL = "http://127.0.0.1:8770/ingest"

_token: str | None = None
_url: str = os.environ.get("NT_HIDS_URL", _DEFAULT_URL)
_enabled: bool = os.environ.get("NT_HIDS_NOTIFY", "1") != "0"
_main_loop: asyncio.AbstractEventLoop | None = None


def _load_token() -> str | None:
    global _token
    if _token is not None:
        return _token
    try:
        cfg = json.loads(_HIDS_CONFIG.read_text())
        tok = cfg.get("token")
        if isinstance(tok, str) and tok:
            _token = tok
            return tok
    except (OSError, json.JSONDecodeError):
        pass
    return None


def _post_blocking(payload: dict, token: str) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(
        _url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-HIDS-Token": token},
    )
    try:
        with urlrequest.urlopen(req, timeout=2.0) as resp:
            resp.read()
    except (URLError, TimeoutError, OSError) as exc:
        print(f"[hids_notify] dropped (HIDS agent unreachable): {exc}", file=sys.stderr)


async def notify(severity: str, category: str, title: str, detail: dict | None = None) -> None:
    """Push one event to HIDS. Never raises; logs and drops on failure."""
    if not _enabled:
        return
    global _main_loop
    if _main_loop is None:
        try:
            _main_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
    token = _load_token()
    if not token:
        return
    payload = {
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail or {},
    }
    try:
        await asyncio.to_thread(_post_blocking, payload, token)
    except Exception as exc:
        print(f"[hids_notify] unexpected error: {exc}", file=sys.stderr)


def notify_threadsafe(severity: str, category: str, title: str, detail: dict | None = None) -> None:
    """Schedule a notify() from sync code without blocking; safe to call from threads.

    Requires that an async path has run notify() at least once so the main loop
    is cached. Routers that emit only from sync handlers should use the async
    variant directly via FastAPI's async handlers instead.
    """
    if not _enabled:
        return
    loop = _main_loop
    if loop is None or loop.is_closed():
        token = _load_token()
        if token:
            _post_blocking({"severity": severity, "category": category,
                            "title": title, "detail": detail or {}}, token)
        return
    try:
        asyncio.run_coroutine_threadsafe(notify(severity, category, title, detail), loop)
    except Exception as exc:
        print(f"[hids_notify] schedule failed: {exc}", file=sys.stderr)
