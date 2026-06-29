"""Theme integrity store — immutable content-addressed cache + TOFU hash lock.

Layout under app_data_dir()/themes/:
  cache/<sha256(url)>/<tag>/<contenthash>.side   immutable blob
  cache/<sha256(url)>/<tag>/meta.json            {url, version, fetchedAt, hash}
  themes.lock.json                               {url@version -> {hash, lockedAt, source}}
  manifests/{default,user}.json
  checksums/official.json                        optional curated first-use verification

TOFU: first fetch of url@version records its hash. Every later fetch must match,
else it's refused as tampering (an immutable version's content changed).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from lib.platform_util import app_data_dir


class TamperError(Exception):
    def __init__(self, url: str, version: str, expected: str, got: str):
        self.url = url
        self.version = version
        self.expected = expected
        self.got = got
        super().__init__(f"hash mismatch for {url}@{version}: expected {expected}, got {got}")


def _root() -> Path:
    p = app_data_dir() / "themes"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def content_hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _lock_path() -> Path:
    return _root() / "themes.lock.json"


def _load_lock() -> dict[str, Any]:
    p = _lock_path()
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    return {"version": 1, "entries": {}}


def _save_lock(lock: dict[str, Any]) -> None:
    _lock_path().write_text(json.dumps(lock, indent=2))


def _checksums() -> dict[str, str]:
    p = _root() / "checksums" / "official.json"
    if p.is_file():
        try:
            return json.loads(p.read_text()).get("entries", {})
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _blob_dir(url: str, tag: str) -> Path:
    d = _root() / "cache" / _url_hash(url) / tag
    d.mkdir(parents=True, exist_ok=True)
    return d


def cached_blob(url: str, tag: str, expected_hash: str) -> bytes | None:
    """Return the cached, content-verified blob for url@tag, or None."""
    path = _blob_dir(url, tag) / (expected_hash.split(":", 1)[-1] + ".side")
    if path.is_file():
        data = path.read_bytes()
        if content_hash(data) == expected_hash:
            return data
    return None


def store_blob(url: str, tag: str, data: bytes) -> str:
    """Write the immutable content-addressed blob; return its content hash."""
    h = content_hash(data)
    d = _blob_dir(url, tag)
    (d / (h.split(":", 1)[-1] + ".side")).write_bytes(data)
    (d / "meta.json").write_text(json.dumps({"url": url, "version": tag, "hash": h}, indent=2))
    return h


def lock_entry(url: str, version: str) -> dict[str, Any] | None:
    return _load_lock()["entries"].get(f"{url}@{version}")


def reconcile(url: str, version: str, data: bytes, locked_at: str) -> tuple[str, str]:
    """Apply TOFU integrity to freshly-fetched bytes.

    Returns (content_hash, source) where source is 'curated' | 'tofu' | 'locked'.
    Raises TamperError if an already-locked version's hash changed.
    """
    got = content_hash(data)
    lock = _load_lock()
    key = f"{url}@{version}"
    existing = lock["entries"].get(key)

    if existing:
        if existing["hash"] != got:
            raise TamperError(url, version, existing["hash"], got)
        return got, "locked"

    # First use — verify against curated checksums if present, else TOFU.
    curated = _checksums().get(key)
    if curated and curated != got:
        raise TamperError(url, version, curated, got)
    source = "curated" if curated else "tofu"
    lock["entries"][key] = {"hash": got, "lockedAt": locked_at, "source": source}
    _save_lock(lock)
    return got, source


# ── manifests ────────────────────────────────────────────────────────────────
def _manifest_path(name: str) -> Path:
    d = _root() / "manifests"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{name}.json"


def load_user_sources() -> list[dict[str, Any]]:
    p = _manifest_path("user")
    if p.is_file():
        try:
            return json.loads(p.read_text()).get("themes", [])
        except (OSError, json.JSONDecodeError):
            pass
    return []


def save_user_sources(themes: list[dict[str, Any]]) -> None:
    _manifest_path("user").write_text(
        json.dumps({"schema": "side-manifest/1", "themes": themes}, indent=2)
    )
