"""Decentralized .side theme distribution — git-tag resolve, immutable
content-addressed cache, TOFU hash-lock, manifest, official-vs-community.

No upload server, no name registry: identity is the source URL. Every fetched
theme is validated (fetch-time gate); the renderer re-validates at apply.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Body, HTTPException, Query

from lib import theme_fetch, theme_store
from lib.theme_trust import is_official
from lib.theme_validate import validate_side

router = APIRouter(prefix="/themes", tags=["themes"])

# Curated default manifest — itself just a file in a project-controlled repo
# (PR-able). The org prefix is the official trust anchor (see theme_trust.py).
DEFAULT_MANIFEST_URL = "https://raw.githubusercontent.com/s-ide/themes/main/manifest.json"

_MANIFEST_TIMEOUT = 10


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fetch_default_manifest(url: str) -> list[dict[str, Any]]:
    """Fetch + parse the curated default manifest into a list of source entries.

    The manifest is just a *list of source URLs* (a directory), not theme
    content — so fetching it does NOT bypass the TOFU hash-lock. Every theme it
    points at still goes through _obtain()/reconcile() (tamper-checked) when it
    is resolved/applied. A network/parse failure degrades gracefully to an
    empty curated list rather than failing the whole manifest endpoint.
    """
    try:
        r = httpx.get(url, follow_redirects=True, timeout=_MANIFEST_TIMEOUT)
        r.raise_for_status()
        obj = r.json()
    except (httpx.HTTPError, json.JSONDecodeError, ValueError):
        return []
    raw = obj.get("themes") if isinstance(obj, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for s in raw:
        if not isinstance(s, dict):
            continue
        src_url = (s.get("url") or "").strip()
        if not src_url:
            continue
        entry: dict[str, Any] = {"url": src_url}
        if s.get("version"):
            entry["version"] = s["version"]
        if s.get("name"):
            entry["name"] = s["name"]
        out.append(entry)
    return out


def _obtain(url: str, tag: str) -> tuple[bytes, dict[str, Any]]:
    """Get validated, integrity-checked bytes for url@tag (cache-first)."""
    entry = theme_store.lock_entry(url, tag)
    data = theme_store.cached_blob(url, tag, entry["hash"]) if entry else None
    if data is None:
        # Cache miss (or never locked) — fetch from source.
        data = theme_fetch.fetch_side(url, tag)

    try:
        obj = json.loads(data)
    except json.JSONDecodeError as e:
        raise HTTPException(422, {"error": "invalid_json", "detail": str(e)})
    errors = validate_side(obj)
    if errors:
        raise HTTPException(422, {"error": "invalid_theme", "errors": errors})

    try:
        content_hash, source = theme_store.reconcile(url, tag, data, _now())
    except theme_store.TamperError as e:
        raise HTTPException(409, {"error": "tamper", "url": e.url, "version": e.version,
                                  "expected": e.expected, "got": e.got})
    theme_store.store_blob(url, tag, data)
    return data, {"hash": content_hash, "source": source, "theme": obj}


@router.get("/manifest")
def get_manifest() -> dict[str, Any]:
    """The curated default sources + any user-added ones, with trust flags.

    The curated default manifest is fetched + merged so a fresh install sees a
    populated gallery out of the box (user sources take precedence on a URL
    collision). Trust ('official') is always re-derived from the URL here — it
    is never taken from the manifest file's contents.
    """
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for s in theme_store.load_user_sources():
        url = s.get("url", "")
        seen.add(url)
        sources.append({**s, "official": is_official(url), "origin": "user"})
    for s in _fetch_default_manifest(DEFAULT_MANIFEST_URL):
        if s["url"] in seen:
            continue
        seen.add(s["url"])
        sources.append({**s, "official": is_official(s["url"]), "origin": "curated"})
    return {"default_manifest_url": DEFAULT_MANIFEST_URL, "themes": sources}


@router.post("/resolve")
def resolve(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    url = (payload.get("url") or "").strip()
    if not url:
        raise HTTPException(400, {"error": "url required"})
    requested = payload.get("version")
    try:
        tag = theme_fetch.resolve_version(url, requested)
    except theme_fetch.ThemeFetchError as e:
        raise HTTPException(502, {"error": "resolve_failed", "detail": str(e)})

    _data, meta = _obtain(url, tag)
    return {
        "url": url,
        "version": tag,
        "hash": meta["hash"],
        "official": is_official(url),
        "source": meta["source"],          # curated | tofu | locked
        "verified": meta["source"] in ("curated", "locked"),
        "name": meta["theme"].get("name"),
    }


@router.get("/file")
def get_file(url: str = Query(...), version: str = Query(...)) -> dict[str, Any]:
    """The validated .side JSON the renderer applies (cache-first, no network
    when the locked blob is present — survives a deleted/moved source)."""
    _data, meta = _obtain(url, version)
    return meta["theme"]


@router.post("/manifests")
def add_source(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    url = (payload.get("url") or "").strip()
    if not url:
        raise HTTPException(400, {"error": "url required"})
    sources = theme_store.load_user_sources()
    if not any(s.get("url") == url for s in sources):
        entry = {"url": url}
        if payload.get("version"):
            entry["version"] = payload["version"]
        sources.append(entry)
        theme_store.save_user_sources(sources)
    return {"themes": sources}


@router.delete("/manifests")
def remove_source(url: str = Query(...)) -> dict[str, Any]:
    sources = [s for s in theme_store.load_user_sources() if s.get("url") != url]
    theme_store.save_user_sources(sources)
    return {"themes": sources}
