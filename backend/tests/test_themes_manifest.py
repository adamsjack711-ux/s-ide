"""get_manifest must populate a fresh install's gallery by fetching + merging
the curated default manifest, while keeping trust URL-anchored and user sources
authoritative on a URL collision. Fetching the manifest (a list of source URLs)
never bypasses the per-theme TOFU hash-lock — only blob reconcile does that.
"""
import json

import httpx
import pytest

from routers import themes


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


@pytest.fixture
def no_user_sources(monkeypatch):
    monkeypatch.setattr(themes.theme_store, "load_user_sources", lambda: [])


def _mock_get(monkeypatch, resp):
    monkeypatch.setattr(themes.httpx, "get", lambda *a, **k: resp)


def test_curated_manifest_populates_fresh_gallery(monkeypatch, no_user_sources):
    _mock_get(monkeypatch, _FakeResp({"themes": [
        {"url": "https://github.com/s-ide/theme-midnight", "name": "Midnight"},
        {"url": "https://github.com/acme/neon", "version": "1.0.0"},
    ]}))
    out = themes.get_manifest()
    urls = {t["url"]: t for t in out["themes"]}
    assert len(out["themes"]) == 2
    # Trust is URL-anchored, never taken from the file.
    assert urls["https://github.com/s-ide/theme-midnight"]["official"] is True
    assert urls["https://github.com/acme/neon"]["official"] is False
    assert urls["https://github.com/acme/neon"]["version"] == "1.0.0"
    assert all(t["origin"] == "curated" for t in out["themes"])


def test_user_source_wins_on_url_collision(monkeypatch):
    shared = "https://github.com/acme/neon"
    monkeypatch.setattr(
        themes.theme_store, "load_user_sources",
        lambda: [{"url": shared, "version": "2.0.0"}],
    )
    _mock_get(monkeypatch, _FakeResp({"themes": [
        {"url": shared, "version": "1.0.0"},
        {"url": "https://github.com/s-ide/theme-midnight"},
    ]}))
    out = themes.get_manifest()
    urls = {t["url"]: t for t in out["themes"]}
    assert len(out["themes"]) == 2
    # The user entry is the one kept (origin user, its pinned version).
    assert urls[shared]["origin"] == "user"
    assert urls[shared]["version"] == "2.0.0"


def test_manifest_fetch_failure_degrades_to_empty(monkeypatch, no_user_sources):
    def _boom(*a, **k):
        raise httpx.ConnectError("offline")
    monkeypatch.setattr(themes.httpx, "get", _boom)
    out = themes.get_manifest()
    assert out["themes"] == []
    assert out["default_manifest_url"] == themes.DEFAULT_MANIFEST_URL


def test_manifest_bad_json_degrades_to_empty(monkeypatch, no_user_sources):
    _mock_get(monkeypatch, _FakeResp(json.JSONDecodeError("x", "", 0)))
    out = themes.get_manifest()
    assert out["themes"] == []


def test_manifest_entries_without_url_are_skipped(monkeypatch, no_user_sources):
    _mock_get(monkeypatch, _FakeResp({"themes": [
        {"name": "no url"},
        {"url": "  "},
        {"url": "https://github.com/acme/ok"},
    ]}))
    out = themes.get_manifest()
    assert [t["url"] for t in out["themes"]] == ["https://github.com/acme/ok"]
