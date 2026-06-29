"""Integrity acceptance tests for theme distribution: TOFU hash pin, tamper
refusal on a changed immutable version, cache-survives-deleted-source, and
URL-anchored official trust.
"""
import pytest

from lib import theme_store
from lib.theme_trust import is_official


@pytest.fixture
def store(tmp_path, monkeypatch):
    # Redirect app-data to a temp dir so each test is isolated.
    monkeypatch.setattr(theme_store, "app_data_dir", lambda *a, **k: tmp_path)
    return theme_store


URL = "https://github.com/acme/neon-harbor"
V = "1.2.0"


def test_tofu_pin_and_cache_roundtrip(store):
    data = b'{"version":"1.0","kind":"theme"}'
    h, source = store.reconcile(URL, V, data, "2026-06-28T00:00:00Z")
    assert source == "tofu"  # trust on first use
    assert store.lock_entry(URL, V)["hash"] == h
    store.store_blob(URL, V, data)
    # Cache-first read returns the exact bytes, no network.
    assert store.cached_blob(URL, V, h) == data


def test_relocking_same_content_is_locked(store):
    data = b'{"a":1}'
    h, _ = store.reconcile(URL, V, data, "t0")
    h2, source2 = store.reconcile(URL, V, data, "t1")
    assert h2 == h and source2 == "locked"


def test_tamper_on_changed_immutable_version(store):
    store.reconcile(URL, V, b'{"original":true}', "t0")
    with pytest.raises(store.TamperError) as ei:
        store.reconcile(URL, V, b'{"tampered":true}', "t1")
    assert ei.value.url == URL and ei.value.version == V


def test_cache_survives_deleted_source(store):
    data = b'{"theme":"cached"}'
    h, _ = store.reconcile(URL, V, data, "t0")
    store.store_blob(URL, V, data)
    # Even if the source vanishes, the locked content-addressed blob still loads.
    assert store.cached_blob(URL, V, h) == data
    # A wrong expected hash (e.g. corruption) does not return stale bytes.
    assert store.cached_blob(URL, V, "sha256:deadbeef") is None


def test_official_anchored_to_url_not_label():
    assert is_official("https://github.com/s-ide/theme-midnight") is True
    assert is_official("https://github.com/attacker/totally-official") is False
