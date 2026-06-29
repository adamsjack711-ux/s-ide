"""Pytest fixtures shared across the backend test suite.

The two big concerns are:

  1. The engagement / audit-log SQLite DB defaults to the user's real
     `~/Library/Application Support/s-ide/engagements.db`. Tests
     must never touch it. The `temp_db` fixture redirects writes into
     `tmp_path` for the duration of one test and resets the cached
     connection between tests.

  2. Several routers read API keys from the OS keychain at import time.
     We don't import routers from the unit-test path here, but the
     keychain helpers are exercised indirectly via `_resolve_provider`
     in `routers/chat.py`. The default test environment has no keys,
     which matches a fresh-install user.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make `lib` importable when pytest is invoked from the repo root.
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture
def temp_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the engagements/audit SQLite DB into `tmp_path`.

    Both `lib.engagements` and `lib.audit_log` go through
    `lib.engagements._db_path()` + the module-level `_conn` cache, so we
    patch the path helper and clear the cached connection. Pytest's tmp_path
    is unique per-test, so each test starts with a fresh DB.
    """
    from lib import engagements

    db_path = tmp_path / "engagements.db"
    monkeypatch.setattr(engagements, "_db_path", lambda: db_path)

    # Force the next _connect() to re-open against the new path. We can't
    # just monkeypatch _conn because _connect() reassigns the module global.
    if engagements._conn is not None:
        try:
            engagements._conn.close()
        except Exception:
            pass
        engagements._conn = None

    yield db_path

    if engagements._conn is not None:
        try:
            engagements._conn.close()
        except Exception:
            pass
        engagements._conn = None


@pytest.fixture(autouse=True)
def _block_real_keychain(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests must never read from / write to the macOS Keychain.

    `routers.settings.keychain_get` (and the named-key variant) shells out
    to the `security` binary. Force-return `None` so import-time provider
    selection and any "key present?" branches see a clean unconfigured
    install. Tests that need to assert keychain-present behaviour can
    locally re-patch.
    """
    try:
        from routers import settings as settings_mod  # noqa: PLC0415
        monkeypatch.setattr(settings_mod, "keychain_get", lambda: None)
        monkeypatch.setattr(settings_mod, "keychain_get_named",
                            lambda name: None)
    except ImportError:
        # settings router may not be importable in pure-lib unit tests.
        pass


@pytest.fixture(autouse=True)
def _restore_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip MHP_* env vars so tests don't pick up the dev shell config."""
    for k in list(os.environ):
        if k.startswith("MHP_"):
            monkeypatch.delenv(k, raising=False)


@pytest.fixture
def permissive_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap target_policy._policy for a permissive shim (warn-on-external).

    Production config.json defaults to ``deny_external_by_default: true`` so
    the operator can't accidentally scan the public internet. Tests that
    exercise the warn/need-confirm code path need the older permissive
    behaviour; this fixture pins it just for the test that opts in.
    """
    from lib import target_policy
    monkeypatch.setattr(target_policy, "_policy", lambda: {
        "allow_private": True,
        "allow_loopback": True,
        "allow_tailscale": True,
        "allow_external": [],
        "deny_external_by_default": False,
    })
