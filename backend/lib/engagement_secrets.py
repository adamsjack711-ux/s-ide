"""Engagement auth secrets — encrypted at rest, redacted everywhere else.

A web-app engagement may carry authentication so tools can reach the target
*as a logged-in user*: a session cookie / bearer token to replay, or
credentials for a login flow. These are **secrets** and are treated as such:

  * Stored encrypted (Fernet / AES-128-CBC + HMAC) in their own table in the
    engagement DB — never in `backend/config.json`, never in plaintext.
  * The encryption key lives in a 0600 keyfile alongside the DB (inside the
    per-user app-data dir), or is supplied via `SIDE_ENGAGEMENT_SECRET_KEY`
    for headless/Linux deployments. The key is never written to config or
    logs either.
  * Only `get_auth()` ever returns the cleartext, and only the safety layer
    calls it — to authenticate to the engagement's *own declared target*.
    Everything user-facing (UI, evidence chain, report, audit entry) goes
    through `redact()` / `auth_meta()`, which expose a reference (kind +
    last4 + username) but never the secret material.

Scoped to one engagement: there is one auth record per engagement, keyed by
`engagement_id`. Deleting the engagement cascades the secret away.
"""
from __future__ import annotations

import json
import logging
import os
import stat
from typing import Any, Literal

from cryptography.fernet import Fernet, InvalidToken

from lib.engagements import _db_path, _now, cursor

logger = logging.getLogger(__name__)

AuthKind = Literal["none", "cookie", "bearer", "credentials"]
VALID_AUTH_KINDS: frozenset[str] = frozenset(
    {"none", "cookie", "bearer", "credentials"}
)

# Fields that hold actual secret material — never echoed back in redacted form.
_SECRET_FIELDS = ("cookie", "token", "password")

# The `engagement_secrets` table is defined in `lib.engagements.SCHEMA` so it's
# created on every connection (including the per-test fresh DB) — no lazy
# bootstrap needed here.


# ── Key material ─────────────────────────────────────────────────────────────

# Cached per key-source string so tests (which redirect _db_path per-test) get
# a fresh Fernet when the keyfile location changes.
_fernet_cache: dict[str, Fernet] = {}


def _keyfile_path():
    # Co-located with the engagement DB so it lands in the same protected
    # per-user app-data dir, and so the `temp_db` test fixture (which redirects
    # _db_path) isolates the key per-test automatically.
    return _db_path().parent / "engagement_secret.key"


def _load_or_create_key() -> bytes:
    """Resolve the Fernet key. Env override first (headless deploys), else a
    0600 keyfile beside the DB, generated on first use."""
    env = os.environ.get("SIDE_ENGAGEMENT_SECRET_KEY", "").strip()
    if env:
        return env.encode("utf-8")

    path = _keyfile_path()
    if path.exists():
        return path.read_bytes().strip()

    key = Fernet.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write with restrictive perms from the start (umask-independent).
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def _fernet() -> Fernet:
    env = os.environ.get("SIDE_ENGAGEMENT_SECRET_KEY", "").strip()
    cache_key = f"env:{env}" if env else f"file:{_keyfile_path()}"
    f = _fernet_cache.get(cache_key)
    if f is None:
        f = Fernet(_load_or_create_key())
        _fernet_cache[cache_key] = f
    return f


# ── Redaction ────────────────────────────────────────────────────────────────

def redact(auth: dict[str, Any] | None) -> dict[str, Any] | None:
    """Project a full auth dict down to a non-secret *reference*.

    Returns kind + a per-kind hint that names the auth without disclosing it:
      * bearer  → last4 of the token
      * cookie  → last4 of the cookie string
      * credentials → username (identity, shown) + login_url; password redacted
    Secret material (cookie / token / password) is NEVER included.
    """
    if not auth:
        return None
    kind = auth.get("kind") or "none"
    meta: dict[str, Any] = {"kind": kind}
    if kind == "bearer":
        tok = auth.get("token") or ""
        meta["has_secret"] = bool(tok)
        if tok:
            meta["last4"] = tok[-4:]
    elif kind == "cookie":
        ck = auth.get("cookie") or ""
        meta["has_secret"] = bool(ck)
        if ck:
            meta["last4"] = ck[-4:]
    elif kind == "credentials":
        meta["username"] = auth.get("username") or ""
        meta["login_url"] = auth.get("login_url") or ""
        meta["has_secret"] = bool(auth.get("password"))
    else:  # none
        meta["has_secret"] = False
    return meta


# ── CRUD ─────────────────────────────────────────────────────────────────────

def set_auth(engagement_id: str, auth: dict[str, Any]) -> dict[str, Any] | None:
    """Encrypt and persist the engagement's auth record. Returns redacted meta.

    `kind == "none"` (or an empty/secret-less record) deletes any existing
    secret rather than storing an empty blob.
    """
    kind = (auth or {}).get("kind") or "none"
    if kind not in VALID_AUTH_KINDS:
        raise ValueError(f"unknown auth kind {kind!r}")

    has_secret = any((auth or {}).get(f) for f in _SECRET_FIELDS)
    if kind == "none" or not has_secret:
        delete_auth(engagement_id)
        return redact({"kind": "none"})

    # Normalise to only the fields we persist, dropping empties.
    payload = {"kind": kind}
    for f in ("cookie", "token", "username", "password", "login_url"):
        v = (auth or {}).get(f)
        if v:
            payload[f] = str(v)

    token = _fernet().encrypt(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    now = _now()
    with cursor() as c:
        c.execute(
            "INSERT INTO engagement_secrets "
            "(engagement_id, kind, ciphertext, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(engagement_id) DO UPDATE SET "
            "kind=excluded.kind, ciphertext=excluded.ciphertext, "
            "updated_at=excluded.updated_at",
            (engagement_id, kind, token, now, now),
        )
    return redact(payload)


def get_auth(engagement_id: str) -> dict[str, Any] | None:
    """Return the DECRYPTED auth dict — server-internal use only.

    Callers must use this *solely* to authenticate to the engagement's own
    declared target, and must never log, return, or forward the cleartext.
    """
    with cursor() as c:
        r = c.execute(
            "SELECT ciphertext FROM engagement_secrets WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()
    if not r or not r["ciphertext"]:
        return None
    try:
        raw = _fernet().decrypt(r["ciphertext"].encode("ascii"))
    except InvalidToken:
        # Key rotated / corrupt blob — fail closed (no auth) rather than raise.
        logger.warning("engagement_secrets: could not decrypt auth for %s "
                       "(key mismatch?)", engagement_id)
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        logger.warning("engagement_secrets: malformed auth payload for %s",
                       engagement_id)
        return None


def auth_meta(engagement_id: str) -> dict[str, Any] | None:
    """Redacted auth reference for the UI. Never returns secret material."""
    return redact(get_auth(engagement_id))


def delete_auth(engagement_id: str) -> bool:
    with cursor() as c:
        c.execute(
            "DELETE FROM engagement_secrets WHERE engagement_id = ?",
            (engagement_id,),
        )
        return c.rowcount > 0
