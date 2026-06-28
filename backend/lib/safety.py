"""Safety layer — the gate between the sealed sandbox and the outside world.

Core principle (see `~/security-engagement-ide-PLAN.md` and CLAUDE.md): the
sealed sandbox is the *default*. Anything that reaches OUTSIDE the box — an
active tool run against an external target — is a deliberate, gated,
attested, and logged exception. This module makes the safe path the default.

Three layers, composed:

  1. ``provenance(target)`` — classify where a target lives:
       * ``"lab"``       internal / sandbox (loopback / private / Tailscale per
                         `lib.target_policy`, or a running lab's host:port — labs
                         bind to loopback so they fall out of the IP-class check
                         automatically). Active runs here are free.
       * ``"owned"``     reserved for code-review of a GitHub repo the user owns.
                         For *live* network targets we never auto-grant this — a
                         live host defaults to ``"external"`` unless lab-class.
       * ``"external"``  everything else. Active runs here are gated.

  2. Attestation store (own ``attestations`` table in engagements.db) — an
     operator's signed statement that they are authorized to actively test a
     set of targets within a time window. ``attestation_for()`` finds a
     non-expired attestation that *covers* a target.

  3. ``require_active_allowed(target, engagement_id)`` — the **hard gate**.
     Lab-class → allow. Otherwise a covering, non-expired attestation is
     mandatory; absent one, raise ``HTTPException(403)``. Server-side and
     non-bypassable: the frontend cannot opt out of it.

Every active action is recorded into the append-only, hash-chained audit
ledger (``lib.audit_log``) via ``audit_active()`` — nothing active is
anonymous.

This module *extends* the existing seams; it does not weaken
``lib.target_policy`` (default-deny external stays) or rewrite scope.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import time
import uuid
from typing import Any, Literal
from urllib.parse import urlparse

from lib.engagements import _now, cursor

logger = logging.getLogger(__name__)

Provenance = Literal["lab", "owned", "external"]


# ── Schema ───────────────────────────────────────────────────────────────────
# Its own table so we don't touch the engagement / audit schemas. Created
# lazily on first use (the engagements connection is shared, so the table
# lives in the same DB file and the same WAL).

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attestations (
  id             TEXT PRIMARY KEY,
  engagement_id  TEXT REFERENCES engagements(id) ON DELETE CASCADE,
  targets        TEXT NOT NULL DEFAULT '[]',   -- JSON list of host/cidr/url strings
  window_start   TEXT NOT NULL,                -- ISO8601 UTC; authorization opens
  window_end     TEXT NOT NULL,                -- ISO8601 UTC; authorization closes
  authority_note TEXT NOT NULL DEFAULT '',     -- who/what authorized this (RoE ref, etc.)
  attested_by    TEXT NOT NULL DEFAULT '',     -- the human taking responsibility
  created_at     TEXT NOT NULL
)
"""
_INDEX = (
    "CREATE INDEX IF NOT EXISTS ix_attestations_engagement "
    "ON attestations(engagement_id, created_at DESC)"
)

_schema_ready = False


def _ensure_schema() -> None:
    global _schema_ready
    if _schema_ready:
        return
    with cursor() as c:
        c.execute(_SCHEMA)
        c.execute(_INDEX)
    _schema_ready = True


# ── Provenance ───────────────────────────────────────────────────────────────

def _host_of(target: str) -> str:
    """Best-effort host extraction: strip URL scheme/path and a trailing port."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        try:
            t = urlparse(t).hostname or t
        except ValueError:
            pass
    # Strip a single `host:port` (but not IPv6, which has many colons / brackets).
    if t.count(":") == 1 and not t.startswith("["):
        t = t.split(":", 1)[0]
    return t.strip("[]").strip(".").lower()


def provenance(target: str) -> Provenance:
    """Classify a target as lab | owned | external.

    "lab" reuses `lib.target_policy`'s IP-class logic: a target that resolves
    to loopback / private / Tailscale (per the policy config) is sandbox-class.
    Running labs bind to 127.0.0.1:<port>, so they classify as lab here too.

    Live network targets that aren't lab-class are "external". "owned" is
    deliberately NOT returned for live targets — it is reserved for the
    GitHub-repo code-review path, which calls `provenance_owned_repo()`
    explicitly rather than passing a network target through here.
    """
    host = _host_of(target)
    if not host:
        return "external"
    # Reuse the policy layer's resolver + IP-class verdict. allow == lab-class
    # (loopback/private/tailscale, or an explicit allow_external entry the user
    # has vouched for). warn/deny == reaches outside the box → external.
    try:
        from lib import target_policy
        verdict, _reason = target_policy.check_target(host)
    except Exception:
        # If classification itself fails, fail closed: treat as external so the
        # attestation gate engages rather than silently allowing.
        logger.exception("provenance: target_policy.check_target failed for %r", host)
        return "external"
    if verdict == "allow":
        return "lab"
    return "external"


def provenance_owned_repo() -> Provenance:
    """Provenance for code-review of a GitHub repo the user owns.

    Separate entry point so the network-target path can't accidentally yield
    "owned". Callers in the code-review flow use this; nothing here grants
    "owned" to a live host.
    """
    return "owned"


# ── Attestation coverage ─────────────────────────────────────────────────────

def _entry_covers(target_host: str, target_ip: Any, entry: str) -> bool:
    """Does one attestation entry (host / CIDR / URL) cover the target?"""
    e_host = _host_of(entry)
    if not e_host:
        return False
    # CIDR / IP entry.
    try:
        net = ipaddress.ip_network(e_host, strict=False)
        if target_ip is not None and target_ip in net:
            return True
        try:
            t_ip = ipaddress.ip_address(target_host)
            if t_ip in net:
                return True
        except ValueError:
            pass
        return False
    except ValueError:
        pass
    # Wildcard subdomain entry.
    if e_host.startswith("*."):
        return target_host.endswith("." + e_host[2:])
    # Bare host: exact OR subdomain (standard scope contract).
    return target_host == e_host or target_host.endswith("." + e_host)


def _resolve_optional(host: str) -> Any:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        from lib.target_policy import _resolve
        ips = _resolve(host)
        return ips[0] if ips else None
    except Exception:
        return None


def _is_active_window(att: dict[str, Any], now: str) -> bool:
    ws = att.get("window_start") or ""
    we = att.get("window_end") or ""
    # Lexicographic compare is correct for ISO8601 UTC strings of equal shape.
    return bool(ws) and bool(we) and ws <= now <= we


# ── Attestation CRUD ─────────────────────────────────────────────────────────

def create_attestation(
    *,
    engagement_id: str | None,
    targets: list[str],
    window_start: str,
    window_end: str,
    authority_note: str = "",
    attested_by: str = "",
) -> dict[str, Any]:
    """Record an authorization attestation. Returns the stored row."""
    _ensure_schema()
    aid = uuid.uuid4().hex
    now = _now()
    clean_targets = [str(t).strip() for t in (targets or []) if str(t).strip()]
    with cursor() as c:
        c.execute(
            "INSERT INTO attestations "
            "(id, engagement_id, targets, window_start, window_end, "
            " authority_note, attested_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (aid, engagement_id, json.dumps(clean_targets),
             window_start, window_end, authority_note, attested_by, now),
        )
    return get_attestation(aid)  # type: ignore[return-value]


def get_attestation(aid: str) -> dict[str, Any] | None:
    _ensure_schema()
    with cursor() as c:
        r = c.execute("SELECT * FROM attestations WHERE id = ?", (aid,)).fetchone()
        return _row(r) if r else None


def list_attestations(engagement_id: str | None) -> list[dict[str, Any]]:
    _ensure_schema()
    with cursor() as c:
        if engagement_id:
            rows = c.execute(
                "SELECT * FROM attestations WHERE engagement_id = ? "
                "ORDER BY created_at DESC",
                (engagement_id,),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM attestations ORDER BY created_at DESC"
            ).fetchall()
        return [_row(r) for r in rows]


def attestation_for(target: str, engagement_id: str | None) -> str | None:
    """Return the id of a NON-EXPIRED attestation that covers `target`, or None.

    Scoped to the active engagement when one is supplied (an attestation tied
    to engagement A must not authorize a run booked under engagement B);
    engagement-less attestations are considered when no engagement is given.
    """
    _ensure_schema()
    host = _host_of(target)
    if not host:
        return None
    ip = _resolve_optional(host)
    now = _now()
    for att in list_attestations(engagement_id):
        if not _is_active_window(att, now):
            continue
        for entry in att.get("targets") or []:
            if _entry_covers(host, ip, entry):
                return att["id"]
    return None


def _row(r: Any) -> dict[str, Any]:
    try:
        targets = json.loads(r["targets"] or "[]")
    except (json.JSONDecodeError, TypeError):
        targets = []
    return {
        "id":             r["id"],
        "engagement_id":  r["engagement_id"],
        "targets":        targets,
        "window_start":   r["window_start"],
        "window_end":     r["window_end"],
        "authority_note": r["authority_note"] or "",
        "attested_by":    r["attested_by"] or "",
        "created_at":     r["created_at"],
    }


# ── The hard gate ────────────────────────────────────────────────────────────

def require_active_allowed(target: str, engagement_id: str | None) -> str | None:
    """Gate an ACTIVE run against a target. Server-side, non-bypassable.

    * Lab-class target (provenance == "lab") → allow, return None (no
      attestation needed; the sandbox is the default-safe path).
    * Otherwise a covering, non-expired attestation is REQUIRED. If found,
      return its id (which the caller records into the audit ledger). If not,
      raise HTTPException(403).
    """
    from fastapi import HTTPException

    if provenance(target) == "lab":
        return None
    aid = attestation_for(target, engagement_id)
    if aid is None:
        raise HTTPException(
            status_code=403,
            detail=(
                "active run blocked: external target requires an "
                "authorization attestation"
            ),
        )
    return aid


def audit_active(
    action: str,
    target: str,
    provenance: str,  # noqa: A002 - mirrors the documented record shape
    params: dict[str, Any] | None = None,
    attestation_id: str | None = None,
) -> str | None:
    """Append an active-action record to the hash-chained audit ledger.

    Maps the documented record `{action, target, provenance, params,
    attestation_id, timestamp}` onto `lib.audit_log.start()` so it inherits
    the append-only {prev_hash, row_hash} chaining. The provenance + the
    attestation id ride along in argv (immutable / chained fields) so the
    ledger row carries *why* the run was allowed. Nothing active is anonymous.

    Returns the audit row id, or None if the ledger write fails (which must
    never block the gate decision itself).
    """
    from lib import audit_log

    argv = [
        f"provenance={provenance}",
        f"attestation_id={attestation_id or 'none'}",
    ]
    if params:
        try:
            argv.append("params=" + json.dumps(params, default=str, separators=(",", ":")))
        except Exception:
            argv.append("params=<unserializable>")
    try:
        aid = audit_log.start(
            tool=action,
            target=target,
            argv=argv,
            engagement_id=(params or {}).get("engagement_id"),
            approver=(attestation_id or "local"),
        )
        # The run itself is recorded by the tool's own audit lifecycle; this
        # row is the authorization anchor, so close it out immediately.
        audit_log.complete(
            aid,
            summary=f"active {action} on {target} ({provenance}); "
                    f"attestation={attestation_id or 'n/a'}",
        )
        return aid
    except Exception:
        logger.exception("audit_active: ledger write failed for %s/%s", action, target)
        return None


# ── Timestamp helper for callers that build windows ──────────────────────────

def now_iso() -> str:
    """ISO8601 UTC 'now' matching the engagements/audit timestamp shape."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
