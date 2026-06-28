"""Audit log — append-only record of every tool invocation.

Distinct from `lib/audit.py`, which is the Network-Audit (LAN port-sweep)
feature. *This* module is the v1.0 audit log surfaced by the `/audit`
page and consumed by the engagement report.

Storage lives in the same SQLite DB as engagements (see
`lib/engagements.py` for the schema). Rows are INSERTed at action start
and UPDATEd once at end — we never DELETE. Append-only means "the API
won't let you mutate history", not "we re-INSERT for completion."

Typical usage from a router::

    from lib import audit_log

    aid = audit_log.start(
        tool="port_scanner",
        target=", ".join(opts.targets),
        argv=["nmap", "-sT", ...],
        engagement_id=engagement_id,
    )
    try:
        result = await run_scan(...)
    except Exception as e:
        audit_log.error(aid, str(e))
        raise
    audit_log.complete(aid, summary=f"{result.open_count} open ports")

Or wrap with the context manager::

    with audit_log.action(tool="port_scanner", target=..., argv=[...]) as a:
        result = await run_scan(...)
        a.summary = f"{result.open_count} open ports"

If something raises inside the `with`, the context manager records the
error and re-raises.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from lib.engagements import _now, cursor  # reuse the same connection + WAL setup

logger = logging.getLogger(__name__)

_VALID_STATUS = {"started", "completed", "error", "stopped"}
_VALID_MODE = {"lab", "engagement"}


# ── Redaction ────────────────────────────────────────────────────────────────
# Strip obvious credential shapes from argv before persistence. Heuristic and
# conservative — better to leave the operator's own scan parameters visible
# than mask them — but blocks the highest-risk leaks (NTLM hashes from
# hash_cracker, plaintext passwords following -p, AWS keys).

_RE_NTLM = re.compile(r"^[A-Fa-f0-9]{32}(:[A-Fa-f0-9]{32})?$")
_RE_AWS_KEY = re.compile(r"^AKIA[0-9A-Z]{16}$")
_RE_AWS_SECRET = re.compile(r"^[A-Za-z0-9/+=]{40}$")
_PASSWORD_FLAG_TOKENS = {"-p", "--password", "--pass", "-w", "--token"}
_REDACTED = "[redacted]"


def _redact_argv(argv: list[str]) -> list[str]:
    """Replace likely-credential tokens with [redacted].

    Only acts on argv elements; doesn't touch tool/target/summary. Errs on
    the side of leaving things visible — argv that looks normal stays.
    """
    out: list[str] = []
    redact_next = False
    for token in argv:
        if redact_next:
            out.append(_REDACTED)
            redact_next = False
            continue
        if token in _PASSWORD_FLAG_TOKENS:
            out.append(token)
            redact_next = True
            continue
        # Spot-check for credential-shaped values.
        if _RE_NTLM.match(token) or _RE_AWS_KEY.match(token) or _RE_AWS_SECRET.match(token):
            out.append(_REDACTED)
            continue
        out.append(token)
    return out


# ── Hash chain ───────────────────────────────────────────────────────────────
# Each row's row_hash = sha256(prev_hash || canonical_immutable_fields). On
# read, verify_chain() walks the table and refuses if any row's prev_hash
# doesn't match the previous row_hash, or any row_hash doesn't match its own
# recomputed value. Detects DELETE FROM audit_log, INSERTs, and reorders.
# Field-level edits to mutable fields (ts_end, status, summary, error) are
# NOT detected — that's a known tradeoff so the UPDATE-after-INSERT pattern
# of start→complete still works without re-chaining every row downstream.


def _canonical_immutable(
    aid: str, ts_start: str, tool: str, target: str,
    argv_json: str, engagement_id: str | None, mode: str, approver: str,
) -> str:
    return json.dumps(
        [aid, ts_start, tool, target, argv_json, engagement_id or "", mode, approver],
        separators=(",", ":"), ensure_ascii=False,
    )


def _compute_row_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def verify_chain() -> tuple[bool, str | None]:
    """Walk the audit_log oldest-first and return (ok, first_bad_id)."""
    prev = ""
    with cursor() as c:
        c.execute(
            "SELECT id, ts_start, tool, target, argv_json, engagement_id, "
            "mode, approver, prev_hash, row_hash FROM audit_log "
            "ORDER BY ts_start ASC, id ASC"
        )
        for r in c.fetchall():
            if (r["prev_hash"] or "") != prev:
                return False, r["id"]
            canonical = _canonical_immutable(
                r["id"], r["ts_start"], r["tool"], r["target"], r["argv_json"],
                r["engagement_id"], r["mode"], r["approver"],
            )
            expected = _compute_row_hash(prev, canonical)
            if (r["row_hash"] or "") != expected:
                return False, r["id"]
            prev = r["row_hash"]
    return True, None


def start(
    *,
    tool: str,
    target: str = "",
    argv: list[str] | None = None,
    engagement_id: str | None = None,
    approver: str = "local",
    mode: str | None = None,
) -> str:
    """Insert a `started` row and return its id.

    `mode` defaults to "engagement" when an engagement_id is present, "lab"
    otherwise. Callers can override.
    """
    aid = uuid.uuid4().hex
    if mode is None:
        mode = "engagement" if engagement_id else "lab"
    if mode not in _VALID_MODE:
        mode = "lab"
    argv_json = json.dumps(_redact_argv(list(argv or [])))
    ts_start = _now()
    with cursor() as c:
        c.execute(
            "SELECT row_hash FROM audit_log "
            "ORDER BY ts_start DESC, id DESC LIMIT 1"
        )
        last = c.fetchone()
        prev_hash = (last["row_hash"] if last else "") or ""
        canonical = _canonical_immutable(
            aid, ts_start, tool, target, argv_json, engagement_id, mode, approver,
        )
        row_hash = _compute_row_hash(prev_hash, canonical)
        c.execute(
            "INSERT INTO audit_log "
            "(id, engagement_id, ts_start, tool, target, argv_json, approver, "
            " mode, status, prev_hash, row_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'started', ?, ?)",
            (aid, engagement_id, ts_start, tool, target, argv_json,
             approver, mode, prev_hash, row_hash),
        )
    return aid


def complete(action_id: str, *, summary: str = "") -> None:
    """Finalize a row as `completed`. Idempotent — no-op if id unknown."""
    with cursor() as c:
        c.execute(
            "UPDATE audit_log SET ts_end = ?, status = 'completed', summary = ? "
            "WHERE id = ? AND status = 'started'",
            (_now(), summary[:2000], action_id),
        )


def error(action_id: str, message: str, *, summary: str = "") -> None:
    """Finalize a row as `error` with the failure message."""
    with cursor() as c:
        c.execute(
            "UPDATE audit_log SET ts_end = ?, status = 'error', error = ?, summary = ? "
            "WHERE id = ? AND status = 'started'",
            (_now(), message[:2000], summary[:2000], action_id),
        )


def stopped(action_id: str, *, summary: str = "") -> None:
    """Finalize a row as `stopped` (user clicked Stop on the scan)."""
    with cursor() as c:
        c.execute(
            "UPDATE audit_log SET ts_end = ?, status = 'stopped', summary = ? "
            "WHERE id = ? AND status = 'started'",
            (_now(), summary[:2000], action_id),
        )


@contextmanager
def action(
    *,
    tool: str,
    target: str = "",
    argv: list[str] | None = None,
    engagement_id: str | None = None,
    approver: str = "local",
    mode: str | None = None,
) -> Iterator["_ActionCtx"]:
    """Context manager that records start/end. Assign `.summary` inside.

    Any exception in the block is recorded and re-raised.
    """
    aid = start(tool=tool, target=target, argv=argv, engagement_id=engagement_id,
                approver=approver, mode=mode)
    ctx = _ActionCtx(aid)
    try:
        yield ctx
    except Exception as e:
        error(aid, f"{type(e).__name__}: {e}", summary=ctx.summary)
        raise
    else:
        if ctx.status == "stopped":
            stopped(aid, summary=ctx.summary)
        else:
            complete(aid, summary=ctx.summary)


class _ActionCtx:
    """Mutable handle yielded by `action()`."""

    __slots__ = ("id", "summary", "status")

    def __init__(self, action_id: str) -> None:
        self.id = action_id
        self.summary: str = ""
        self.status: str = "completed"

    def mark_stopped(self) -> None:
        self.status = "stopped"


# ── Reads ────────────────────────────────────────────────────────────────────

def list_actions(
    *,
    engagement_id: str | None = None,
    tool: str | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return rows newest-first, with optional filters."""
    where: list[str] = []
    params: list[Any] = []
    if engagement_id is not None:
        where.append("engagement_id = ?")
        params.append(engagement_id)
    if tool:
        where.append("tool = ?")
        params.append(tool)
    if status and status in _VALID_STATUS:
        where.append("status = ?")
        params.append(status)
    sql = (
        "SELECT id, engagement_id, ts_start, ts_end, tool, target, "
        "argv_json, approver, mode, status, summary, error "
        "FROM audit_log"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts_start DESC LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    with cursor() as c:
        c.execute(sql, tuple(params))
        return [_row_to_dict(r) for r in c.fetchall()]


def get_action(action_id: str) -> dict[str, Any] | None:
    with cursor() as c:
        c.execute(
            "SELECT id, engagement_id, ts_start, ts_end, tool, target, "
            "argv_json, approver, mode, status, summary, error "
            "FROM audit_log WHERE id = ?",
            (action_id,),
        )
        row = c.fetchone()
        return _row_to_dict(row) if row else None


def tool_counts() -> list[dict[str, Any]]:
    """Aggregate: invocations per tool with completed/error/stopped split."""
    with cursor() as c:
        c.execute(
            "SELECT tool, status, COUNT(*) as n FROM audit_log GROUP BY tool, status"
        )
        rows = c.fetchall()
    agg: dict[str, dict[str, int]] = {}
    for r in rows:
        agg.setdefault(r["tool"], {"completed": 0, "error": 0, "stopped": 0, "started": 0})
        agg[r["tool"]][r["status"]] = r["n"]
    out: list[dict[str, Any]] = []
    for tool, by_status in sorted(agg.items()):
        total = sum(by_status.values())
        out.append({"tool": tool, "total": total, **by_status})
    return out


def _row_to_dict(r: Any) -> dict[str, Any]:
    try:
        argv = json.loads(r["argv_json"]) if r["argv_json"] else []
    except (json.JSONDecodeError, TypeError):
        argv = []
    return {
        "id":            r["id"],
        "engagement_id": r["engagement_id"],
        "ts_start":      r["ts_start"],
        "ts_end":        r["ts_end"],
        "tool":          r["tool"],
        "target":        r["target"],
        "argv":          argv,
        "approver":      r["approver"],
        "mode":          r["mode"],
        "status":        r["status"],
        "summary":       r["summary"],
        "error":         r["error"],
    }
