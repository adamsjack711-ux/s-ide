"""Targets registry — first-class objects representing things tools can run against.

A target is anything with an address: a managed lab endpoint, a manually
entered IP/URL, a Tailscale peer, an SSH config host, or a host found on
the LAN. The registry lives in the same SQLite store as engagements
(``engagements.db``) so engagement-scoped targets can FK-reference their
engagement and get cascade-deleted with it.

Engagement model
----------------
``engagement_id`` is nullable:
  * NULL = global (lab targets, manual scratch, fresh discovery results)
  * Set  = bound to that engagement; cascade-deletes when the engagement does

When the active engagement is set in the UI, the Targets page lists both
its bound targets + the global pool. Tool pages prefer the active target
for prefill regardless of binding.

``scope_tag`` is the policy band used by ``lib/scope.py`` in engagement
mode: ``lab`` (skip scope check), ``owned`` / ``authorized`` (in-scope by
ownership), or ``manual`` (no automatic policy — caller decides). Today
``scope_tag`` is informational; future engagement scope enforcement will
read it to decide whether to gate a tool run.

``kind`` is where the target came from (informational + UI grouping):
``lab`` | ``manual`` | ``tailscale`` | ``ssh`` | ``lan``.

``hidden`` is used for lab targets after the lab stops — we soft-delete
so the lab-intent prefill keeps working across stop/start cycles and the
audit log keeps its FK references stable.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from lib.engagements import cursor, _now


# Sentinel for "don't filter on engagement_id" on find_by_meta(). Distinct
# from ``None`` so callers can ask explicitly for global rows (engagement_id
# IS NULL) without the default behaviour collapsing the two cases.
_ANY_ENGAGEMENT: Any = object()


# ── Public API ───────────────────────────────────────────────────────────────
def list_targets(
    engagement_id: str | None = None,
    kind: str | None = None,
    include_hidden: bool = False,
) -> list[dict[str, Any]]:
    """List targets.

    Filters:
      * ``engagement_id="<id>"`` — bound to that engagement only.
      * ``engagement_id=None`` (default) — every target (global + every
        engagement's). The UI typically calls this on the global Targets
        page and groups in the renderer.
      * ``kind="lab"`` etc. — restrict to one source.
      * ``include_hidden=True`` — include soft-deleted lab rows.
    """
    q = "SELECT * FROM targets"
    where: list[str] = []
    params: list[Any] = []
    if engagement_id is not None:
        where.append("engagement_id = ?")
        params.append(engagement_id)
    if kind is not None:
        where.append("kind = ?")
        params.append(kind)
    if not include_hidden:
        where.append("hidden = 0")
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY added_at DESC"
    with cursor() as c:
        return [_row_to_target(r) for r in c.execute(q, params).fetchall()]


def get_target(tid: str) -> dict[str, Any] | None:
    with cursor() as c:
        r = c.execute("SELECT * FROM targets WHERE id = ?", (tid,)).fetchone()
        return _row_to_target(r) if r else None


def create_target(
    name: str,
    address: str,
    kind: str,
    *,
    engagement_id: str | None = None,
    source_meta: dict[str, Any] | None = None,
    scope_tag: str = "manual",
) -> dict[str, Any]:
    tid = str(uuid.uuid4())
    now = _now()
    with cursor() as c:
        c.execute(
            "INSERT INTO targets (id, engagement_id, name, address, kind, "
            "source_meta, scope_tag, added_at, last_seen_at, hidden) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (tid, engagement_id, name, address, kind,
             json.dumps(source_meta or {}), scope_tag, now, now),
        )
    return get_target(tid)  # type: ignore[return-value]


def update_target(tid: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    fields: list[str] = []
    values: list[Any] = []
    for key in ("name", "address", "kind", "scope_tag", "engagement_id"):
        if key in patch:
            fields.append(f"{key} = ?")
            values.append(patch[key])
    if "source_meta" in patch:
        fields.append("source_meta = ?")
        values.append(json.dumps(patch["source_meta"] or {}))
    if "hidden" in patch:
        fields.append("hidden = ?")
        values.append(1 if patch["hidden"] else 0)
    if not fields:
        return get_target(tid)
    values.append(tid)
    with cursor() as c:
        c.execute(f"UPDATE targets SET {', '.join(fields)} WHERE id = ?", values)
    return get_target(tid)


def delete_target(tid: str) -> bool:
    with cursor() as c:
        c.execute("DELETE FROM targets WHERE id = ?", (tid,))
        return c.rowcount > 0


def touch_last_seen(tid: str) -> None:
    with cursor() as c:
        c.execute("UPDATE targets SET last_seen_at = ?, hidden = 0 WHERE id = ?",
                  (_now(), tid))


def upsert_lab_target(
    lab_id: str,
    lab_name: str,
    host_port: int,
    container_port: int,
    primary_url: str = "",
    *,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Idempotent insert/refresh of a lab-derived target.

    If a target with ``kind='lab'`` and matching ``(lab_id, host_port,
    engagement_id)`` in its source_meta already exists, it's unhidden and
    last_seen_at is touched. Otherwise a fresh row is inserted.

    Address is ``127.0.0.1:<host_port>`` (or the bare URL when the lab
    publishes its primary on this port). Name is ``<lab_name> :<host_port>``.

    ``engagement_id`` keyword:
      * ``None`` (default) — global lab target, behaves like before.
        Used by the auto-register hook on lab start.
      * Set      — engagement-bound target. The "attach lab to engagement"
        flow creates a separate row per engagement so each scope sees its
        own copy in its targets list and survives the engagement being
        deleted (cascade).
    """
    # Scope the dedupe lookup to the target engagement — global rows and
    # engagement-bound rows live side-by-side, so passing the explicit id
    # here is what keeps the upsert idempotent per (lab, port, engagement).
    existing = find_by_meta(lab_id, host_port, engagement_id=engagement_id)
    address = f"127.0.0.1:{host_port}"
    name = f"{lab_name} :{host_port}"
    meta = {
        "lab_id":         lab_id,
        "host_port":      host_port,
        "container_port": container_port,
        "primary_url":    primary_url,
    }
    if existing:
        update_target(existing["id"], {
            "name":        name,
            "address":     address,
            "source_meta": meta,
            "hidden":      False,
        })
        touch_last_seen(existing["id"])
        return get_target(existing["id"])  # type: ignore[return-value]
    return create_target(
        name=name,
        address=address,
        kind="lab",
        engagement_id=engagement_id,
        source_meta=meta,
        scope_tag="lab",
    )


def find_by_meta(
    lab_id: str,
    host_port: int | None = None,
    *,
    engagement_id: str | None | Any = _ANY_ENGAGEMENT,
) -> dict[str, Any] | None:
    """Look up a lab-derived target by its lab_id (and optionally host port).

    Used by the auto-register hook to upsert idempotently when a lab is
    re-started: the existing record is unhidden + last_seen_at touched,
    rather than a duplicate row being inserted.

    ``engagement_id`` keyword (tri-state via _ANY_ENGAGEMENT sentinel):
      * Omitted (default ``_ANY_ENGAGEMENT``) — match any engagement scope;
        first hit wins. Preserves the old call shape for callers that don't
        care which engagement the row belongs to.
      * ``None``    — match only the global pool (engagement_id IS NULL).
      * ``"<eid>"`` — match only rows bound to that engagement.
    """
    with cursor() as c:
        rows = c.execute(
            "SELECT * FROM targets WHERE kind = 'lab' "
            "ORDER BY added_at DESC"
        ).fetchall()
    for r in rows:
        try:
            meta = json.loads(r["source_meta"] or "{}")
        except json.JSONDecodeError:
            continue
        if meta.get("lab_id") != lab_id:
            continue
        if host_port is not None and meta.get("host_port") != host_port:
            continue
        if engagement_id is not _ANY_ENGAGEMENT:
            if (r["engagement_id"] or None) != engagement_id:
                continue
        return _row_to_target(r)
    return None


def hide_lab_targets(lab_id: str) -> int:
    """Mark every lab-derived target for ``lab_id`` as hidden. Returns the
    count of rows touched. Used on lab stop to drop them from the default
    UI list while keeping the rows for the audit log + future restarts."""
    with cursor() as c:
        rows = c.execute(
            "SELECT id, source_meta FROM targets WHERE kind = 'lab'"
        ).fetchall()
        count = 0
        for r in rows:
            try:
                meta = json.loads(r["source_meta"] or "{}")
            except json.JSONDecodeError:
                continue
            if meta.get("lab_id") == lab_id:
                c.execute("UPDATE targets SET hidden = 1 WHERE id = ?", (r["id"],))
                count += 1
        return count


# ── Internals ────────────────────────────────────────────────────────────────
def _row_to_target(r: sqlite3.Row) -> dict[str, Any]:
    try:
        source_meta = json.loads(r["source_meta"] or "{}")
    except json.JSONDecodeError:
        source_meta = {}
    return {
        "id":            r["id"],
        "engagement_id": r["engagement_id"],
        "name":          r["name"],
        "address":       r["address"],
        "kind":          r["kind"],
        "source_meta":   source_meta,
        "scope_tag":     r["scope_tag"],
        "added_at":      r["added_at"],
        "last_seen_at":  r["last_seen_at"],
        "hidden":        bool(r["hidden"]),
    }
