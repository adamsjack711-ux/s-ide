"""The engagement spine — Target / Sub-target / Engagement / pairing domain model.

This is the core authorization model for s-ide. One rule governs everything:

    **Authorization flows from the engagement, never from a target existing.**

The four nouns:

  * **Target** — a system/application being *described*. Inert. Holds no scope
    and authorizes nothing. Has provenance (``lab`` / ``owned`` / ``external``),
    a name, and metadata only.
  * **Sub-target** — an addressable component of a Target (host / service / url /
    endpoint / directory). Inert and *un-armed* until an engagement is attached.
    A tool or playbook can only fire at a sub-target that is currently armed.
  * **Engagement** — the authorized context (owns scope + attestation; defined in
    ``lib.engagements`` + ``lib.safety``). *Attaching* an engagement to a
    sub-target **arms** it. One engagement may arm many sub-targets; each
    attachment is a separate explicit act. A sub-target carries at most one
    active arming at a time, so "the engagement that arms it" is unambiguous.
  * **Pairing / run** — engagement × sub-target. The only unit that executes.
    Target alone = inert; engagement alone = no surface; only the armed pairing
    runs.

Arming rules (the safety core):

  * A sub-target with no engagement attached is **un-armed** — tools/playbooks
    against it are refused server-side (``require_armed`` raises 403). Un-armed
    is the default for every newly-declared sub-target.
  * Arming = attaching an engagement (which carries scope + attestation). The
    attachment brings the sub-target into that engagement's scope; the parent
    Target never confers scope.
  * Disarming (detaching the engagement) returns the sub-target to inert.
    Nothing stays armed implicitly.

This module *extends* the existing seams. It adds its own tables to the shared
``engagements.db`` (created lazily, like ``lib.safety``), reuses the
``engagements`` table for the authorized context, the ``findings`` table for
evidence, and ``lib.scope`` + ``lib.safety`` for the run-time enforcement
(scope default-deny + attestation hard-gate). It does **not** weaken
``target_policy`` or touch the existing ``targets`` registry (which stays the
tool-prefill / lab-autoregister layer).
"""
from __future__ import annotations

import json
import logging
import socket
import uuid
from typing import Any, Literal

from lib.engagements import _now, cursor, get_engagement

logger = logging.getLogger(__name__)

Provenance = Literal["lab", "owned", "external"]
SubTargetType = Literal["host", "service", "url", "endpoint", "directory"]

VALID_PROVENANCE: frozenset[str] = frozenset({"lab", "owned", "external"})
VALID_SUBTARGET_TYPE: frozenset[str] = frozenset(
    {"host", "service", "url", "endpoint", "directory"}
)


# ── Schema ───────────────────────────────────────────────────────────────────
# Own tables so the core engagement / findings schemas are untouched. Created
# lazily on first use — the engagements connection is shared, so these live in
# the same DB file + WAL and inherit PRAGMA foreign_keys=ON.

_SCHEMA = [
    # A Target is inert: provenance + name + metadata. It authorizes nothing.
    """
    CREATE TABLE IF NOT EXISTS spine_targets (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      provenance  TEXT NOT NULL DEFAULT 'external',   -- lab|owned|external
      metadata    TEXT NOT NULL DEFAULT '{}',
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL
    )
    """,
    # A sub-target is an addressable component of a Target. Un-armed by default —
    # there is no scope or engagement column here; arming lives in spine_armings.
    """
    CREATE TABLE IF NOT EXISTS spine_subtargets (
      id          TEXT PRIMARY KEY,
      target_id   TEXT NOT NULL REFERENCES spine_targets(id) ON DELETE CASCADE,
      type        TEXT NOT NULL,                       -- host|service|url|endpoint|directory
      address     TEXT NOT NULL,                       -- the addressable string
      label       TEXT NOT NULL DEFAULT '',
      metadata    TEXT NOT NULL DEFAULT '{}',
      created_at  TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_spine_subtargets_target ON spine_subtargets(target_id)",
    # An arming = an engagement attached to a sub-target. detached_at NULL means
    # the arming is ACTIVE (the sub-target is armed). Detaching sets detached_at,
    # preserving the history. At most one active arming per sub-target is enforced
    # in code (arm() refuses a second active attachment).
    """
    CREATE TABLE IF NOT EXISTS spine_armings (
      id             TEXT PRIMARY KEY,
      sub_target_id  TEXT NOT NULL REFERENCES spine_subtargets(id) ON DELETE CASCADE,
      engagement_id  TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
      armed_at       TEXT NOT NULL,
      detached_at    TEXT                                -- NULL = active arming
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_spine_armings_sub ON spine_armings(sub_target_id, detached_at)",
    "CREATE INDEX IF NOT EXISTS ix_spine_armings_eng ON spine_armings(engagement_id, detached_at)",
    # A pairing run = the execution of a tool against an armed sub-target. Carries
    # the arming engagement id (the run's authorized context) + the rolled-up
    # target id so provenance is exact.
    """
    CREATE TABLE IF NOT EXISTS spine_runs (
      id             TEXT PRIMARY KEY,
      sub_target_id  TEXT NOT NULL REFERENCES spine_subtargets(id) ON DELETE CASCADE,
      engagement_id  TEXT NOT NULL,
      target_id      TEXT NOT NULL,
      tool           TEXT NOT NULL DEFAULT '',
      status         TEXT NOT NULL DEFAULT 'started',   -- started|completed|error|refused
      started_at     TEXT NOT NULL,
      ended_at       TEXT,
      output         TEXT NOT NULL DEFAULT '',
      summary        TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_spine_runs_sub ON spine_runs(sub_target_id, started_at DESC)",
    # Finding provenance — links a finding (in the existing findings table) to the
    # exact engagement × sub-target pairing it was born from, plus the rolled-up
    # target id so a Target's findings = union across its sub-targets.
    """
    CREATE TABLE IF NOT EXISTS spine_finding_links (
      finding_id     TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
      engagement_id  TEXT NOT NULL,
      sub_target_id  TEXT NOT NULL,
      target_id      TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_spine_links_target ON spine_finding_links(target_id)",
    "CREATE INDEX IF NOT EXISTS ix_spine_links_sub ON spine_finding_links(sub_target_id)",
    "CREATE INDEX IF NOT EXISTS ix_spine_links_eng ON spine_finding_links(engagement_id)",
]

# Keyed on the live connection object rather than a sticky bool: if the
# engagements connection is swapped (a test redirecting the DB, or a backend
# reconnect), the schema is re-created against the new connection instead of
# being skipped because a previous one already had the tables.
_schema_conn: Any = None


def _ensure_schema() -> None:
    global _schema_conn
    from lib import engagements as _eng

    conn = _eng._connect()
    if _schema_conn is conn:
        return
    with cursor() as c:
        for stmt in _SCHEMA:
            c.execute(stmt)
    _schema_conn = conn


# ── Targets (inert) ──────────────────────────────────────────────────────────

def list_targets() -> list[dict[str, Any]]:
    _ensure_schema()
    with cursor() as c:
        rows = c.execute(
            "SELECT * FROM spine_targets ORDER BY created_at DESC"
        ).fetchall()
    return [_row_target(r) for r in rows]


def get_target(tid: str) -> dict[str, Any] | None:
    _ensure_schema()
    with cursor() as c:
        r = c.execute("SELECT * FROM spine_targets WHERE id = ?", (tid,)).fetchone()
    return _row_target(r) if r else None


def create_target(
    name: str,
    provenance: str = "external",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if provenance not in VALID_PROVENANCE:
        raise ValueError(f"unknown provenance {provenance!r}")
    _ensure_schema()
    tid = uuid.uuid4().hex
    now = _now()
    with cursor() as c:
        c.execute(
            "INSERT INTO spine_targets (id, name, provenance, metadata, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (tid, name, provenance, json.dumps(metadata or {}), now, now),
        )
    return get_target(tid)  # type: ignore[return-value]


def update_target(tid: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    _ensure_schema()
    fields: list[str] = []
    values: list[Any] = []
    if "name" in patch:
        fields.append("name = ?")
        values.append(patch["name"])
    if "provenance" in patch:
        if patch["provenance"] not in VALID_PROVENANCE:
            raise ValueError(f"unknown provenance {patch['provenance']!r}")
        fields.append("provenance = ?")
        values.append(patch["provenance"])
    if "metadata" in patch:
        fields.append("metadata = ?")
        values.append(json.dumps(patch["metadata"] or {}))
    if not fields:
        return get_target(tid)
    fields.append("updated_at = ?")
    values.append(_now())
    values.append(tid)
    with cursor() as c:
        c.execute(f"UPDATE spine_targets SET {', '.join(fields)} WHERE id = ?", values)
    return get_target(tid)


def delete_target(tid: str) -> bool:
    _ensure_schema()
    with cursor() as c:
        c.execute("DELETE FROM spine_targets WHERE id = ?", (tid,))
        return c.rowcount > 0


# ── Sub-targets (inert + un-armed by default) ────────────────────────────────

def list_sub_targets(target_id: str) -> list[dict[str, Any]]:
    _ensure_schema()
    with cursor() as c:
        rows = c.execute(
            "SELECT * FROM spine_subtargets WHERE target_id = ? ORDER BY created_at",
            (target_id,),
        ).fetchall()
    return [_row_subtarget(r) for r in rows]


def get_sub_target(sid: str) -> dict[str, Any] | None:
    _ensure_schema()
    with cursor() as c:
        r = c.execute(
            "SELECT * FROM spine_subtargets WHERE id = ?", (sid,)
        ).fetchone()
    return _row_subtarget(r) if r else None


def create_sub_target(
    target_id: str,
    type: str,  # noqa: A002 - mirrors the domain vocabulary
    address: str,
    label: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if type not in VALID_SUBTARGET_TYPE:
        raise ValueError(f"unknown sub-target type {type!r}")
    if get_target(target_id) is None:
        raise ValueError(f"target not found: {target_id}")
    _ensure_schema()
    sid = uuid.uuid4().hex
    now = _now()
    with cursor() as c:
        c.execute(
            "INSERT INTO spine_subtargets (id, target_id, type, address, label, "
            "metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sid, target_id, type, address, label, json.dumps(metadata or {}), now),
        )
    return get_sub_target(sid)  # type: ignore[return-value]


def update_sub_target(sid: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    _ensure_schema()
    fields: list[str] = []
    values: list[Any] = []
    if "type" in patch:
        if patch["type"] not in VALID_SUBTARGET_TYPE:
            raise ValueError(f"unknown sub-target type {patch['type']!r}")
        fields.append("type = ?")
        values.append(patch["type"])
    for key in ("address", "label"):
        if key in patch:
            fields.append(f"{key} = ?")
            values.append(patch[key])
    if "metadata" in patch:
        fields.append("metadata = ?")
        values.append(json.dumps(patch["metadata"] or {}))
    if not fields:
        return get_sub_target(sid)
    values.append(sid)
    with cursor() as c:
        c.execute(f"UPDATE spine_subtargets SET {', '.join(fields)} WHERE id = ?", values)
    return get_sub_target(sid)


def delete_sub_target(sid: str) -> bool:
    _ensure_schema()
    with cursor() as c:
        c.execute("DELETE FROM spine_subtargets WHERE id = ?", (sid,))
        return c.rowcount > 0


# ── Arming (the safety core) ─────────────────────────────────────────────────

def current_arming(sub_target_id: str) -> dict[str, Any] | None:
    """The active arming for a sub-target, or None if it's un-armed.

    A sub-target carries at most one active arming (detached_at IS NULL). The
    returned dict carries the arming engagement_id + name so callers can show
    which engagement arms the sub-target.
    """
    _ensure_schema()
    with cursor() as c:
        r = c.execute(
            "SELECT * FROM spine_armings WHERE sub_target_id = ? "
            "AND detached_at IS NULL ORDER BY armed_at DESC LIMIT 1",
            (sub_target_id,),
        ).fetchone()
    if not r:
        return None
    arming = _row_arming(r)
    eng = get_engagement(arming["engagement_id"])
    arming["engagement_name"] = (eng or {}).get("name") if eng else None
    return arming


def is_armed(sub_target_id: str) -> bool:
    return current_arming(sub_target_id) is not None


def arm(sub_target_id: str, engagement_id: str) -> dict[str, Any]:
    """Attach an engagement to a sub-target — the deliberate act that arms it.

    Idempotent for the same engagement (returns the existing active arming).
    Refuses (ValueError) to arm a sub-target that is already armed by a
    *different* engagement: detach first, so the arming engagement is always
    unambiguous.
    """
    _ensure_schema()
    sub = get_sub_target(sub_target_id)
    if sub is None:
        raise ValueError(f"sub-target not found: {sub_target_id}")
    if get_engagement(engagement_id) is None:
        raise ValueError(f"engagement not found: {engagement_id}")
    existing = current_arming(sub_target_id)
    if existing is not None:
        if existing["engagement_id"] == engagement_id:
            return existing  # already armed by this engagement — no-op
        raise ValueError(
            "sub-target is already armed by another engagement; "
            "detach it before arming with a different engagement"
        )
    aid = uuid.uuid4().hex
    now = _now()
    with cursor() as c:
        c.execute(
            "INSERT INTO spine_armings (id, sub_target_id, engagement_id, "
            "armed_at, detached_at) VALUES (?, ?, ?, ?, NULL)",
            (aid, sub_target_id, engagement_id, now),
        )
    return current_arming(sub_target_id)  # type: ignore[return-value]


def disarm(sub_target_id: str) -> bool:
    """Detach the active engagement — return the sub-target to inert.

    Returns True if an active arming was detached, False if it was already
    un-armed. Nothing stays armed implicitly.
    """
    _ensure_schema()
    now = _now()
    with cursor() as c:
        c.execute(
            "UPDATE spine_armings SET detached_at = ? "
            "WHERE sub_target_id = ? AND detached_at IS NULL",
            (now, sub_target_id),
        )
        return c.rowcount > 0


def armed_sub_targets(engagement_id: str) -> list[dict[str, Any]]:
    """Sub-targets currently armed by a given engagement (enriched with target)."""
    _ensure_schema()
    with cursor() as c:
        rows = c.execute(
            "SELECT s.* FROM spine_subtargets s "
            "JOIN spine_armings a ON a.sub_target_id = s.id "
            "WHERE a.engagement_id = ? AND a.detached_at IS NULL "
            "ORDER BY a.armed_at DESC",
            (engagement_id,),
        ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        sub = _row_subtarget(r)
        sub["target"] = get_target(sub["target_id"])
        out.append(sub)
    return out


def require_armed(sub_target_id: str) -> dict[str, Any]:
    """The hard arm gate. Server-side, non-bypassable.

    Returns the active arming (carrying the engagement that authorizes the run)
    when the sub-target is armed. Raises HTTPException(403) — refusing the run
    with a clear message — when it is un-armed. The parent Target never confers
    arming; only an attached engagement does.
    """
    from fastapi import HTTPException

    sub = get_sub_target(sub_target_id)
    if sub is None:
        raise HTTPException(status_code=404, detail=f"sub-target not found: {sub_target_id}")
    arming = current_arming(sub_target_id)
    if arming is None:
        raise HTTPException(
            status_code=403,
            detail={
                "reason": (
                    "sub-target is un-armed: attach an engagement to arm it before "
                    "running tools or playbooks against it"
                ),
                "code": "SUBTARGET_UNARMED",
                "sub_target_id": sub_target_id,
            },
        )
    return arming


# ── Pairing runs (engagement × sub-target — the only unit that executes) ──────

def _record_run_start(
    sub_target_id: str, engagement_id: str, target_id: str, tool: str,
) -> str:
    rid = uuid.uuid4().hex
    with cursor() as c:
        c.execute(
            "INSERT INTO spine_runs (id, sub_target_id, engagement_id, target_id, "
            "tool, status, started_at) VALUES (?, ?, ?, ?, ?, 'started', ?)",
            (rid, sub_target_id, engagement_id, target_id, tool, _now()),
        )
    return rid


def _record_run_end(rid: str, status: str, output: str, summary: str) -> None:
    with cursor() as c:
        c.execute(
            "UPDATE spine_runs SET status = ?, output = ?, summary = ?, ended_at = ? "
            "WHERE id = ?",
            (status, output[:200_000], summary[:2000], _now(), rid),
        )


def get_run(rid: str) -> dict[str, Any] | None:
    _ensure_schema()
    with cursor() as c:
        r = c.execute("SELECT * FROM spine_runs WHERE id = ?", (rid,)).fetchone()
    return _row_run(r) if r else None


def list_runs(sub_target_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    _ensure_schema()
    with cursor() as c:
        if sub_target_id:
            rows = c.execute(
                "SELECT * FROM spine_runs WHERE sub_target_id = ? "
                "ORDER BY started_at DESC LIMIT ?",
                (sub_target_id, limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM spine_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [_row_run(r) for r in rows]


def run_pairing(sub_target_id: str, tool: str = "connect") -> dict[str, Any]:
    """Run a tool against an armed sub-target — the only execution path.

    Order of enforcement:
      1. ``require_armed`` — refuse with 403 if the sub-target is un-armed.
      2. ``scope`` + ``safety`` (via ``lib.scope.enforce_rest(active=True)``) —
         the arming engagement's scope must cover the address (a local-only
         engagement can't reach outside its scope), and an external target needs
         a covering attestation. This is where the engagement's authorization
         actually applies; the parent Target never confers it.
      3. record the run + execute a bounded probe + audit it under the arming
         engagement id (so every write carries X-MHP-Engagement-Id).

    Raises HTTPException on refusal (un-armed, out-of-scope, missing attestation).
    Returns the completed run record.
    """
    from lib import scope as scope_lib

    arming = require_armed(sub_target_id)           # 403 if un-armed
    sub = get_sub_target(sub_target_id)             # exists (require_armed checked)
    assert sub is not None
    eid = arming["engagement_id"]
    target_id = sub["target_id"]
    address = sub["address"]

    # Scope + safety enforcement, scoped to the ARMING engagement. Network
    # sub-targets run through the full check; a directory sub-target isn't a
    # network endpoint, so we only require the engagement to be present.
    if sub["type"] == "directory":
        scope_lib.enforce_engagement_present(eid, "engagement")
    else:
        # confirm=True: arming the sub-target IS the deliberate, attested act,
        # so we don't bounce an in-scope external target back for a UI confirm —
        # the attestation gate inside enforce_rest is the real check.
        scope_lib.enforce_rest(
            address, eid, "engagement",
            confirm=True, active=True, action=f"spine-run:{tool}",
        )

    rid = _record_run_start(sub_target_id, eid, target_id, tool)
    status, output, summary = _execute(sub, tool)
    _record_run_end(rid, status, output, summary)

    # The run's own audit row — carries the arming engagement id so the ledger
    # records that this pairing executed under that authorized context.
    try:
        from lib import audit_log
        aud = audit_log.start(
            tool=f"spine-run:{tool}",
            target=address,
            argv=[f"sub_target_id={sub_target_id}", f"target_id={target_id}"],
            engagement_id=eid,
        )
        audit_log.complete(aud, summary=summary)
    except Exception:
        logger.exception("run_pairing: audit write failed for run %s", rid)

    return get_run(rid)  # type: ignore[return-value]


def _execute(sub: dict[str, Any], tool: str) -> tuple[str, str, str]:
    """A bounded, safe execution against an armed (and scope-checked) sub-target.

    The full tool arsenal hooks in here later; for the spine's purposes this is a
    real connectivity probe so an armed pairing produces genuine output (and an
    un-armed one never reaches this code). Never raises — failures are captured
    into the output so the run completes with a status.
    """
    address = sub["address"]
    stype = sub["type"]
    lines: list[str] = [f"$ {tool} {address}"]
    if stype == "directory":
        import os
        ok = os.path.isdir(address)
        lines.append(f"directory {'exists' if ok else 'not found'}: {address}")
        return ("completed" if ok else "error",
                "\n".join(lines),
                f"{tool}: {'ok' if ok else 'missing'}")
    host, port = _host_port(address, default_port=80 if stype in ("url", "endpoint") else None)
    if host is None:
        lines.append("could not parse an address to probe")
        return "error", "\n".join(lines), f"{tool}: unparseable address"
    if port is None:
        lines.append(f"resolved host {host} (no port to connect — recording reachability check)")
        try:
            socket.getaddrinfo(host, None)
            lines.append("host resolves")
            return "completed", "\n".join(lines), f"{tool}: {host} resolves"
        except OSError as e:
            lines.append(f"resolution failed: {e}")
            return "error", "\n".join(lines), f"{tool}: {host} unresolved"
    # Dispatch by tool family. These are bounded, dependency-light stdlib probes
    # (socket / ssl / http.client) — never a shell, never unbounded. Anything we
    # don't have a richer probe for falls back to the TCP connect check, so an
    # armed pairing always produces genuine output. The full external-tool
    # arsenal (nmap, the web fuzzers, …) layers on here incrementally.
    t = tool.lower()
    scheme = "https" if (port == 443 or "https" in (address or "")) else "http"
    if any(k in t for k in ("tls", "ssl", "cert")):
        return _probe_tls(host, port, tool, lines)
    if any(k in t for k in ("http", "fingerprint", "cms", "header", "probe", "wayback", "takeover")):
        return _probe_http(host, port, scheme, tool, lines)
    return _probe_connect(host, port, tool, lines)


def _probe_connect(host: str, port: int, tool: str, lines: list[str]) -> tuple[str, str, str]:
    try:
        with socket.create_connection((host, port), timeout=3.0):
            lines.append(f"connected to {host}:{port} — port open")
        return "completed", "\n".join(lines), f"{tool}: {host}:{port} open"
    except OSError as e:
        lines.append(f"connect to {host}:{port} failed: {e}")
        return "completed", "\n".join(lines), f"{tool}: {host}:{port} closed/filtered"


def _probe_http(host: str, port: int, scheme: str, tool: str, lines: list[str]) -> tuple[str, str, str]:
    """A bounded HTTP HEAD/GET: status line + a few telling response headers."""
    import http.client

    conn = None
    try:
        if scheme == "https":
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=5.0, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=5.0)
        conn.request("HEAD", "/", headers={"User-Agent": "s-ide-workbench"})
        r = conn.getresponse()
        lines.append(f"{scheme.upper()} {r.status} {r.reason}")
        for h in ("Server", "X-Powered-By", "Location", "Content-Type", "Strict-Transport-Security"):
            v = r.getheader(h)
            if v:
                lines.append(f"{h}: {v}")
        return "completed", "\n".join(lines), f"{tool}: HTTP {r.status} from {host}"
    except Exception as e:  # noqa: BLE001 — capture into output, never raise
        lines.append(f"http probe failed: {e}")
        return "completed", "\n".join(lines), f"{tool}: http probe failed"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _probe_tls(host: str, port: int, tool: str, lines: list[str]) -> tuple[str, str, str]:
    """A bounded TLS handshake: negotiated version + cert subject/issuer/expiry."""
    import ssl

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5.0) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                lines.append(f"TLS {s.version()} · cipher {s.cipher()[0] if s.cipher() else '?'}")
                cert = s.getpeercert()
                if cert:
                    def _name(field):
                        return ", ".join(f"{k}={v}" for part in field for (k, v) in part)
                    if cert.get("subject"):
                        lines.append(f"subject: {_name(cert['subject'])}")
                    if cert.get("issuer"):
                        lines.append(f"issuer: {_name(cert['issuer'])}")
                    if cert.get("notAfter"):
                        lines.append(f"expires: {cert['notAfter']}")
        return "completed", "\n".join(lines), f"{tool}: TLS ok on {host}:{port}"
    except Exception as e:  # noqa: BLE001
        lines.append(f"tls probe failed: {e}")
        return "completed", "\n".join(lines), f"{tool}: tls probe failed"


def _host_port(address: str, default_port: int | None) -> tuple[str | None, int | None]:
    """Best-effort (host, port) from an address string (url, host:port, host)."""
    from urllib.parse import urlparse

    a = (address or "").strip()
    if not a:
        return None, None
    if "://" in a:
        try:
            u = urlparse(a)
            host = u.hostname
            port = u.port or (443 if u.scheme == "https" else default_port)
            return host, port
        except ValueError:
            return None, None
    # host:port (but not bare IPv6)
    if a.count(":") == 1 and not a.startswith("["):
        host, _, p = a.partition(":")
        try:
            return host or None, int(p)
        except ValueError:
            return host or None, default_port
    return a, default_port


# ── Findings (born from a pairing; tagged with engagement × sub-target) ───────

def create_pairing_finding(
    sub_target_id: str,
    title: str,
    severity: str,
    description: str = "",
    evidence: str = "",
    tool: str = "",
    status: str = "open",
) -> dict[str, Any]:
    """Mint a finding from an armed pairing.

    Requires the sub-target to be armed (``require_armed`` → 403 otherwise): a
    finding is born from a specific engagement × sub-target pairing. The finding
    is stored in the existing ``findings`` table (under the arming engagement)
    and a ``spine_finding_links`` row tags it with { engagement_id,
    sub_target_id, target_id } so roll-up to the parent Target is computable.
    """
    from lib import engagements

    arming = require_armed(sub_target_id)
    sub = get_sub_target(sub_target_id)
    assert sub is not None
    eid = arming["engagement_id"]
    target_id = sub["target_id"]

    finding = engagements.create_finding(
        engagement_id=eid,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        tool=tool,
        target=sub["address"],
        status=status,
    )
    _ensure_schema()
    with cursor() as c:
        c.execute(
            "INSERT OR REPLACE INTO spine_finding_links "
            "(finding_id, engagement_id, sub_target_id, target_id) "
            "VALUES (?, ?, ?, ?)",
            (finding["id"], eid, sub_target_id, target_id),
        )
    finding["sub_target_id"] = sub_target_id
    finding["target_id"] = target_id
    return finding


def _findings_by_links(where: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    """Join spine_finding_links → findings, returning enriched finding dicts."""
    from lib import engagements

    _ensure_schema()
    with cursor() as c:
        links = c.execute(
            f"SELECT * FROM spine_finding_links WHERE {where}", params
        ).fetchall()
    out: list[dict[str, Any]] = []
    for link in links:
        f = engagements.get_finding(link["finding_id"])
        if not f:
            continue
        f["sub_target_id"] = link["sub_target_id"]
        f["target_id"] = link["target_id"]
        out.append(f)
    out.sort(key=lambda f: f.get("ts") or "", reverse=True)
    return out


def findings_for_target(target_id: str) -> list[dict[str, Any]]:
    """A Target's findings = the union across all its sub-targets' pairings."""
    return _findings_by_links("target_id = ?", (target_id,))


def findings_for_sub_target(sub_target_id: str) -> list[dict[str, Any]]:
    return _findings_by_links("sub_target_id = ?", (sub_target_id,))


def findings_for_engagement(engagement_id: str) -> list[dict[str, Any]]:
    return _findings_by_links("engagement_id = ?", (engagement_id,))


def all_pairing_findings() -> list[dict[str, Any]]:
    return _findings_by_links("1 = 1", ())


# ── Default-safe local surface ───────────────────────────────────────────────

def ensure_local_surface() -> dict[str, Any]:
    """Idempotently declare the local machine as a lab-provenance Target.

    The local machine is just a Target whose sub-targets (loopback host +
    backend service) can be armed *only* via an engagement scoped local-only —
    the same model as everything else, the narrowest pairing. This declares the
    pieces; it does NOT auto-arm anything (un-armed is the default). It also
    ensures a local-only engagement exists to arm them with.
    """
    from lib import engagements

    _ensure_schema()
    # Find an existing builtin-local target by metadata marker.
    existing = None
    for t in list_targets():
        if (t.get("metadata") or {}).get("builtin") == "local":
            existing = t
            break
    if existing is None:
        target = create_target(
            name="This machine",
            provenance="lab",
            metadata={"builtin": "local"},
        )
        create_sub_target(target["id"], "host", "127.0.0.1", label="loopback")
        create_sub_target(target["id"], "service", "127.0.0.1:8765", label="s-ide backend")
    else:
        target = existing

    # Ensure a local-only engagement exists (narrow scope). Not attached here —
    # arming stays a deliberate act in the Targets / Engagements tabs.
    local_eng = None
    for e in engagements.list_engagements():
        if (e.get("name") or "") == "Local (sandbox)":
            local_eng = e
            break
    if local_eng is None:
        local_eng = engagements.create_engagement(
            name="Local (sandbox)",
            scope=["127.0.0.1", "localhost", "::1"],
            exclusions=[],
            notes="Default-safe local-only engagement. Arms localhost sub-targets only.",
            type="local-app",
            provenance="lab",
        )
    return {"target": get_target(target["id"]), "engagement": local_eng}


# ── Row helpers ──────────────────────────────────────────────────────────────

def _json_or(default: Any, raw: Any) -> Any:
    try:
        return json.loads(raw) if raw else default
    except (json.JSONDecodeError, TypeError):
        return default


def _row_target(r: Any) -> dict[str, Any]:
    return {
        "id":         r["id"],
        "name":       r["name"],
        "provenance": r["provenance"],
        "metadata":   _json_or({}, r["metadata"]),
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }


def _row_subtarget(r: Any) -> dict[str, Any]:
    sub = {
        "id":         r["id"],
        "target_id":  r["target_id"],
        "type":       r["type"],
        "address":    r["address"],
        "label":      r["label"] or "",
        "metadata":   _json_or({}, r["metadata"]),
        "created_at": r["created_at"],
    }
    # Enrich with live arming state so listings can show armed/un-armed + by whom.
    arming = current_arming(sub["id"])
    sub["armed"] = arming is not None
    sub["arming"] = arming
    return sub


def _row_arming(r: Any) -> dict[str, Any]:
    return {
        "id":            r["id"],
        "sub_target_id": r["sub_target_id"],
        "engagement_id": r["engagement_id"],
        "armed_at":      r["armed_at"],
        "detached_at":   r["detached_at"],
    }


def _row_run(r: Any) -> dict[str, Any]:
    return {
        "id":            r["id"],
        "sub_target_id": r["sub_target_id"],
        "engagement_id": r["engagement_id"],
        "target_id":     r["target_id"],
        "tool":          r["tool"],
        "status":        r["status"],
        "started_at":    r["started_at"],
        "ended_at":      r["ended_at"],
        "output":        r["output"] or "",
        "summary":       r["summary"] or "",
    }
