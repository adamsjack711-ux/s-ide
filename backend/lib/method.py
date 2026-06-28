"""Learning-sandbox data model — the single source of truth.

Extends the engagement spine (same ``engagements.db``) with the tables the
report / agent-export / retest are all *views* over: ordered method Steps
(append-only, hash-chained like the audit log), per-finding method state +
root-cause + remediation, the per-lab asset graph, lab metadata (incl. a
PRIVATE solution that ``learner_serialize`` can never emit), global learning
progress, and declarative playbooks.

Nothing here is authored by hand in the UI; the views read these rows.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from lib.platform_util import app_data_dir

_LOCK = threading.Lock()
_INITED = False


def _db_path():
    return app_data_dir() / "engagements.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


_SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_method (
  finding_id   TEXT PRIMARY KEY,
  state        TEXT NOT NULL DEFAULT 'open',   -- open | fixed | verified
  root_cause   TEXT,                           -- json {anchor, explanation}
  remediation  TEXT,                           -- json {change, why}
  updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
  id            TEXT PRIMARY KEY,
  finding_id    TEXT NOT NULL,
  ordinal       INTEGER NOT NULL,
  action        TEXT NOT NULL,                 -- json {tool_id, params}  (FACT)
  evidence      TEXT NOT NULL,                 -- json {raw_output, hash, timestamp} (FACT)
  interpretation TEXT,                         -- text (INFERENCE)
  links_from    TEXT,                          -- step id | null
  anchored      INTEGER NOT NULL DEFAULT 0,
  prev_hash     TEXT NOT NULL DEFAULT '',
  row_hash      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_steps_finding ON steps(finding_id, ordinal);
CREATE TABLE IF NOT EXISTS assets (
  id         TEXT PRIMARY KEY,
  scope_key  TEXT NOT NULL,                    -- lab:<id> | eng:<id>
  kind       TEXT NOT NULL,                    -- host | service | cert | endpoint | tech
  key        TEXT NOT NULL,                    -- natural key (e.g. ip, host:port)
  props      TEXT,                             -- json
  source_tool TEXT,
  first_seen TEXT NOT NULL,
  UNIQUE(scope_key, kind, key)
);
CREATE TABLE IF NOT EXISTS labs_meta (
  lab_id        TEXT PRIMARY KEY,
  armed_snapshot TEXT,                         -- json
  solution      TEXT,                          -- json  [PRIVATE — never serialized to learner/report]
  learner_view  TEXT,                          -- json {description, objective, hints[]}
  source_anchor TEXT,                          -- json
  updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS progress (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  labs_solved   TEXT NOT NULL DEFAULT '[]',
  vuln_classes  TEXT NOT NULL DEFAULT '[]',
  methodology_steps TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS playbooks (
  id    TEXT PRIMARY KEY,
  name  TEXT NOT NULL,
  steps TEXT NOT NULL                          -- json [{tool_id, in_map, expected, methodology_ids[]}]
);
"""


def _ensure() -> None:
    global _INITED
    if _INITED:
        return
    with _LOCK, _connect() as conn:
        conn.executescript(_SCHEMA)
        conn.execute("INSERT OR IGNORE INTO progress(id) VALUES (1)")
        conn.commit()
    _INITED = True


@contextmanager
def _tx() -> Iterator[sqlite3.Connection]:
    _ensure()
    with _LOCK:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hash(prev: str, canonical: str) -> str:
    return hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()


# ── Assets (asset graph) ─────────────────────────────────────────────────────
def record_asset(scope_key: str, kind: str, key: str, props: dict[str, Any] | None = None,
                 source_tool: str | None = None) -> dict[str, Any]:
    with _tx() as conn:
        existing = conn.execute(
            "SELECT id, props FROM assets WHERE scope_key=? AND kind=? AND key=?",
            (scope_key, kind, key),
        ).fetchone()
        if existing:
            merged = {**json.loads(existing["props"] or "{}"), **(props or {})}
            conn.execute("UPDATE assets SET props=? WHERE id=?", (json.dumps(merged), existing["id"]))
            return {"id": existing["id"], "scope_key": scope_key, "kind": kind, "key": key, "props": merged, "new": False}
        aid = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO assets(id, scope_key, kind, key, props, source_tool, first_seen) VALUES (?,?,?,?,?,?,?)",
            (aid, scope_key, kind, key, json.dumps(props or {}), source_tool, _now()),
        )
        return {"id": aid, "scope_key": scope_key, "kind": kind, "key": key, "props": props or {}, "new": True}


def list_assets(scope_key: str) -> list[dict[str, Any]]:
    with _tx() as conn:
        rows = conn.execute(
            "SELECT id, kind, key, props, source_tool, first_seen FROM assets WHERE scope_key=? ORDER BY kind, key",
            (scope_key,),
        ).fetchall()
    return [{**dict(r), "props": json.loads(r["props"] or "{}")} for r in rows]


# ── Finding method state + steps (append-only, hash-chained) ─────────────────
def upsert_method(finding_id: str, state: str | None = None,
                  root_cause: dict | None = None, remediation: dict | None = None) -> dict[str, Any]:
    with _tx() as conn:
        cur = conn.execute("SELECT state, root_cause, remediation FROM finding_method WHERE finding_id=?", (finding_id,)).fetchone()
        st = state or (cur["state"] if cur else "open")
        rc = json.dumps(root_cause) if root_cause is not None else (cur["root_cause"] if cur else None)
        rem = json.dumps(remediation) if remediation is not None else (cur["remediation"] if cur else None)
        conn.execute(
            "INSERT INTO finding_method(finding_id, state, root_cause, remediation, updated_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(finding_id) DO UPDATE SET state=excluded.state, root_cause=excluded.root_cause, "
            "remediation=excluded.remediation, updated_at=excluded.updated_at",
            (finding_id, st, rc, rem, _now()),
        )
    return get_method(finding_id)


def append_step(finding_id: str, action: dict, evidence: dict,
                interpretation: str | None = None, links_from: str | None = None,
                anchored: bool = False) -> dict[str, Any]:
    """Append an ordered, hash-chained Step. action+evidence are FACT; interpretation is INFERENCE."""
    with _tx() as conn:
        last = conn.execute(
            "SELECT ordinal, row_hash FROM steps WHERE finding_id=? ORDER BY ordinal DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        ordinal = (last["ordinal"] + 1) if last else 0
        prev_hash = (last["row_hash"] if last else "") or ""
        sid = uuid.uuid4().hex
        ev = dict(evidence)
        ev.setdefault("timestamp", _now())
        ev.setdefault("hash", hashlib.sha256(str(ev.get("raw_output", "")).encode("utf-8")).hexdigest())
        canonical = json.dumps({"finding_id": finding_id, "ordinal": ordinal, "action": action, "evidence": ev}, sort_keys=True)
        row_hash = _hash(prev_hash, canonical)
        conn.execute(
            "INSERT INTO steps(id, finding_id, ordinal, action, evidence, interpretation, links_from, anchored, prev_hash, row_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sid, finding_id, ordinal, json.dumps(action), json.dumps(ev), interpretation,
             links_from, 1 if anchored else 0, prev_hash, row_hash),
        )
    return {"id": sid, "ordinal": ordinal, "anchored": anchored, "row_hash": row_hash}


def list_steps(finding_id: str) -> list[dict[str, Any]]:
    with _tx() as conn:
        rows = conn.execute(
            "SELECT * FROM steps WHERE finding_id=? ORDER BY ordinal", (finding_id,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["action"] = json.loads(d["action"])
        d["evidence"] = json.loads(d["evidence"])
        d["anchored"] = bool(d["anchored"])
        out.append(d)
    return out


def get_method(finding_id: str) -> dict[str, Any]:
    with _tx() as conn:
        r = conn.execute("SELECT * FROM finding_method WHERE finding_id=?", (finding_id,)).fetchone()
    m = {"finding_id": finding_id, "state": "open", "root_cause": None, "remediation": None}
    if r:
        m["state"] = r["state"]
        m["root_cause"] = json.loads(r["root_cause"]) if r["root_cause"] else None
        m["remediation"] = json.loads(r["remediation"]) if r["remediation"] else None
    m["steps"] = list_steps(finding_id)
    return m


# ── Labs (private solution) ──────────────────────────────────────────────────
def upsert_lab(lab_id: str, *, armed_snapshot=None, solution=None, learner_view=None, source_anchor=None) -> None:
    with _tx() as conn:
        cur = conn.execute("SELECT * FROM labs_meta WHERE lab_id=?", (lab_id,)).fetchone()
        def keep(field, val):
            if val is not None:
                return json.dumps(val)
            return cur[field] if cur else None
        conn.execute(
            "INSERT INTO labs_meta(lab_id, armed_snapshot, solution, learner_view, source_anchor, updated_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(lab_id) DO UPDATE SET armed_snapshot=excluded.armed_snapshot, "
            "solution=excluded.solution, learner_view=excluded.learner_view, source_anchor=excluded.source_anchor, updated_at=excluded.updated_at",
            (lab_id, keep("armed_snapshot", armed_snapshot), keep("solution", solution),
             keep("learner_view", learner_view), keep("source_anchor", source_anchor), _now()),
        )


def _lab_row(lab_id: str) -> sqlite3.Row | None:
    with _tx() as conn:
        return conn.execute("SELECT * FROM labs_meta WHERE lab_id=?", (lab_id,)).fetchone()


def learner_serialize(lab_id: str) -> dict[str, Any]:
    """The ONLY path the learner UI / report read. Whitelists learner_view +
    source_anchor; the private ``solution`` and armed_snapshot are NEVER emitted."""
    r = _lab_row(lab_id)
    if not r:
        return {"lab_id": lab_id, "learner_view": None}
    return {
        "lab_id": lab_id,
        "learner_view": json.loads(r["learner_view"]) if r["learner_view"] else None,
        "source_anchor": json.loads(r["source_anchor"]) if r["source_anchor"] else None,
        # NOTE: solution + armed_snapshot intentionally omitted.
    }


def get_solution(lab_id: str) -> dict[str, Any] | None:
    """Privileged read — used only by the gated 'solve' reveal, never by learner/report."""
    r = _lab_row(lab_id)
    if not r or not r["solution"]:
        return None
    return json.loads(r["solution"])


# ── Progress (global) ────────────────────────────────────────────────────────
def get_progress() -> dict[str, Any]:
    with _tx() as conn:
        r = conn.execute("SELECT labs_solved, vuln_classes, methodology_steps FROM progress WHERE id=1").fetchone()
    return {
        "labs_solved": json.loads(r["labs_solved"]),
        "vuln_classes": json.loads(r["vuln_classes"]),
        "methodology_steps": json.loads(r["methodology_steps"]),
    }


def mark_progress(*, lab_solved: str | None = None, vuln_class: str | None = None,
                  methodology_id: str | None = None) -> dict[str, Any]:
    with _tx() as conn:
        r = conn.execute("SELECT labs_solved, vuln_classes, methodology_steps FROM progress WHERE id=1").fetchone()
        solved = set(json.loads(r["labs_solved"]))
        vulns = set(json.loads(r["vuln_classes"]))
        steps = set(json.loads(r["methodology_steps"]))
        if lab_solved:
            solved.add(lab_solved)
        if vuln_class:
            vulns.add(vuln_class)
        if methodology_id:
            steps.add(methodology_id)
        conn.execute(
            "UPDATE progress SET labs_solved=?, vuln_classes=?, methodology_steps=? WHERE id=1",
            (json.dumps(sorted(solved)), json.dumps(sorted(vulns)), json.dumps(sorted(steps))),
        )
    return get_progress()
