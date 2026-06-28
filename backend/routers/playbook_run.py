"""Declarative playbooks — CRUD + methodology coverage.

A playbook is an ordered list of steps; each step names a tool, an optional
``in_map`` (what asset/input it consumes), the ``expected`` observation, and the
WSTG/PTES ``methodology_ids`` it exercises. The learning surface steps through a
playbook by emitting ``openTool`` on the frontend bus for each step's ``tool_id``.

Storage is the existing ``playbooks`` table in ``engagements.db`` (created by
``lib/method.py``). This router uses a small LOCAL sqlite helper so it never
imports or edits ``method.py`` for writes — but coverage reads progress through
``lib.method.get_progress()`` (the global learning progress), so a step's
methodology id counts as "covered" once it has been practiced anywhere.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from lib import method
from lib.platform_util import app_data_dir

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


# ── Local sqlite helper (does NOT touch method.py) ───────────────────────────
def _db_path():
    return app_data_dir() / "engagements.db"


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    # The table is created by lib/method.py at first touch; create-if-missing
    # here too so this router is self-sufficient even if method hasn't run yet.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS playbooks (id TEXT PRIMARY KEY, name TEXT NOT NULL, steps TEXT NOT NULL)"
    )
    # Lab binding: a playbook may target a specific training lab. Added as a
    # nullable column (ALTER-if-missing) so existing rows + the method.py
    # creator stay valid — a NULL lab_id means "not bound to any lab".
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(playbooks)").fetchall()}
    if "lab_id" not in cols:
        conn.execute("ALTER TABLE playbooks ADD COLUMN lab_id TEXT")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ── Schemas ──────────────────────────────────────────────────────────────────
class PlaybookStep(BaseModel):
    tool_id: str
    in_map: str | None = None
    expected: str = ""
    methodology_ids: list[str] = []


class PlaybookIn(BaseModel):
    name: str
    steps: list[PlaybookStep] = []
    lab_id: str | None = None


class Playbook(BaseModel):
    id: str
    name: str
    steps: list[PlaybookStep]
    lab_id: str | None = None


def _row_to_playbook(r: sqlite3.Row) -> dict[str, Any]:
    # `lab_id` is read defensively: a row created before the column existed (or
    # by method.py's narrower CREATE) won't carry the key until re-saved.
    keys = r.keys()
    return {
        "id": r["id"],
        "name": r["name"],
        "steps": json.loads(r["steps"] or "[]"),
        "lab_id": r["lab_id"] if "lab_id" in keys else None,
    }


# ── CRUD ─────────────────────────────────────────────────────────────────────
@router.get("")
def list_playbooks() -> dict[str, Any]:
    with _conn() as conn:
        rows = conn.execute("SELECT id, name, steps, lab_id FROM playbooks ORDER BY name").fetchall()
    return {"playbooks": [_row_to_playbook(r) for r in rows]}


@router.post("")
def create_playbook(body: PlaybookIn) -> dict[str, Any]:
    pid = uuid.uuid4().hex
    steps = [s.model_dump() for s in body.steps]
    with _conn() as conn:
        conn.execute(
            "INSERT INTO playbooks(id, name, steps, lab_id) VALUES (?,?,?,?)",
            (pid, body.name.strip() or "Untitled playbook", json.dumps(steps), body.lab_id),
        )
    return {"id": pid, "name": body.name, "steps": steps, "lab_id": body.lab_id}


@router.get("/{playbook_id}")
def get_playbook(playbook_id: str) -> dict[str, Any]:
    with _conn() as conn:
        r = conn.execute(
            "SELECT id, name, steps, lab_id FROM playbooks WHERE id=?", (playbook_id,)
        ).fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="playbook not found")
    return _row_to_playbook(r)


@router.put("/{playbook_id}")
def update_playbook(playbook_id: str, body: PlaybookIn) -> dict[str, Any]:
    """Replace a playbook's name, steps, and lab binding.

    There is no partial update — the editor always sends the full document.
    Returns the saved playbook (404 if the id is unknown).
    """
    steps = [s.model_dump() for s in body.steps]
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE playbooks SET name=?, steps=?, lab_id=? WHERE id=?",
            (body.name.strip() or "Untitled playbook", json.dumps(steps), body.lab_id, playbook_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="playbook not found")
    return {"id": playbook_id, "name": body.name, "steps": steps, "lab_id": body.lab_id}


# ── Methodology coverage ─────────────────────────────────────────────────────
@router.post("/{playbook_id}/coverage")
def playbook_coverage(playbook_id: str) -> dict[str, Any]:
    """Which methodology ids across this playbook's steps are covered vs not.

    "Covered" = present in the global learning progress
    (``method.get_progress()['methodology_steps']``).
    """
    with _conn() as conn:
        r = conn.execute("SELECT steps FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="playbook not found")
    steps = json.loads(r["steps"] or "[]")

    # Deduplicate while preserving first-seen order.
    required: list[str] = []
    seen: set[str] = set()
    for s in steps:
        for mid in s.get("methodology_ids", []) or []:
            if mid not in seen:
                seen.add(mid)
                required.append(mid)

    practiced = set(method.get_progress().get("methodology_steps", []))
    covered = [m for m in required if m in practiced]
    missing = [m for m in required if m not in practiced]
    return {
        "playbook_id": playbook_id,
        "required": required,
        "covered": covered,
        "missing": missing,
        "pct": round(100 * len(covered) / len(required)) if required else 0,
    }
