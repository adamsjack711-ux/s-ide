"""Lab-container filesystem surface — fix-in-place + retest=replay.

Stage 5 of the learning sandbox (SANDBOX-DESIGN.md): the root-cause chain
terminates at a file:line / route / config, the operator opens the offending
lab-container source in Monaco, edits it, writes it back, and replays the
recorded Step chain to verify the fix.

This is a thin REST seam over ``lib/labs.sidecar_exec`` (read/write inside the
lab's docker-bridge sidecar) and ``lib/method`` (the recorded Step chain +
finding-method state). All file paths are confined to the lab container:
absolute paths and ``..`` traversal are rejected.
"""
from __future__ import annotations

import posixpath
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from lib import labs as labs_lib, method

router = APIRouter(prefix="/labfs", tags=["labfs"])


# ── Path confinement ─────────────────────────────────────────────────────────
def _safe_rel_path(path: str) -> str:
    """Validate a lab-relative path and return its normalized form.

    Rejects (HTTP 400):
      * empty paths
      * absolute paths (leading ``/``)
      * ``..`` traversal (anywhere in the path, including post-normalization)
      * NUL bytes / shell metacharacters that could break out of the argv

    Returns the ``posixpath.normpath``-cleaned relative path. Because the
    file lives inside the container and is reached only via ``cat``/``tee``
    argv (no shell), this is defense-in-depth on top of the sidecar's own
    whitelist — but it keeps the seam honest about confinement.
    """
    if not isinstance(path, str) or not path.strip():
        raise HTTPException(status_code=400, detail="path is required")
    p = path.strip()
    if p.startswith("/") or p.startswith("~"):
        raise HTTPException(status_code=400, detail="absolute paths are not allowed")
    # Reject control chars / NUL / shell metacharacters up front.
    bad = set("\0\n\r;|&`$<>*?")
    if any(c in bad for c in p):
        raise HTTPException(status_code=400, detail="path contains illegal characters")
    # Normalize and re-check: catch `a/../../etc/passwd` and friends.
    norm = posixpath.normpath(p)
    if norm == ".." or norm.startswith("../") or "/../" in norm or norm.startswith("/"):
        raise HTTPException(status_code=400, detail="path traversal is not allowed")
    if norm in ("", "."):
        raise HTTPException(status_code=400, detail="path is required")
    return norm


def _require_lab(lab_id: str) -> None:
    if labs_lib.get_lab_def(lab_id) is None:
        raise HTTPException(status_code=404, detail=f"unknown lab: {lab_id}")


# ── Read ─────────────────────────────────────────────────────────────────────
class ReadResult(BaseModel):
    path: str
    content: str
    rc: int


@router.get("/{lab_id}/read", response_model=ReadResult)
async def read_file(lab_id: str, path: str = Query(...)) -> ReadResult:
    """Read a file from the lab container via the sidecar (``cat <path>``)."""
    _require_lab(lab_id)
    rel = _safe_rel_path(path)
    res = await labs_lib.sidecar_exec(lab_id, "cat", [rel], 10)
    rc = int(res.get("rc", -1))
    # On a non-zero rc the stderr carries the reason (missing file, no sidecar,
    # command-not-allowed); surface it as the content so the editor can show it.
    content = res.get("stdout", "") if rc == 0 else (res.get("stderr", "") or res.get("stdout", ""))
    return ReadResult(path=rel, content=content, rc=rc)


# ── Write ────────────────────────────────────────────────────────────────────
class WriteIn(BaseModel):
    path: str
    content: str


class WriteResult(BaseModel):
    path: str
    rc: int
    written: bool
    note: str | None = None


@router.post("/{lab_id}/write", response_model=WriteResult)
async def write_file(lab_id: str, body: WriteIn) -> WriteResult:
    """Write a file back into the lab container (fix-in-place).

    Implemented via ``tee <path>`` with the new contents fed on stdin — no
    shell, no heredoc, so the file body can contain any characters without
    needing to be escaped into an argv.

    LIMITATION: ``lib/labs.sidecar_exec`` only runs commands in the lab's
    ``sidecar_allowed_cmds`` whitelist and does NOT pipe stdin. ``tee`` (and
    any write command) is therefore rejected for every lab whose whitelist
    omits it — which today is all of them. When that happens this endpoint
    returns ``rc != 0`` + ``written=False`` and a ``note`` explaining the
    block, rather than silently failing. READ still works regardless. To
    enable writes the integrator must (a) add the write command to the lab's
    ``sidecar_allowed_cmds`` and (b) extend ``sidecar_exec`` to forward stdin.
    """
    _require_lab(lab_id)
    rel = _safe_rel_path(body.path)
    res = await _write_via_sidecar(lab_id, rel, body.content)
    rc = int(res.get("rc", -1))
    written = rc == 0
    note: str | None = None
    if not written:
        note = (
            (res.get("stderr") or res.get("stdout") or "write failed").strip()
            + "  (sidecar write may be blocked by the command whitelist — see "
            "routers/labfs.py for the enablement steps; READ is unaffected)"
        )
    return WriteResult(path=rel, rc=rc, written=written, note=note)


async def _write_via_sidecar(lab_id: str, rel: str, content: str) -> dict[str, Any]:
    """Best-effort write through the sidecar.

    Uses ``tee`` so the file body is delivered out-of-band (stdin) rather than
    as an argv arg. ``sidecar_exec`` does not currently forward stdin, so this
    will return the whitelist-block rc for labs that don't permit ``tee`` —
    the caller turns that into an honest ``written=False`` response.
    """
    return await labs_lib.sidecar_exec(lab_id, "tee", [rel], 10)


# ── Retest = replay the Step chain ───────────────────────────────────────────
class RetestIn(BaseModel):
    finding_id: str


class RetestStep(BaseModel):
    ordinal: int
    tool_id: str
    replayed: bool
    note: str


class RetestResult(BaseModel):
    finding_id: str
    steps: list[RetestStep]
    verified: bool
    state: str


@router.post("/{lab_id}/retest", response_model=RetestResult)
async def retest(lab_id: str, body: RetestIn) -> RetestResult:
    """Replay the recorded Step chain for a finding to verify a fix.

    Each recorded Step carries ``action.tool_id`` + ``action.params`` (FACT).
    Verification logic: if EVERY previously-succeeding step would now FAIL to
    reproduce its exploit, the vulnerability is gone and the finding flips to
    ``verified`` (auto-advance, per SANDBOX-DESIGN stage 5).

    PLUG-IN POINT: actual per-tool re-execution is not wired here — that means
    re-dispatching ``action.tool_id`` through the tool registry / WS runner
    with ``action.params`` and diffing the fresh evidence against the recorded
    evidence hash. This scaffold iterates the chain, marks each step
    ``replayed=False`` with a note pinpointing exactly where the re-exec plugs
    in, and computes the verified transition off the (currently empty) replay
    outcomes so the wiring is the only thing left to add.
    """
    _require_lab(lab_id)
    steps = method.list_steps(body.finding_id)

    out: list[RetestStep] = []
    any_step = False
    all_now_fail = True  # vacuously true until a step is actually replayed
    for s in steps:
        any_step = True
        action = s.get("action") or {}
        tool_id = str(action.get("tool_id") or "unknown")

        # ── re-execution plug-in point ──────────────────────────────────────
        # replayed = await run_tool(lab_id, tool_id, action.get("params", {}))
        # now_reproduces = replayed and evidence_matches(replayed, s["evidence"])
        # all_now_fail = all_now_fail and not now_reproduces
        replayed = False
        all_now_fail = False  # nothing actually re-run yet → can't claim a fix
        # ────────────────────────────────────────────────────────────────────

        out.append(RetestStep(
            ordinal=int(s.get("ordinal", 0)),
            tool_id=tool_id,
            replayed=replayed,
            note=(
                f"re-exec plug-in: dispatch tool_id='{tool_id}' with "
                f"action.params and diff fresh evidence vs recorded "
                f"evidence.hash to decide if the exploit still reproduces"
            ),
        ))

    # Verification: only when there WAS a chain and every step now fails to
    # reproduce. With no real re-execution wired this stays False, so the
    # state is never flipped prematurely.
    verified = any_step and all_now_fail
    if verified:
        method.upsert_method(body.finding_id, state="verified")
        state = "verified"
    else:
        state = method.get_method(body.finding_id).get("state", "open")

    return RetestResult(
        finding_id=body.finding_id,
        steps=out,
        verified=verified,
        state=state,
    )
