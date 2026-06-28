"""Engagement management — CRUD + auto-recorded results + findings + report.

Active-engagement awareness is **frontend-driven**: when the user selects an
engagement, the frontend POSTs every successful scan result here. This avoids
threading a global "current engagement" through every router.
"""
from __future__ import annotations

import base64
import html
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import anthropic
import httpx
from fastapi import APIRouter, File, HTTPException, Query, Response, UploadFile
from pydantic import BaseModel, Field

from lib import audit_log, coverage, engagement_secrets, engagements
from lib import targets as targets_lib
from lib.auth import mint_report_nonce
from lib.errors import MhpError
from lib.validators import validate_url
from .settings import keychain_get, keychain_get_named

logger = logging.getLogger(__name__)

# Auth + nonce gate is applied at the app level (_REPORT_GATE in main.py)
# instead of here. That lets POST /report-link mint a nonce that GET
# /report?nonce=… can consume — without the stricter router-level
# require_local_auth blocking the nonce path.
router = APIRouter(prefix="/engagements", tags=["engagements"])


def _md_code_fence(content: str) -> tuple[str, str]:
    """Return (open_fence, close_fence) that won't be terminated by `content`.

    Markdown code fences may be ``` or longer; a longer fence wraps content
    that contains shorter runs of backticks. Pick a fence one tick longer
    than the longest run of backticks in `content`, with a minimum of 3.
    """
    longest = 0
    run = 0
    for ch in content:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    fence = "`" * max(3, longest + 1)
    return fence, fence


# ── Request models ──────────────────────────────────────────────────────────

class EngagementAuthInput(BaseModel):
    """Optional web-app authentication, captured at create time.

    Carries secret material on the way IN only — it is encrypted into the
    engagement secret store immediately and never echoed back. The response
    surfaces a redacted reference (kind + last4 / username), never the secret.
    """
    kind: Literal["none", "cookie", "bearer", "credentials"] = "none"
    cookie:    str = Field("", max_length=8192)   # kind=cookie: replayed Cookie header
    token:     str = Field("", max_length=8192)   # kind=bearer: replayed bearer token
    username:  str = Field("", max_length=500)    # kind=credentials
    password:  str = Field("", max_length=2048)   # kind=credentials
    login_url: str = Field("", max_length=2048)   # kind=credentials: login form URL


class EngagementCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    scope: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    notes: str = ""
    # Typed engagement. `generic` keeps the quick-create paths working
    # unchanged; the typed-create flow sends local-app / web-app explicitly.
    type: Literal["generic", "local-app", "web-app", "host"] = "generic"
    provenance: Literal["lab", "owned", "external"] = "external"
    # local-app: directory to hook onto (validated server-side: must exist + be
    # a readable directory). Becomes the engagement's source root.
    source_root: str = Field("", max_length=4096)
    # web-app: target URL(s); the first becomes the engagement's primary target.
    targets: list[str] = Field(default_factory=list)
    # web-app: optional auth, stored encrypted (never plaintext / never logged).
    auth: EngagementAuthInput | None = None


_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(raw: str, default: str = "file") -> str:
    """Strip everything outside [A-Za-z0-9._-] and cap at 120 chars.

    Prevents Content-Disposition header quote-breakout (raw
    `x"; filename="evil.exe` was previously echoed verbatim into the
    `filename="..."` slot, letting a malicious upload spoof the saved
    name or smuggle a second header parameter).
    """
    s = _FILENAME_SAFE_RE.sub("_", raw or "").strip("._-")
    return (s[:120] or default)


class EngagementPatch(BaseModel):
    name: str | None = None
    scope: list[str] | None = None
    exclusions: list[str] | None = None
    notes: str | None = None
    status: Literal["active", "completed", "archived"] | None = None
    # Codebase folder + primary target are settable after creation (e.g. the
    # Graph view's "Set codebase folder"). update_engagement() already accepts
    # these columns; they just need to survive the patch model.
    source_root: str | None = None
    primary_target: str | None = None


class ResultPost(BaseModel):
    tool: str = Field(..., max_length=200)
    target: str = Field("", max_length=500)
    summary: str = Field("", max_length=4000)
    raw: Any = None


class FindingCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    severity: Literal["info", "low", "medium", "high", "critical"]
    description: str = ""
    evidence: str = ""
    cvss: float | None = None
    linked_result_id: str | None = None


class FindingPatch(BaseModel):
    title: str | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    description: str | None = None
    evidence: str | None = None
    cvss: float | None = Field(None, ge=0, le=10)
    status: Literal["open", "triaged", "fixed", "wont_fix"] | None = None


# ── Engagement CRUD ─────────────────────────────────────────────────────────

@router.get("")
def list_all(include_archived: bool = False) -> dict[str, Any]:
    return {"engagements": engagements.list_engagements(include_archived)}


def _host_of_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _validate_source_root(raw: str) -> str:
    """local-app: the path must exist and be a readable directory.

    Returns the resolved absolute path; raises HTTPException(400) with a
    clear message otherwise so no engagement is created on a bad path.
    """
    s = (raw or "").strip()
    if not s:
        raise HTTPException(400, "local-app engagement requires a directory path")
    p = Path(s).expanduser()
    try:
        resolved = p.resolve()
    except (OSError, RuntimeError):
        raise HTTPException(400, f"invalid directory path: {s}")
    if not resolved.exists():
        raise HTTPException(400, f"directory does not exist: {resolved}")
    if not resolved.is_dir():
        raise HTTPException(400, f"not a directory: {resolved}")
    if not os.access(resolved, os.R_OK):
        raise HTTPException(400, f"directory is not readable: {resolved}")
    return str(resolved)


def _validate_web_targets(raw: list[str]) -> list[str]:
    """web-app: require at least one valid http(s) URL. Returns the cleaned,
    de-duplicated list (order preserved; first is the primary target)."""
    out: list[str] = []
    seen: set[str] = set()
    for t in raw or []:
        t = (t or "").strip()
        if not t:
            continue
        try:
            url = validate_url(t, field="target")
        except MhpError as exc:
            raise HTTPException(400, str(exc))
        if url not in seen:
            seen.add(url)
            out.append(url)
    if not out:
        raise HTTPException(400, "web-app engagement requires at least one valid URL")
    return out


@router.post("")
def create(body: EngagementCreate) -> dict[str, Any]:
    scope = list(body.scope)
    source_root = ""
    primary_target = ""
    target_specs: list[tuple[str, str]] = []  # (name, address) for the targets registry

    # ── Branch validation (fail BEFORE creating anything) ──────────────────
    if body.type == "local-app":
        source_root = _validate_source_root(body.source_root)
        primary_target = source_root
    elif body.type == "web-app":
        urls = _validate_web_targets(body.targets)
        primary_target = urls[0]
        for u in urls:
            host = _host_of_url(u)
            # Fold the target host into scope so engagement-mode scope
            # enforcement covers the declared target (strengthens, never
            # weakens, target_policy — we only ADD allowed targets).
            if host and host not in scope:
                scope.append(host)
            target_specs.append((u, u))

    # Provenance drives scope_tag for the registry rows.
    scope_tag = {"lab": "lab", "owned": "owned", "external": "authorized"}.get(
        body.provenance, "manual")
    target_kind = "lab" if body.provenance == "lab" else "manual"

    # ── Create (audit carries type/provenance — never the auth secret) ─────
    aid = audit_log.start(
        tool="engagement-create", target=body.name,
        argv=[body.name, f"type={body.type}", f"provenance={body.provenance}"],
    )
    try:
        e = engagements.create_engagement(
            body.name, scope, body.exclusions, body.notes,
            type=body.type, provenance=body.provenance,
            source_root=source_root, primary_target=primary_target,
        )
    except ValueError as exc:
        audit_log.error(aid, str(exc))
        raise HTTPException(400, str(exc))

    eid = e["id"]

    # Register the primary target so tools in this engagement default to it.
    primary_target_id: str | None = None
    for tname, addr in target_specs:
        t = targets_lib.create_target(
            name=tname, address=addr, kind=target_kind,
            engagement_id=eid, scope_tag=scope_tag,
            source_meta={"origin": "engagement-create"},
        )
        if primary_target_id is None:
            primary_target_id = t["id"]

    # ── Encrypted auth (web-app only; redacted in the response) ────────────
    auth_meta = None
    if body.type == "web-app" and body.auth and body.auth.kind != "none":
        try:
            auth_meta = engagement_secrets.set_auth(eid, body.auth.model_dump())
        except ValueError as exc:
            # Auth is optional — don't fail the whole create, surface the issue.
            logger.warning("engagement %s: auth not stored: %s", eid, exc)
            auth_meta = None

    audit_log.complete(aid, summary=f"created {eid} type={body.type}")
    return {
        **e,
        "primary_target_id": primary_target_id,
        "auth": auth_meta,   # redacted reference only; never the secret
    }


@router.get("/{eid}")
def get_one(eid: str) -> dict[str, Any]:
    e = engagements.get_engagement(eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    return e


@router.patch("/{eid}")
def patch_one(eid: str, body: EngagementPatch) -> dict[str, Any]:
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    patch = body.model_dump(exclude_none=True)
    aid = audit_log.start(
        tool="engagement-patch", target=eid,
        argv=sorted(patch.keys()), engagement_id=eid,
    )
    e = engagements.update_engagement(eid, patch)
    audit_log.complete(aid, summary=",".join(sorted(patch.keys())))
    return e  # type: ignore[return-value]


@router.delete("/{eid}")
def delete_one(eid: str) -> dict[str, bool]:
    aid = audit_log.start(tool="engagement-delete", target=eid, argv=[eid],
                          engagement_id=eid)
    ok = engagements.delete_engagement(eid)
    if not ok:
        audit_log.error(aid, "engagement not found")
        raise HTTPException(404, "engagement not found")
    audit_log.complete(aid, summary="deleted")
    return {"deleted": True}


# ── Engagement auth (encrypted secrets — redacted reads only) ────────────────

@router.get("/{eid}/auth")
def get_auth_meta(eid: str) -> dict[str, Any]:
    """Redacted auth reference for the UI. Never returns secret material —
    only kind + a non-secret hint (last4 / username)."""
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    return {"auth": engagement_secrets.auth_meta(eid)}


@router.put("/{eid}/auth")
def put_auth(eid: str, body: EngagementAuthInput) -> dict[str, Any]:
    """Set / replace / clear (kind=none) the engagement's auth. The secret is
    encrypted at rest; the audit row records only the kind, never the value."""
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    aid = audit_log.start(
        tool="engagement-auth-set", target=eid,
        argv=[f"kind={body.kind}"], engagement_id=eid,
    )
    try:
        meta = engagement_secrets.set_auth(eid, body.model_dump())
    except ValueError as exc:
        audit_log.error(aid, str(exc))
        raise HTTPException(400, str(exc))
    audit_log.complete(aid, summary=f"auth kind={body.kind}")
    return {"auth": meta}


@router.delete("/{eid}/auth")
def delete_auth(eid: str) -> dict[str, bool]:
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    aid = audit_log.start(tool="engagement-auth-delete", target=eid,
                          argv=[eid], engagement_id=eid)
    removed = engagement_secrets.delete_auth(eid)
    audit_log.complete(aid, summary="deleted" if removed else "none")
    return {"deleted": removed}


# ── Results ─────────────────────────────────────────────────────────────────

@router.post("/{eid}/results")
def post_result(eid: str, body: ResultPost) -> dict[str, Any]:
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    aid = audit_log.start(tool=f"result-{body.tool}", target=body.target,
                          argv=[body.tool, body.target], engagement_id=eid)
    r = engagements.record_result(eid, body.tool, body.target,
                                  body.summary, body.raw)
    audit_log.complete(aid, summary=body.summary[:200])
    return r


@router.get("/{eid}/results")
def get_results(eid: str, limit: int = 200) -> dict[str, Any]:
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    return {"results": engagements.list_results(eid, limit=limit)}


@router.get("/{eid}/results/{rid}")
def get_result(eid: str, rid: str) -> dict[str, Any]:
    r = engagements.get_result(rid)
    if not r or r["engagement_id"] != eid:
        raise HTTPException(404, "result not found")
    return r


# ── Coverage matrix ───────────────────────────────────────────────────────────

@router.get("/{eid}/coverage")
def get_coverage(eid: str) -> dict[str, Any]:
    """What's been checked for this engagement — DNS / TLS / headers /
    services / findings / report — derived from the audit log, results
    timeline, and findings. Read-only; see lib/coverage.py."""
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    return coverage.compute_coverage(eid)


# ── Findings ────────────────────────────────────────────────────────────────

@router.post("/{eid}/findings")
def post_finding(eid: str, body: FindingCreate) -> dict[str, Any]:
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    aid = audit_log.start(
        tool="finding-create", target=body.title,
        argv=[body.severity, body.title], engagement_id=eid,
    )
    try:
        f = engagements.create_finding(
            eid, body.title, body.severity,
            description=body.description, evidence=body.evidence,
            cvss=body.cvss, linked_result_id=body.linked_result_id,
        )
    except ValueError as e:
        audit_log.error(aid, str(e))
        raise HTTPException(400, str(e))
    audit_log.complete(aid, summary=f"{body.severity}: {f.get('id', '')}")
    return f


@router.get("/{eid}/findings")
def get_findings(eid: str) -> dict[str, Any]:
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    return {"findings": engagements.list_findings(eid)}


@router.patch("/{eid}/findings/{fid}")
def patch_finding(eid: str, fid: str, body: FindingPatch) -> dict[str, Any]:
    f = engagements.get_finding(fid)
    if not f or f["engagement_id"] != eid:
        raise HTTPException(404, "finding not found")
    patch = body.model_dump(exclude_none=True)
    aid = audit_log.start(
        tool="finding-patch", target=fid,
        argv=sorted(patch.keys()), engagement_id=eid,
    )
    try:
        out = engagements.update_finding(fid, patch)
    except ValueError as e:
        audit_log.error(aid, str(e))
        raise HTTPException(400, str(e))
    audit_log.complete(aid, summary=",".join(sorted(patch.keys())))
    return out  # type: ignore[return-value]


@router.delete("/{eid}/findings/{fid}")
def delete_finding(eid: str, fid: str) -> dict[str, bool]:
    f = engagements.get_finding(fid)
    if not f or f["engagement_id"] != eid:
        raise HTTPException(404, "finding not found")
    aid = audit_log.start(tool="finding-delete", target=fid, argv=[fid],
                          engagement_id=eid)
    engagements.delete_finding(fid)
    audit_log.complete(aid, summary="deleted")
    return {"deleted": True}


# ── Screenshots ─────────────────────────────────────────────────────────────

MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024   # 10 MB cap per upload
ALLOWED_MIMES = {"image/png", "image/jpeg", "image/gif", "image/webp"}


@router.post("/{eid}/findings/{fid}/screenshots")
async def upload_screenshot(eid: str, fid: str, file: UploadFile = File(...)) -> dict[str, Any]:
    f = engagements.get_finding(fid)
    if not f or f["engagement_id"] != eid:
        raise HTTPException(404, "finding not found")
    mime = (file.content_type or "").lower()
    if mime not in ALLOWED_MIMES:
        raise HTTPException(415, f"unsupported image type: {mime}")
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty file")
    if len(data) > MAX_SCREENSHOT_BYTES:
        raise HTTPException(413, f"file too large (max {MAX_SCREENSHOT_BYTES // 1024 // 1024} MB)")
    aid = audit_log.start(
        tool="finding-screenshot-upload", target=fid,
        argv=[_safe_filename(file.filename or "", default="screenshot"), mime, str(len(data))],
        engagement_id=eid,
    )
    s = engagements.add_screenshot(fid, mime, file.filename or "", data)
    audit_log.complete(aid, summary=f"id={s.get('id')} bytes={len(data)}")
    return s


@router.get("/{eid}/findings/{fid}/screenshots")
def list_screenshots(eid: str, fid: str) -> dict[str, Any]:
    f = engagements.get_finding(fid)
    if not f or f["engagement_id"] != eid:
        raise HTTPException(404, "finding not found")
    return {"screenshots": engagements.list_screenshots(fid)}


@router.get("/{eid}/screenshots/{sid}")
def get_screenshot(eid: str, sid: str) -> Response:
    # eid not strictly needed for lookup, but kept for nesting/auth symmetry
    res = engagements.get_screenshot(sid)
    if not res:
        raise HTTPException(404, "screenshot not found")
    mime, filename, data = res
    safe = _safe_filename(filename, default="screenshot")
    return Response(
        content=data, media_type=mime,
        headers={"Content-Disposition": f'inline; filename="{safe}"'},
    )


@router.delete("/{eid}/screenshots/{sid}")
def delete_screenshot(eid: str, sid: str) -> dict[str, bool]:
    aid = audit_log.start(
        tool="finding-screenshot-delete", target=sid, argv=[sid],
        engagement_id=eid,
    )
    if not engagements.delete_screenshot(sid):
        audit_log.error(aid, "screenshot not found")
        raise HTTPException(404, "screenshot not found")
    audit_log.complete(aid, summary="deleted")
    return {"deleted": True}


# ── GitHub Issues export ────────────────────────────────────────────────────

class GithubExportBody(BaseModel):
    owner:        str = Field(..., min_length=1)
    repo:         str = Field(..., min_length=1)
    label_prefix: str = "mhp"
    severity_filter: list[str] | None = None   # only export these severities


@router.post("/{eid}/export/github")
async def export_to_github(eid: str, body: GithubExportBody) -> dict[str, Any]:
    eng = engagements.get_engagement(eid)
    if not eng:
        raise HTTPException(404, "engagement not found")
    token = keychain_get_named("github_token")
    if not token:
        raise HTTPException(401,
            "github_token not configured. POST /settings/keys/github_token with "
            'a personal access token (`repo` scope required).')

    aid = audit_log.start(
        tool="engagement-export-github", target=f"{body.owner}/{body.repo}",
        argv=[body.owner, body.repo, body.label_prefix or "mhp"],
        engagement_id=eid,
    )
    findings = engagements.list_findings(eid)
    if body.severity_filter:
        findings = [f for f in findings if f["severity"] in body.severity_filter]
    if not findings:
        audit_log.complete(aid, summary="no findings match")
        return {"created": [], "skipped": 0,
                "message": "no findings match the filter"}

    created: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "s-ide/0.1",
    }

    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        for f in findings:
            title = f"[{f['severity'].upper()}] {f['title']}"
            label = f"{body.label_prefix}/{f['severity']}"
            evidence = (f.get("evidence") or "")[:8000]
            open_fence, close_fence = _md_code_fence(evidence)
            body_md = (
                f"### Engagement\n{eng['name']}\n\n"
                f"### Severity\n`{f['severity']}`"
                + (f"  ·  CVSS {f['cvss']}" if f.get("cvss") is not None else "")
                + "\n\n"
                f"### Description\n{f.get('description', '') or '_(none)_'}\n\n"
                f"### Evidence\n"
                f"{open_fence}\n{evidence}\n{close_fence}\n\n"
                f"---\n_recorded {f['ts']} · finding id `{f['id']}` · "
                f"engagement `{eid}`_\n"
            )
            try:
                r = await client.post(
                    f"https://api.github.com/repos/{body.owner}/{body.repo}/issues",
                    json={"title": title, "body": body_md, "labels": [label]},
                )
                if r.status_code == 201:
                    issue = r.json()
                    created.append({
                        "finding_id": f["id"],
                        "issue_number": issue.get("number"),
                        "url": issue.get("html_url"),
                    })
                else:
                    failed.append({
                        "finding_id": f["id"],
                        "status": r.status_code,
                        "detail": r.text[:200],
                    })
            except Exception as e:
                logger.exception("github issue export failed finding_id=%s", f.get("id"))
                failed.append({"finding_id": f["id"],
                               "detail": f"{type(e).__name__}: request failed"})

    audit_log.complete(
        aid,
        summary=f"created={len(created)} failed={len(failed)} total={len(findings)}",
    )
    return {"created": created, "failed": failed,
            "total_findings": len(findings)}


# ── Report export ───────────────────────────────────────────────────────────

@router.post("/{eid}/report-link")
def report_link(
    eid: str,
    format: Literal["html", "md"] = "html",
    snapshot_id: str | None = Query(default=None, max_length=64),
) -> dict[str, str]:
    """Mint a one-shot, 30-second URL for the system browser to open.

    The URL embeds a path-bound nonce instead of the long-lived bearer
    token, so it can leak into browser history without compromising the
    backend. The frontend `requestReportLink()` POSTs here, then calls
    window.open(url) on the returned link.
    """
    e = engagements.get_engagement(eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    if snapshot_id:
        snap = engagements.get_report_snapshot(snapshot_id)
        if not snap or snap["engagement_id"] != eid:
            raise HTTPException(404, "snapshot not found")

    path = f"/engagements/{eid}/report"
    nonce = mint_report_nonce(path)
    qs = f"format={format}&nonce={nonce}"
    if snapshot_id:
        qs += f"&snapshot_id={snapshot_id}"
    return {"url": f"{path}?{qs}"}


@router.get("/{eid}/report")
def export_report(
    eid: str,
    format: Literal["html", "md"] = "html",
    snapshot_id: str | None = Query(default=None, max_length=64),
) -> Response:
    e = engagements.get_engagement(eid)
    if not e:
        raise HTTPException(404, "engagement not found")

    if snapshot_id:
        snap = engagements.get_report_snapshot(snapshot_id)
        if not snap or snap["engagement_id"] != eid:
            raise HTTPException(404, "snapshot not found")
        if format == "md":
            return Response(
                content=snap["md"], media_type="text/markdown",
                headers={"Content-Disposition":
                         f'attachment; filename="{_slug(e["name"])}-{snap["ts"]}.md"'},
            )
        return Response(
            content=snap["html"], media_type="text/html; charset=utf-8",
            headers={"Content-Disposition":
                     f'inline; filename="{_slug(e["name"])}-{snap["ts"]}.html"'},
        )

    findings = engagements.list_findings(eid)
    stats = engagements.engagement_stats(eid)
    results = engagements.list_results(eid, limit=500)
    summaries = engagements.list_tool_summaries(eid, limit=500)

    if format == "md":
        body = _render_md(e, findings, results, stats, summaries=summaries)
        return Response(
            content=body, media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{_slug(e["name"])}.md"'},
        )

    body = _render_html(e, findings, results, stats, summaries=summaries)
    return Response(
        content=body, media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'inline; filename="{_slug(e["name"])}.html"'},
    )


# ── Report snapshot lifecycle ───────────────────────────────────────────────

@router.post("/{eid}/report/generate")
def generate_report(eid: str) -> dict[str, Any]:
    """Generate a timestamped report snapshot.

    Runs an AI executive-summary rollup over the engagement's findings + tool
    summaries (skipped gracefully if no API key), bakes the HTML and Markdown
    bodies, and persists the result so subsequent downloads are deterministic.
    Returns the new snapshot's metadata.
    """
    e = engagements.get_engagement(eid)
    if not e:
        raise HTTPException(404, "engagement not found")

    aid = audit_log.start(
        tool="report-snapshot-generate", target=e["name"], argv=[eid],
        engagement_id=eid,
    )
    findings = engagements.list_findings(eid)
    stats = engagements.engagement_stats(eid)
    results = engagements.list_results(eid, limit=500)
    summaries = engagements.list_tool_summaries(eid, limit=500)

    rollup = _generate_rollup(e, findings, summaries, stats)

    html_body = _render_html(e, findings, results, stats,
                             summaries=summaries, rollup=rollup)
    md_body = _render_md(e, findings, results, stats,
                         summaries=summaries, rollup=rollup)

    snap = engagements.create_report_snapshot(
        engagement_id=eid, rollup=rollup, html=html_body, md=md_body,
    )
    audit_log.complete(
        aid,
        summary=f"snapshot={snap.get('id', '')} findings={len(findings)} summaries={len(summaries)}",
    )
    return {
        **snap,
        "engagement_name": e["name"],
        "finding_count": len(findings),
        "summary_count": len(summaries),
    }


@router.get("/{eid}/reports")
def list_reports(eid: str) -> dict[str, Any]:
    if engagements.get_engagement(eid) is None:
        raise HTTPException(404, "engagement not found")
    return {"snapshots": engagements.list_report_snapshots(eid)}


@router.delete("/{eid}/reports/{sid}")
def delete_report(eid: str, sid: str) -> dict[str, bool]:
    snap = engagements.get_report_snapshot(sid)
    if not snap or snap["engagement_id"] != eid:
        raise HTTPException(404, "snapshot not found")
    aid = audit_log.start(
        tool="report-snapshot-delete", target=sid, argv=[sid],
        engagement_id=eid,
    )
    engagements.delete_report_snapshot(sid)
    audit_log.complete(aid, summary="deleted")
    return {"deleted": True}


# ── AI rollup ───────────────────────────────────────────────────────────────

def _rollup_prompt_path() -> Path:
    override = os.getenv("MHP_ROLLUP_SYSTEM_PROMPT_FILE", "").strip()
    if override:
        return Path(override)
    # Mirror chat.py's resolution: bundle path inside PyInstaller, repo path otherwise.
    import sys as _sys
    meipass = getattr(_sys, "_MEIPASS", None)
    base = Path(meipass) / "prompts" if meipass else \
           Path(__file__).resolve().parent.parent / "prompts"
    return base / "report_rollup.md"


def _resolve_rollup_prompt() -> str:
    raw = os.getenv("MHP_ROLLUP_SYSTEM_PROMPT", "").strip()
    if raw:
        return raw
    try:
        return _rollup_prompt_path().read_text(encoding="utf-8")
    except Exception:
        return ("Write the engagement's executive summary: posture (2-3 lines), "
                "top risks (bullets), recommended remediation (bullets). Terse, "
                "markdown, no fluff.")


def _generate_rollup(
    e: dict[str, Any], findings: list[dict[str, Any]],
    summaries: list[dict[str, Any]], stats: dict[str, Any],
) -> str:
    """Best-effort: produce an executive-summary blob in Markdown.

    Returns empty string if no API key is configured or the call fails — the
    rest of the report still renders.
    """
    api_key = keychain_get()
    if not api_key:
        return ""

    # Compact, ranked feed: highest-severity findings first, then summaries.
    findings_sorted = sorted(
        findings,
        key=lambda f: engagements.SEVERITY_ORDER.get(f["severity"], 99),
    )
    findings_block = "\n".join(
        f"- [{f['severity']}] {f['title']}"
        + (f" (target `{f['target']}`, tool `{f['tool']}`)"
           if f.get("target") or f.get("tool") else "")
        + (f" — {(f.get('description') or '')[:200]}"
           if f.get("description") else "")
        for f in findings_sorted[:40]
    ) or "_no findings recorded_"

    summaries_block = "\n\n".join(
        f"**{s['tool']}** ({s.get('target') or 'no target'}, {s['ts']}):\n{s['summary']}"
        for s in summaries[:20]
    ) or "_no tool summaries recorded_"

    user_message = (
        f"**Engagement:** {e['name']}\n"
        f"**Scope:** {', '.join(e['scope']) if e['scope'] else '_(unscoped)_'}\n"
        f"**Stats:** {stats['result_count']} runs · "
        f"{stats['finding_count']} findings · "
        f"{len(stats['tools_used'])} tools used\n\n"
        f"## Findings (severity-ordered)\n{findings_block}\n\n"
        f"## Per-tool summaries\n{summaries_block}\n"
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=os.getenv("MHP_CHAT_MODEL", "").strip() or "claude-sonnet-4-6",
            max_tokens=1400,
            system=[{
                "type": "text",
                "text": _resolve_rollup_prompt(),
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": user_message}],
        )
        chunks: list[str] = []
        for block in msg.content:
            if getattr(block, "type", None) == "text":
                chunks.append(block.text)
        return _strip_rollup_wrapper("".join(chunks).strip())
    except Exception:
        logger.exception("report rollup generation failed")
        return ""


def _strip_rollup_wrapper(text: str) -> str:
    """Drop a leading wrapper heading like `## Executive Summary…` if the model
    emitted one despite the prompt asking it not to.

    Walks through any blank lines / horizontal rules between the wrapper and
    the first real `## Posture` (or other expected) section. Idempotent.
    """
    if not text:
        return text
    lines = text.splitlines()
    i = 0
    # Skip leading blanks.
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i < len(lines):
        head = lines[i].strip().lower()
        # Match any `#`/`##`/`###`/`####` line containing "executive summary"
        # or generic "summary"/"report" — these are all the wrapper variants
        # we've seen the model emit despite the prompt asking it not to.
        if re.match(r"^#{1,4}\s+", head) and (
            "executive summary" in head
            or head.endswith("summary")
            or head.endswith("report")
        ):
            i += 1
            # Skip blank lines and horizontal rules right after the wrapper.
            while i < len(lines) and (not lines[i].strip() or
                                       lines[i].strip().startswith("---")):
                i += 1
            return "\n".join(lines[i:]).strip()
    return text.strip()


# ── Tiny markdown subset → HTML (for AI-authored sections) ──────────────────

_MD_INLINE_PATTERNS = (
    (re.compile(r"`([^`\n]+)`"), r"<code>\1</code>"),
    (re.compile(r"\*\*([^*\n]+)\*\*"), r"<strong>\1</strong>"),
    (re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)"), r"<em>\1</em>"),
)


def _md_to_html(md: str) -> str:
    """Convert the constrained markdown the AI prompts produce into safe HTML.

    Handles only: ## / ### headers, - / * bullets, **bold**, *em*, `code`,
    blank-line paragraphs. Everything else is escaped. Output is wrapped in
    a single <div> so callers can style it as a block.
    """
    if not md:
        return ""
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    in_ul = False

    def close_ul() -> None:
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False

    def inline(s: str) -> str:
        s = html.escape(s)
        for pat, rep in _MD_INLINE_PATTERNS:
            s = pat.sub(rep, s)
        return s

    for raw_line in lines:
        line = raw_line.rstrip()
        if not line.strip():
            close_ul()
            continue
        m = re.match(r"^(#{2,4})\s+(.*)$", line)
        if m:
            close_ul()
            # Demote one level so AI-authored subheadings sit under the
            # report's outer <h2> section header.
            level = min(len(m.group(1)) + 1, 5)
            out.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
            continue
        m = re.match(r"^[-*]\s+(.*)$", line)
        if m:
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{inline(m.group(1))}</li>")
            continue
        close_ul()
        out.append(f"<p>{inline(line)}</p>")
    close_ul()
    return '<div class="ai-block">' + "".join(out) + "</div>"


# ── Renderers ───────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#cf222e",
    "high":     "#cf6f22",
    "medium":   "#9a6700",
    "low":      "#0969da",
    "info":     "#57606a",
}


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in name).strip("-").lower()[:50] or "report"


def _render_html(
    e: dict[str, Any], findings: list[dict[str, Any]],
    results: list[dict[str, Any]], stats: dict[str, Any],
    summaries: list[dict[str, Any]] | None = None,
    rollup: str = "",
) -> str:
    summaries = summaries or []
    screenshots = engagements.screenshots_for_engagement(e["id"])
    # Sort findings: critical → info, then most-recent within tier (by created_at desc)
    findings = sorted(
        findings,
        key=lambda f: (engagements.SEVERITY_ORDER.get(f["severity"], 99),
                       -float(f.get("created_at") or 0)),
    )

    parts: list[str] = []
    parts.append(f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>{html.escape(e['name'])} — Engagement Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          max-width: 880px; margin: 2em auto; padding: 0 2em; color: #1f2328; }}
  h1, h2, h3 {{ color: #1f2328; }}
  h1 {{ border-bottom: 2px solid #1f2328; padding-bottom: .3em; }}
  .meta {{ color: #57606a; font-size: 14px; margin-bottom: 2em; }}
  .scope, .summary {{ background: #f6f8fa; border: 1px solid #d0d7de; padding: 1em;
                      border-radius: 6px; margin: 1em 0; }}
  .scope code, .summary code {{ font-family: ui-monospace, monospace; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ text-align: left; padding: .5em .75em; border-bottom: 1px solid #d0d7de; }}
  th {{ background: #f6f8fa; font-size: 12px; text-transform: uppercase;
        letter-spacing: .04em; color: #57606a; }}
  .sev-pill {{ display: inline-block; padding: 1px 8px; border-radius: 10px;
               color: white; font-size: 11px; font-weight: bold;
               text-transform: uppercase; letter-spacing: .04em; }}
  .finding {{ border: 1px solid #d0d7de; border-radius: 6px; padding: 1em;
              margin-bottom: 1em; }}
  .finding h3 {{ margin-top: 0; }}
  .finding pre {{ background: #f6f8fa; padding: .75em; border-radius: 4px;
                  overflow-x: auto; font-size: 12px; }}
  footer {{ margin-top: 4em; padding-top: 1em; border-top: 1px solid #d0d7de;
            color: #57606a; font-size: 12px; }}
  .ai-block {{ background: #f6f8fa; border-left: 3px solid #6e40c9;
              border-radius: 4px; padding: .25em 1em; margin: .75em 0; }}
  .ai-block h3, .ai-block h4 {{ margin-top: 1em; margin-bottom: .3em;
                                font-size: 13px; text-transform: uppercase;
                                letter-spacing: .04em; color: #6e40c9; }}
  .ai-block ul {{ margin: .3em 0 .8em 1.2em; padding: 0; }}
  .ai-block li {{ margin: .2em 0; }}
  .ai-block p {{ margin: .4em 0; }}
  .tool-summary {{ border: 1px solid #d0d7de; border-left: 3px solid #6e40c9;
                  border-radius: 4px; padding: .5em 1em; margin-bottom: .75em; }}
  .tool-summary .meta {{ font-size: 12px; color: #57606a; margin: 0 0 .25em 0; }}
  .badge {{ display: inline-block; font-size: 10px; font-weight: bold;
           text-transform: uppercase; letter-spacing: .04em; color: white;
           background: #6e40c9; padding: 1px 6px; border-radius: 8px;
           margin-right: .4em; }}
  @media print {{ body {{ max-width: none; margin: 0; }} }}
</style></head><body>
<h1>{html.escape(e['name'])}</h1>
<div class="meta">
  Engagement Report · Status: <b>{html.escape(e['status'])}</b><br>
  Created {html.escape(e['created_at'])} · Last activity {html.escape(e['updated_at'])}
</div>

<h2>Scope</h2>
<div class="scope">
""")
    if e["scope"]:
        parts.append("<b>In-scope:</b><ul>")
        for s in e["scope"]:
            parts.append(f"<li><code>{html.escape(s)}</code></li>")
        parts.append("</ul>")
    else:
        parts.append("<p><em>No scope defined.</em></p>")
    if e["exclusions"]:
        parts.append("<b>Out-of-scope (exclusions):</b><ul>")
        for s in e["exclusions"]:
            parts.append(f"<li><code>{html.escape(s)}</code></li>")
        parts.append("</ul>")
    parts.append("</div>")

    if e["notes"]:
        parts.append(
            f"<h2>Notes</h2><div class='scope'><pre style='white-space: pre-wrap; "
            f"background: none; padding: 0;'>{html.escape(e['notes'])}</pre></div>"
        )

    # Executive summary
    parts.append("<h2>Executive Summary</h2>")
    if rollup:
        parts.append(_md_to_html(rollup))
    parts.append("<div class='summary'>")
    parts.append(f"<p>{stats['result_count']} scan results recorded across "
                 f"{len(stats['tools_used'])} distinct tools.</p>")
    if stats["findings_by_severity"]:
        parts.append("<p><b>Findings by severity:</b></p><ul>")
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in stats["findings_by_severity"]:
                color = SEVERITY_COLORS.get(sev, "#57606a")
                parts.append(
                    f"<li><span class='sev-pill' style='background:{color}'>"
                    f"{sev}</span> {stats['findings_by_severity'][sev]}</li>"
                )
        parts.append("</ul>")
    else:
        parts.append("<p><em>No findings recorded.</em></p>")
    parts.append("</div>")

    # Findings
    parts.append("<h2>Findings</h2>")
    if not findings:
        parts.append("<p><em>No findings.</em></p>")
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "#57606a")
        parts.append(f"""<div class="finding">
  <h3>
    <span class="sev-pill" style="background:{color}">{html.escape(f['severity'])}</span>
    {html.escape(f['title'])}
  </h3>
  <div class="meta">Status: {html.escape(f['status'])}{
    f' · CVSS {f["cvss"]}' if f.get("cvss") is not None else ""
  } · Recorded {html.escape(f['ts'])}</div>
""")
        if f["description"]:
            parts.append(f"<p>{html.escape(f['description']).replace(chr(10), '<br>')}</p>")
        if f["evidence"]:
            parts.append(f"<pre>{html.escape(f['evidence'])}</pre>")
        # Inline screenshots as base64 data URIs so the HTML is self-contained
        # — survives saving to disk, no broken-image refs after exporting.
        shots = screenshots.get(f["id"], [])
        for s in shots:
            try:
                b64 = base64.b64encode(s["data"]).decode("ascii")
                parts.append(
                    f'<figure style="margin: 1em 0;">'
                    f'<img src="data:{s["mime"]};base64,{b64}" '
                    f'alt="{html.escape(s["filename"] or "screenshot")}" '
                    f'style="max-width:100%; border:1px solid #d0d7de; border-radius:4px;">'
                    f'<figcaption style="font-size:11px; color:#57606a; margin-top:4px;">'
                    f'{html.escape(s["filename"] or "screenshot")}</figcaption></figure>'
                )
            except Exception:
                pass
        parts.append("</div>")

    # Tool summaries (AI rollups per tool run — between findings and raw log)
    if summaries:
        parts.append("<h2>Tool Summaries</h2>")
        parts.append("<p style='color:#57606a;font-size:13px;'>"
                     "AI-generated synthesis of each tool run that was "
                     "summarized during the engagement.</p>")
        for s in summaries:
            target_html = (f" · <code>{html.escape(s.get('target') or '')}</code>"
                           if s.get("target") else "")
            parts.append(
                f'<div class="tool-summary">'
                f'<div class="meta"><span class="badge">AI</span>'
                f'<code>{html.escape(s["tool"])}</code>{target_html} · '
                f'{html.escape(s["ts"])}</div>'
                f'{_md_to_html(s["summary"])}'
                f'</div>'
            )

    # Results summary (tool/target/timestamp only — raw bodies omitted from report)
    parts.append("<h2>Activity Log</h2>")
    if not results:
        parts.append("<p><em>No scan activity.</em></p>")
    else:
        parts.append("<table><thead><tr><th>Timestamp</th><th>Tool</th>"
                     "<th>Target</th><th>Summary</th></tr></thead><tbody>")
        for r in results:
            parts.append(
                f"<tr><td>{html.escape(r['ts'])}</td>"
                f"<td><code>{html.escape(r['tool'])}</code></td>"
                f"<td><code>{html.escape(r['target'])}</code></td>"
                f"<td>{html.escape(r['summary'][:200])}</td></tr>"
            )
        parts.append("</tbody></table>")

    parts.append("""<footer>
Generated by s-ide. Use your browser's <em>File → Print → Save as PDF</em>
to export this report as a PDF.
</footer></body></html>""")
    return "".join(parts)


def _render_md(
    e: dict[str, Any], findings: list[dict[str, Any]],
    results: list[dict[str, Any]], stats: dict[str, Any],
    summaries: list[dict[str, Any]] | None = None,
    rollup: str = "",
) -> str:
    summaries = summaries or []
    findings = sorted(
        findings,
        key=lambda f: engagements.SEVERITY_ORDER.get(f["severity"], 99),
    )
    out: list[str] = []
    out.append(f"# {e['name']}\n")
    out.append(f"_Engagement Report · Status: **{e['status']}**_\n")
    out.append(f"_Created {e['created_at']} · Last activity {e['updated_at']}_\n")

    out.append("\n## Scope\n")
    if e["scope"]:
        out.append("**In-scope:**\n")
        for s in e["scope"]:
            out.append(f"- `{s}`")
    else:
        out.append("_No scope defined._")
    if e["exclusions"]:
        out.append("\n**Out-of-scope (exclusions):**\n")
        for s in e["exclusions"]:
            out.append(f"- `{s}`")

    if e["notes"]:
        out.append(f"\n## Notes\n\n{e['notes']}\n")

    out.append("\n## Executive Summary\n")
    if rollup:
        out.append(rollup)
        out.append("")
        out.append("### Activity totals")
    out.append(f"- {stats['result_count']} scan results across {len(stats['tools_used'])} tools.")
    if stats["findings_by_severity"]:
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in stats["findings_by_severity"]:
                out.append(f"- **{sev.upper()}**: {stats['findings_by_severity'][sev]}")
    else:
        out.append("- No findings recorded.")

    out.append("\n## Findings\n")
    if not findings:
        out.append("_No findings._")
    for f in findings:
        cvss = f" · CVSS {f['cvss']}" if f.get("cvss") is not None else ""
        out.append(f"\n### [{f['severity'].upper()}] {f['title']}\n")
        out.append(f"_Status: {f['status']}{cvss} · {f['ts']}_\n")
        if f["description"]:
            out.append(f"\n{f['description']}\n")
        if f["evidence"]:
            open_fence, close_fence = _md_code_fence(f["evidence"])
            out.append(f"\n{open_fence}\n{f['evidence']}\n{close_fence}\n")

    if summaries:
        out.append("\n## Tool Summaries\n")
        out.append("_AI-generated synthesis of each tool run that was "
                   "summarized during the engagement._\n")
        for s in summaries:
            target_part = f" · target `{s['target']}`" if s.get("target") else ""
            out.append(f"### `{s['tool']}`{target_part}\n")
            out.append(f"_{s['ts']}_\n")
            out.append(s["summary"])
            out.append("")

    out.append("\n## Activity Log\n")
    if not results:
        out.append("_No scan activity._")
    else:
        out.append("| Timestamp | Tool | Target | Summary |")
        out.append("|---|---|---|---|")
        for r in results:
            out.append(
                f"| {r['ts']} | `{r['tool']}` | `{r['target']}` | "
                f"{r['summary'][:200].replace(chr(124), '|').replace(chr(10), ' ')} |"
            )

    return "\n".join(out) + "\n"


# ── Tool catalog suggestions (consumed by frontend) ────────────────────────

@router.get("/_catalog/suggestions")
def catalog_suggestions() -> dict[str, Any]:
    """Curated list of tools the user could plan to build next. Pre-populated
    from the user's wishlist (AD / Cloud / OSINT / Wireless / Post-Exploit /
    Reporting). The frontend offers a 'Seed with suggestions' button that
    bulk-adds these into the local planned-tools list."""
    return {"suggestions": CATALOG_SUGGESTIONS}


CATALOG_SUGGESTIONS: list[dict[str, str]] = [
    # ── Active Directory ────────────────────────────────────────────────────
    {"category": "Active Directory", "label": "LDAP Enumerator",
     "description": "Enumerate users, groups, OUs, GPOs, and password policy via LDAP. Impacket-based (pure Python)."},
    {"category": "Active Directory", "label": "Kerberoasting",
     "description": "SPN enumeration + TGS ticket request. Crack offline with hashcat. Impacket GetUserSPNs flow."},
    {"category": "Active Directory", "label": "AS-REP Roasting",
     "description": "Harvest accounts with pre-auth disabled. Crack the AS-REP offline. Impacket GetNPUsers flow."},
    {"category": "Active Directory", "label": "BloodHound Ingestor",
     "description": "Collect attack-path data from a domain. SharpHound-equivalent in Python."},
    {"category": "Active Directory", "label": "SMB Enumerator",
     "description": "Enumerate shares, null sessions, and logged-in users via SMB. Impacket smbclient flow."},
    {"category": "Active Directory", "label": "AD Password Sprayer",
     "description": "Domain-aware password spray. Respects lockout policy; backs off when threshold approaches."},

    # ── Cloud Security ──────────────────────────────────────────────────────
    {"category": "Cloud Security", "label": "AWS Enumeration",
     "description": "IAM, S3 buckets, exposed instance metadata, misconfigured roles. Read-only checks."},
    {"category": "Cloud Security", "label": "Azure Recon",
     "description": "Tenant enumeration, exposed blob storage, app registrations."},
    {"category": "Cloud Security", "label": "GCP Recon",
     "description": "Project discovery, exposed buckets, service-account leaks."},
    {"category": "Cloud Security", "label": "IMDS Tester",
     "description": "Dedicated cloud metadata diagnostic. Probes AWS / Azure / GCP IMDS from a chosen origin."},
    {"category": "Cloud Security", "label": "S3 Bucket Scanner",
     "description": "Permutation-based public S3 bucket finder. Given a target name, generate plausible names and check ACLs."},

    # ── OSINT depth ─────────────────────────────────────────────────────────
    {"category": "OSINT", "label": "Breach Data Lookup",
     "description": "HaveIBeenPwned + DeHashed for emails and passwords. Identifies users whose creds have leaked."},
    {"category": "OSINT", "label": "LinkedIn Scraper",
     "description": "Employee enumeration for social engineering. Outputs name / role / email-format guesses."},
    {"category": "OSINT", "label": "Google Dorking",
     "description": "Automated dork generation + execution for a target. Surfaces exposed files, login pages, configs."},
    {"category": "OSINT", "label": "Paste / GitHub Leak Scanner",
     "description": "Credentials and secrets in public pastes. Scans Pastebin, GitHub code search, GitHub gists."},
    {"category": "OSINT", "label": "People Search Aggregator",
     "description": "theHarvester-style email + name + phone collection from multiple OSINT sources."},
    {"category": "OSINT", "label": "Shodan / Censys Query",
     "description": "Full API query UI for Shodan and Censys, not just subdomain enum."},

    # ── Wireless ────────────────────────────────────────────────────────────
    {"category": "Wireless", "label": "WPA Handshake Capture",
     "description": "Monitor mode + deauth + capture WPA handshake. Needs a compatible adapter."},
    {"category": "Wireless", "label": "Evil Twin Detector",
     "description": "Find rogue APs matching known SSIDs in range. Passive monitor."},
    {"category": "Wireless", "label": "PMKID Attack",
     "description": "Modern WPA2 crack without deauth. Capture PMKID directly."},
    {"category": "Wireless", "label": "Bluetooth Recon",
     "description": "Device discovery + service enumeration over Bluetooth + BLE."},

    # ── Post-Exploitation ───────────────────────────────────────────────────
    {"category": "Post-Exploitation", "label": "Payload Obfuscator",
     "description": "Base64 / XOR / AMSI bypass wrappers for shell payloads. UI for stacking transforms."},
    {"category": "Post-Exploitation", "label": "C2 Beacon Simulator",
     "description": "Test if your reverse shells can call back through a firewall. Spins up a listener and target callback."},
    {"category": "Post-Exploitation", "label": "Credential Harvester",
     "description": "Parse loot from common locations (browser DBs, SSH configs, AWS credentials, .env files)."},
    {"category": "Post-Exploitation", "label": "Lateral Movement Planner",
     "description": "Given BloodHound data, suggest next-hop targets and reachable ACL paths."},
    {"category": "Post-Exploitation", "label": "Pivoting Helper",
     "description": "SSH tunnel / SOCKS proxy builder with a visual chain diagram."},

    # ── Reporting extras (engagement system covers the core) ────────────────
    {"category": "Reporting", "label": "CVSS Calculator (built-in)",
     "description": "CVSS v3.1 calculator embedded in the finding form. Maps vector strings to numeric score."},
    {"category": "Reporting", "label": "Screenshot evidence attachments",
     "description": "Attach screenshots to findings; embedded in the HTML/PDF report."},
    {"category": "Reporting", "label": "GitHub Issues export",
     "description": "Push findings directly into a GitHub repo's issues, one issue per finding."},
]
