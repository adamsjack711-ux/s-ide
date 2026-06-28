"""BloodHound Ingestor — wraps the `bloodhound.py` SharpHound-equivalent.

The bloodhound library is **synchronous and slow** for large domains (minutes).
We run each collection in a background thread, track it as a "job", let the
UI poll for status, and on completion ZIP up the output JSON files so the user
can download + import into their own BloodHound instance.

One job per process at a time — concurrent BloodHound runs against the same
DC are unfriendly to defenders and rarely useful.
"""
from __future__ import annotations

import io
import logging
import os
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from lib import audit_log, scope
from lib.ad_auth import CredsModel
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bloodhound", tags=["bloodhound"])

COLLECTION_METHODS = [
    "Default",   # the standard SharpHound mix
    "Group", "LocalAdmin", "Session", "ACL",
    "Trusts", "Container", "ObjectProps",
    "RDP", "DCOM", "PSRemote",
    "All",
]


class IngestBody(BaseModel):
    creds:          CredsModel
    methods:        list[str] = Field(default_factory=lambda: ["Default"])
    nameserver:     str = Field("", description="DNS server; defaults to dc_host")
    num_workers:    int = Field(default=10, ge=1, le=50)
    zip_jsons:      bool = True
    confirm_auth:   bool = Field(False, description="I have authorization to run BloodHound collection against this domain")
    engagement_id:  str | None = Field(None, description="Active engagement id (audit-log + scope)")


class Job:
    def __init__(self, jid: str) -> None:
        self.id = jid
        self.state = "queued"   # queued | running | done | error
        self.started_at = ""
        self.finished_at = ""
        self.error = ""
        self.log: list[str] = []
        self.workdir = tempfile.mkdtemp(prefix="bh_")
        self.zip_path: str | None = None
        self.file_count = 0
        self.audit_id: str | None = None

    def line(self, msg: str) -> None:
        self.log.append(f"{time.strftime('%H:%M:%S')} {msg}")
        # Keep the log bounded — UI shows last ~500 lines
        if len(self.log) > 1000:
            self.log = self.log[-500:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "state": self.state,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "error": self.error, "log_tail": self.log[-50:],
            "file_count": self.file_count,
            "has_zip": bool(self.zip_path and os.path.exists(self.zip_path)),
        }


_jobs: dict[str, Job] = {}
_lock = threading.Lock()


def _run_collection(job: Job, body: IngestBody) -> None:
    """Synchronous BloodHound collection — runs in a background thread."""
    job.state = "running"
    job.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    job.line(f"Workdir: {job.workdir}")

    try:
        # Imports here so the bloodhound dep is loaded lazily (slow import)
        from bloodhound.ad.authentication import ADAuthentication
        from bloodhound.ad.domain import AD
        from bloodhound import BloodHound
    except ImportError as e:
        job.state = "error"
        job.error = f"bloodhound library unavailable: {e}"
        return

    creds = body.creds
    nameserver = body.nameserver or creds.dc_host

    try:
        auth = ADAuthentication(
            username=creds.username,
            password=creds.password if not creds.nt_hash else "",
            domain=creds.domain,
            lm_hash=creds.nt_hash and "aad3b435b51404eeaad3b435b51404ee" or "",
            nt_hash=creds.nt_hash.lower() if creds.nt_hash else "",
            auth_method="auto",
        )
        ad = AD(auth=auth, domain=creds.domain, nameserver=nameserver,
                dns_tcp=False, dns_timeout=3.0)
        job.line(f"Resolving DC for {creds.domain}…")
        ad.dns_resolve(domain=creds.domain)

        bh = BloodHound(ad)
        job.line("Connecting to AD…")
        bh.connect()

        # Run collection with cwd set to job.workdir so the JSONs land there
        prev_cwd = os.getcwd()
        os.chdir(job.workdir)
        try:
            job.line(f"Collection methods: {', '.join(body.methods)}")
            bh.run(
                collect=body.methods,
                num_workers=body.num_workers,
                disable_pooling=False,
            )
        finally:
            os.chdir(prev_cwd)

        # Gather the JSON files bloodhound wrote
        jsons = [f for f in os.listdir(job.workdir) if f.endswith(".json")]
        job.file_count = len(jsons)
        job.line(f"Wrote {len(jsons)} JSON file(s).")

        if body.zip_jsons and jsons:
            zpath = os.path.join(job.workdir, f"bloodhound_{creds.domain}_{int(time.time())}.zip")
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in jsons:
                    zf.write(os.path.join(job.workdir, f), arcname=f)
            job.zip_path = zpath
            job.line(f"ZIP: {os.path.basename(zpath)}")

        job.state = "done"
        if job.audit_id:
            try: audit_log.complete(job.audit_id,
                                    summary=f"{job.file_count} JSON files, methods={','.join(body.methods)}")
            except Exception: logger.exception("audit_log finalize failed")
    except Exception as exc:
        logger.exception("bloodhound collection failed job=%s", job.id)
        job.state = "error"
        job.error = "BloodHound collection failed — see server log for details."
        job.line(f"FAILED: {job.error}")
        if job.audit_id:
            try: audit_log.error(job.audit_id, f"{type(exc).__name__}: {exc}")
            except Exception: pass
    finally:
        job.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@router.get("/methods")
def methods() -> dict[str, Any]:
    return {"methods": COLLECTION_METHODS}


@router.post("/run")
def start_run(body: IngestBody, request: Request) -> dict[str, Any]:
    if not body.confirm_auth:
        raise MhpError(
            "Confirm you have authorization to run BloodHound collection against this domain.",
            code=ErrorCode.NEED_CONFIRM, status_code=409,
        )
    eid = body.engagement_id or get_engagement_id(request)
    scope.enforce_rest(
        body.creds.dc_host or body.creds.domain, eid, get_mode(request),
    )
    with _lock:
        running = [j for j in _jobs.values() if j.state in ("queued", "running")]
        if running:
            raise HTTPException(409,
                f"Another BloodHound job is already running ({running[0].id}).")
        if not body.creds.username or (not body.creds.password and not body.creds.nt_hash):
            raise HTTPException(400,
                "BloodHound collection needs valid AD credentials.")
        if not body.creds.domain:
            raise HTTPException(400, "domain is required (e.g. corp.local)")
        for m in body.methods:
            if m not in COLLECTION_METHODS:
                raise HTTPException(400, f"unknown collection method: {m}")

        jid = uuid.uuid4().hex[:12]
        job = Job(jid)
        try:
            job.audit_id = audit_log.start(
                tool="bloodhound",
                target=body.creds.domain or body.creds.dc_host,
                argv=[body.creds.dc_host,
                      f"methods={','.join(body.methods)}",
                      f"workers={body.num_workers}"],
                engagement_id=body.engagement_id,
            )
        except Exception:
            logger.exception("audit_log.start failed (job continues)")
        _jobs[jid] = job

    thread = threading.Thread(target=_run_collection, args=(job, body), daemon=True)
    thread.start()
    return {"job": job.to_dict()}


@router.get("/jobs")
def list_jobs() -> dict[str, Any]:
    return {"jobs": [j.to_dict() for j in _jobs.values()]}


@router.get("/jobs/{jid}")
def get_job(jid: str) -> dict[str, Any]:
    j = _jobs.get(jid)
    if not j:
        raise HTTPException(404, "job not found")
    return {**j.to_dict(), "log": j.log}


@router.get("/jobs/{jid}/download")
def download_zip(jid: str) -> Response:
    j = _jobs.get(jid)
    if not j:
        raise HTTPException(404, "job not found")
    if not j.zip_path or not os.path.exists(j.zip_path):
        raise HTTPException(404, "no zip available (job not finished or no data)")
    with open(j.zip_path, "rb") as f:
        data = f.read()
    return Response(
        content=data, media_type="application/zip",
        headers={"Content-Disposition":
                 f'attachment; filename="{os.path.basename(j.zip_path)}"'},
    )


@router.delete("/jobs/{jid}")
def delete_job(jid: str) -> dict[str, bool]:
    j = _jobs.pop(jid, None)
    if not j:
        raise HTTPException(404, "job not found")
    try:
        shutil.rmtree(j.workdir, ignore_errors=True)
    except Exception:
        pass
    return {"deleted": True}
