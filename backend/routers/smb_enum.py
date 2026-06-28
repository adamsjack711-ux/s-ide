"""SMB Enumerator — Impacket-based.

Two modes of auth:
  - Authenticated: `CredsModel.username` + password OR `nt_hash` (pass-the-hash)
  - Null session: leave both empty — older / misconfigured servers accept this

For each accessible share we list READ access (and try a 1-deep listing to
sample contents) plus WRITE access (we don't write — just check the perms
flag in the response). We never delete or modify anything.

Optional target host (`target`) lets the user point at non-DC SMB hosts;
defaults to `dc_host`.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from lib import scope
from lib.ad_auth import CredsModel, open_smb
from lib.errors import ErrorCode, MhpError
from lib.mode import get_mode
from lib.validators import validate_hostname

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/smb", tags=["smb-enum"])

# Share names we flag as high-interest if found
INTERESTING_SHARE_NAMES = {
    "backup", "backups", "it", "admin", "share", "shared",
    "hr", "finance", "users$", "home", "data",
    "scripts", "netlogon", "sysvol",
}


class EnumBody(BaseModel):
    creds:  CredsModel
    target: str = Field("", description="SMB host (defaults to dc_host)")
    list_files: bool = True  # try to list top-level files in each readable share
    engagement_id: str | None = Field(None, description="Active engagement (for scope check + audit)")
    confirm: bool = Field(False, description="Set true to re-submit after acknowledging a `warn` verdict")


def _add(out: list[dict[str, Any]], severity: str, title: str,
         detail: str, evidence: Any = None) -> None:
    out.append({"severity": severity, "title": title,
                "detail": detail, "evidence": evidence})


@router.post("/enum")
def enum(body: EnumBody, request: Request) -> dict[str, Any]:
    body.creds.dc_host = validate_hostname(body.creds.dc_host, field="dc_host")
    target = body.target or body.creds.dc_host
    target = validate_hostname(target, field="target")

    # Scope check — combines target_policy + engagement scope, gated by
    # Lab/Engagement mode (resolved from the X-MHP-Mode header).
    mode = get_mode(request)
    sc_verdict, sc_reason, sc_layers = scope.check_combined(
        target, body.engagement_id, mode,
    )
    if sc_verdict == "deny":
        raise MhpError(
            f"scope check failed: {sc_reason}",
            code=ErrorCode.TARGET_DENIED,
            status_code=403,
            extra={"target": target, "layers": sc_layers},
        )
    if sc_verdict == "warn" and not body.confirm:
        raise MhpError(
            sc_reason,
            code=ErrorCode.NEED_CONFIRM,
            status_code=409,
            extra={"target": target, "need_confirm": True, "layers": sc_layers},
        )

    try:
        conn = open_smb(body.creds, target=target)
    except Exception:
        logger.exception("smb_enum SMB login failed")
        raise MhpError(
            "SMB login failed",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        ) from None

    findings: list[dict[str, Any]] = []
    try:
        server_os = conn.getServerOS() or ""
        domain_or_workgroup = conn.getServerDomain() or ""
        server_name = conn.getServerName() or ""
        if conn.isGuestSession() == 1:
            _add(findings, "high",
                 "Server accepted guest authentication",
                 f"Connection to {target!r} was downgraded to a guest session — "
                 "anonymous access permitted.",
                 evidence={"target": target})

        shares: list[dict[str, Any]] = []
        try:
            for s in conn.listShares():
                share = {
                    "name":    s["shi1_netname"][:-1] if s["shi1_netname"].endswith("\x00") else s["shi1_netname"],
                    "type":    s["shi1_type"],
                    "comment": s["shi1_remark"][:-1] if s["shi1_remark"].endswith("\x00") else s["shi1_remark"],
                    "readable": False, "files": [],
                }
                # listPath probes whether we can read root
                if body.list_files:
                    try:
                        files = conn.listPath(share["name"], "*")
                        share["readable"] = True
                        sample = []
                        for f in files:
                            name = f.get_longname()
                            if name in (".", ".."):
                                continue
                            sample.append({"name": name, "size": f.get_filesize(),
                                           "is_dir": f.is_directory()})
                            if len(sample) >= 50:
                                break
                        share["files"] = sample
                    except Exception:
                        share["readable"] = False

                shares.append(share)

                low_name = share["name"].lower()
                if share["readable"] and low_name in INTERESTING_SHARE_NAMES:
                    _add(findings, "high",
                         f"Readable interesting share: {share['name']!r}",
                         f"Share {share['name']!r} is readable and matches a known "
                         "high-interest name pattern.",
                         evidence=share)
                elif share["readable"] and low_name not in (
                    "ipc$", "print$", "admin$", "c$",  # default admin shares
                ):
                    _add(findings, "medium",
                         f"Readable share: {share['name']!r}",
                         f"Share {share['name']!r} is readable. Triage contents.",
                         evidence={"name": share["name"], "files_sample": share["files"][:5]})
        except Exception as e:
            findings.append({"severity": "info", "title": "Could not list shares",
                             "detail": str(e), "evidence": None})

        # Logged-in users — not always permitted; ignore failures
        try:
            users_resp = []
            # Impacket's hNetWkstaUserEnum isn't always available in newer versions;
            # we wrap in try/except to fail silently
            from impacket.dcerpc.v5 import transport, wkst
            stringbinding = f"ncacn_np:{target}[\\PIPE\\wkssvc]"
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_credentials(
                body.creds.username, body.creds.password,
                body.creds.domain, "",
                body.creds.nt_hash.lower() if body.creds.nt_hash else "",
            )
            rpctransport.setRemoteHost(target)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            for u in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
                users_resp.append({
                    "username": u["wkui1_username"][:-1].rstrip(),
                    "logon_domain": u["wkui1_logon_domain"][:-1].rstrip(),
                })
            dce.disconnect()
            logged_in = users_resp
        except Exception:
            logged_in = []

        return {
            "target":   target,
            "server":   {"name": server_name, "os": server_os,
                         "domain": domain_or_workgroup},
            "shares":   shares,
            "logged_in_users": logged_in,
            "findings": findings,
        }
    finally:
        try: conn.close()
        except Exception: pass
