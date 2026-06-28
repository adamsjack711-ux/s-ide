"""LDAP Enumerator — pull users / groups / DCs / policy / GPOs from AD via ldap3.

Categories the user can request:

  - **users**     — all user accounts + UAC-decoded flags + pwdLastSet
  - **groups**    — all groups + member counts
  - **dcs**       — domain controllers (objectClass=computer & primary group 516)
  - **policy**    — default domain password policy (lockoutThreshold, etc.)
  - **gpos**      — Group Policy Objects
  - **computers** — all computer accounts
  - **spns**      — accounts with serviceprincipalname set (kerberoastable hint)
  - **admins**    — Domain Admins / Enterprise Admins / Schema Admins members

Findings surfaced for the user (severity/title/detail/evidence):
  - High: account with PASSWD_NOTREQD set
  - High: account with DONT_REQUIRE_PREAUTH set (AS-REP roastable)
  - Medium: account with old pwdLastSet (> 1 year)
  - Info: every Domain Admin
"""
from __future__ import annotations

import datetime
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from lib import scope
from lib.ad_auth import (
    CredsModel, decode_uac, domain_to_base_dn, open_ldap,
    UAC_DONT_REQUIRE_PREAUTH, UAC_PASSWD_NOTREQD,
)
from lib.errors import ErrorCode, MhpError
from lib.mode import get_mode
from lib.validators import validate_domain, validate_hostname

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ldap", tags=["ldap-enum"])

CATEGORIES = ["users", "groups", "dcs", "policy", "gpos",
              "computers", "spns", "admins"]


class EnumBody(BaseModel):
    creds:         CredsModel
    categories:    list[str] = Field(default_factory=lambda: list(CATEGORIES))
    confirm:       bool = False
    engagement_id: str | None = None


def _add_finding(out: list[dict[str, Any]], severity: str, title: str,
                 detail: str, evidence: Any = None) -> None:
    out.append({"severity": severity, "title": title,
                "detail": detail, "evidence": evidence})


def _ldap_to_iso(t: Any) -> str | None:
    """ldap3 returns datetimes natively for most attributes."""
    if t is None:
        return None
    if isinstance(t, datetime.datetime):
        return t.replace(tzinfo=datetime.timezone.utc).isoformat()
    return str(t)


def _users(conn, base_dn: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user))",
        attributes=["sAMAccountName", "displayName", "userAccountControl",
                    "pwdLastSet", "lastLogon", "memberOf",
                    "servicePrincipalName"],
        paged_size=200,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    out: list[dict[str, Any]] = []
    for entry in conn.entries:
        try:
            uac = int(entry.userAccountControl.value or 0)
        except Exception:
            uac = 0
        pwd_last = entry.pwdLastSet.value if "pwdLastSet" in entry else None
        flags = decode_uac(uac)
        sam = str(entry.sAMAccountName.value)
        row = {
            "sam": sam,
            "display": str(entry.displayName.value or "") if "displayName" in entry else "",
            "uac": uac,
            "flags": flags,
            "pwd_last_set": _ldap_to_iso(pwd_last),
            "spns": list(entry.servicePrincipalName.values) if "servicePrincipalName" in entry else [],
            "groups_count": len(entry.memberOf.values) if "memberOf" in entry else 0,
        }
        if uac & UAC_PASSWD_NOTREQD:
            _add_finding(findings, "high",
                         f"User {sam!r}: PASSWD_NOTREQD",
                         f"UserAccountControl on {sam!r} has PASSWD_NOTREQD set — "
                         "account may have an empty password.",
                         evidence={"sam": sam, "uac": uac, "flags": flags})
        if uac & UAC_DONT_REQUIRE_PREAUTH:
            _add_finding(findings, "high",
                         f"User {sam!r}: DONT_REQUIRE_PREAUTH (AS-REP roastable)",
                         f"{sam!r} has Kerberos pre-auth disabled — request an AS-REP "
                         "and crack the encrypted timestamp offline.",
                         evidence={"sam": sam, "flags": flags})
        if row["spns"]:
            _add_finding(findings, "medium",
                         f"User {sam!r}: has SPNs (Kerberoastable)",
                         f"{sam!r} has {len(row['spns'])} SPN(s) — request the TGS and "
                         "crack the ticket offline.",
                         evidence={"sam": sam, "spns": row["spns"]})
        if isinstance(pwd_last, datetime.datetime):
            age = (now - pwd_last.replace(tzinfo=datetime.timezone.utc)).days
            if age > 365:
                _add_finding(findings, "medium",
                             f"User {sam!r}: password >1 year old",
                             f"Password last set {age} days ago.",
                             evidence={"sam": sam, "days": age})
        out.append(row)
    return out


def _groups(conn, base_dn: str) -> list[dict[str, Any]]:
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=group)",
        attributes=["sAMAccountName", "member", "description"],
        paged_size=200,
    )
    out: list[dict[str, Any]] = []
    for entry in conn.entries:
        out.append({
            "sam": str(entry.sAMAccountName.value),
            "description": str(entry.description.value or "") if "description" in entry else "",
            "member_count": len(entry.member.values) if "member" in entry else 0,
        })
    return out


def _dcs(conn, base_dn: str) -> list[dict[str, Any]]:
    # primaryGroupID 516 = Domain Controllers
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=computer)(primaryGroupID=516))",
        attributes=["sAMAccountName", "dNSHostName", "operatingSystem",
                    "operatingSystemVersion"],
    )
    out: list[dict[str, Any]] = []
    for entry in conn.entries:
        out.append({
            "sam": str(entry.sAMAccountName.value),
            "dns": str(entry.dNSHostName.value) if "dNSHostName" in entry else "",
            "os": str(entry.operatingSystem.value) if "operatingSystem" in entry else "",
            "os_version": str(entry.operatingSystemVersion.value) if "operatingSystemVersion" in entry else "",
        })
    return out


def _policy(conn, base_dn: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=domainDNS)",
        attributes=["lockoutThreshold", "lockoutDuration",
                    "lockoutObservationWindow", "minPwdLength",
                    "minPwdAge", "maxPwdAge", "pwdHistoryLength",
                    "pwdProperties"],
    )
    out: dict[str, Any] = {}
    if conn.entries:
        entry = conn.entries[0]
        out = {
            "lockout_threshold":          int(entry.lockoutThreshold.value or 0) if "lockoutThreshold" in entry else None,
            "min_password_length":        int(entry.minPwdLength.value or 0) if "minPwdLength" in entry else None,
            "password_history_length":    int(entry.pwdHistoryLength.value or 0) if "pwdHistoryLength" in entry else None,
        }
        if out["lockout_threshold"] == 0:
            _add_finding(findings, "high",
                         "Domain lockout threshold is 0 (no lockout)",
                         "lockoutThreshold = 0 means accounts never lock. Password "
                         "spraying is unbounded.",
                         evidence=out)
        elif out["lockout_threshold"] and out["lockout_threshold"] < 5:
            _add_finding(findings, "info",
                         f"Domain lockout threshold: {out['lockout_threshold']}",
                         "Low threshold — be careful with sprayers.",
                         evidence=out)
        if out["min_password_length"] and out["min_password_length"] < 12:
            _add_finding(findings, "medium",
                         f"Min password length: {out['min_password_length']}",
                         "Less than 12 — short passwords are crackable.",
                         evidence=out)
    return out


def _gpos(conn, base_dn: str) -> list[dict[str, Any]]:
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=groupPolicyContainer)",
        attributes=["displayName", "name", "gPCFileSysPath"],
    )
    return [
        {"display": str(e.displayName.value or "") if "displayName" in e else "",
         "name":    str(e.name.value or ""),
         "path":    str(e.gPCFileSysPath.value or "") if "gPCFileSysPath" in e else ""}
        for e in conn.entries
    ]


def _computers(conn, base_dn: str) -> list[dict[str, Any]]:
    conn.search(
        search_base=base_dn,
        search_filter="(objectCategory=computer)",
        attributes=["sAMAccountName", "dNSHostName", "operatingSystem"],
        paged_size=200,
    )
    return [
        {"sam": str(e.sAMAccountName.value),
         "dns": str(e.dNSHostName.value) if "dNSHostName" in e else "",
         "os":  str(e.operatingSystem.value) if "operatingSystem" in e else ""}
        for e in conn.entries
    ]


def _spns(conn, base_dn: str) -> list[dict[str, Any]]:
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(servicePrincipalName=*))",
        attributes=["sAMAccountName", "servicePrincipalName"],
    )
    return [
        {"sam":  str(e.sAMAccountName.value),
         "spns": list(e.servicePrincipalName.values)}
        for e in conn.entries
    ]


def _admins(conn, base_dn: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for group_name in ("Domain Admins", "Enterprise Admins", "Schema Admins"):
        conn.search(
            search_base=base_dn,
            search_filter=f"(sAMAccountName={group_name})",
            attributes=["member"],
        )
        if conn.entries:
            members = list(conn.entries[0].member.values) if "member" in conn.entries[0] else []
            out.append({"group": group_name, "members": members,
                        "count": len(members)})
            if members:
                _add_finding(findings, "info",
                             f"{group_name}: {len(members)} member(s)",
                             "Members of this group can fully compromise the domain.",
                             evidence={"group": group_name, "members": members})
    return out


@router.post("/enum")
def enum(body: EnumBody, request: Request) -> dict[str, Any]:
    body.creds.dc_host = validate_hostname(body.creds.dc_host, field="dc_host")
    if body.creds.domain:
        body.creds.domain = validate_domain(body.creds.domain, field="domain")
    scope.enforce_rest(
        body.creds.domain or body.creds.dc_host,
        body.engagement_id, get_mode(request),
        confirm=body.confirm,
    )
    try:
        conn = open_ldap(body.creds)
    except Exception:
        logger.exception("ldap_enum LDAP bind failed")
        raise MhpError(
            "LDAP bind failed",
            code=ErrorCode.UNAUTHORIZED,
            status_code=401,
        ) from None
    try:
        base_dn = domain_to_base_dn(body.creds.domain)
        if not base_dn:
            raise HTTPException(400, "domain is required (e.g. corp.local)")
        out: dict[str, Any] = {
            "domain": body.creds.domain, "base_dn": base_dn,
            "categories": {}, "findings": [],
        }
        runners = {
            "users":     lambda: {"users":     _users(conn, base_dn, out["findings"])},
            "groups":    lambda: {"groups":    _groups(conn, base_dn)},
            "dcs":       lambda: {"dcs":       _dcs(conn, base_dn)},
            "policy":    lambda: {"policy":    _policy(conn, base_dn, out["findings"])},
            "gpos":      lambda: {"gpos":      _gpos(conn, base_dn)},
            "computers": lambda: {"computers": _computers(conn, base_dn)},
            "spns":      lambda: {"spns":      _spns(conn, base_dn)},
            "admins":    lambda: {"admins":    _admins(conn, base_dn, out["findings"])},
        }
        for cat in body.categories:
            if cat not in runners:
                continue
            try:
                out["categories"][cat] = runners[cat]()
            except Exception as e:
                out["categories"][cat] = {"error": str(e)}
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        out["findings"].sort(key=lambda f: order.get(f["severity"], 99))
        return out
    finally:
        try: conn.unbind()
        except Exception: pass
