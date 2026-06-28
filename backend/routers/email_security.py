"""Email security audit — SPF, DMARC, DKIM, MTA-STS, BIMI.

REST  GET /email/audit/{domain}?confirm=true

All checks are DNS-based (TXT records), same shape as DNS Recon. We probe a
shortlist of common DKIM selectors; if none hit, it doesn't mean DKIM isn't
configured — only that no common selector worked.
"""
from __future__ import annotations

import logging
import re
import secrets
import socket
import subprocess
import time
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from lib import hids_notify
from lib import scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.target_policy import require_target
from lib.validators import validate_domain

logger = logging.getLogger(__name__)

router = APIRouter(tags=["email-security"], dependencies=[Depends(require_local_auth)])

import shutil as _shutil
DIG = _shutil.which("dig")

DKIM_SELECTORS = (
    "default", "google", "k1", "k2", "selector1", "selector2",
    "dkim", "mail", "smtp", "s1", "s2", "mxvault",
    "amazonses", "fm1", "fm2", "fm3",  # FastMail
)


def _query_txt(name: str) -> list[str]:
    if not DIG:
        return []
    try:
        r = subprocess.run(
            [DIG, "+short", "+time=2", "+tries=1", name, "TXT"],
            capture_output=True, text=True, timeout=4.0,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    out = []
    for line in r.stdout.splitlines():
        # dig prints TXT records with surrounding quotes; multi-string TXT is
        # concatenated. Strip the outer quotes and join chunks.
        s = line.strip()
        if not s:
            continue
        # Join "..." "..." into one
        chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', s)
        joined = "".join(chunks) if chunks else s.strip('"')
        out.append(joined)
    return out


def _parse_spf(records: list[str]) -> dict[str, Any]:
    spf_record = next((r for r in records if r.lower().startswith("v=spf1")), "")
    if not spf_record:
        return {"present": False, "raw": "", "mechanisms": [], "all_qualifier": ""}
    parts = spf_record.split()
    mechanisms = parts[1:]
    # 'all' qualifier: -all, ~all, ?all, +all (or just 'all' = +all)
    all_qual = ""
    for mech in mechanisms:
        if mech.lower().endswith("all"):
            q = mech[0]
            all_qual = q if q in "+-~?" else "+"
            break
    return {
        "present": True,
        "raw": spf_record,
        "mechanisms": mechanisms,
        "all_qualifier": all_qual,
    }


def _parse_dmarc(records: list[str]) -> dict[str, Any]:
    dmarc_record = next((r for r in records if r.lower().startswith("v=dmarc1")), "")
    if not dmarc_record:
        return {"present": False, "raw": "", "tags": {}}
    tags: dict[str, str] = {}
    for tok in dmarc_record.split(";"):
        tok = tok.strip()
        if "=" in tok:
            k, _, v = tok.partition("=")
            tags[k.strip().lower()] = v.strip()
    return {"present": True, "raw": dmarc_record, "tags": tags}


def _parse_mta_sts(records: list[str]) -> dict[str, Any]:
    rec = next((r for r in records if r.lower().startswith("v=stsv1")), "")
    if not rec:
        return {"present": False, "raw": ""}
    tags: dict[str, str] = {}
    for tok in rec.split(";"):
        tok = tok.strip()
        if "=" in tok:
            k, _, v = tok.partition("=")
            tags[k.strip().lower()] = v.strip()
    return {"present": True, "raw": rec, "tags": tags}


def _parse_bimi(records: list[str]) -> dict[str, Any]:
    rec = next((r for r in records if r.lower().startswith("v=bimi1")), "")
    if not rec:
        return {"present": False, "raw": ""}
    tags: dict[str, str] = {}
    for tok in rec.split(";"):
        tok = tok.strip()
        if "=" in tok:
            k, _, v = tok.partition("=")
            tags[k.strip().lower()] = v.strip()
    return {"present": True, "raw": rec, "tags": tags}


def _find_dkim(domain: str) -> dict[str, Any]:
    """Probe common DKIM selectors. Returns {selectors_found, raw, wildcard}.

    First probes a random selector — if it returns a DKIM-shaped record, the
    domain has a wildcard at *._domainkey.{domain} and we cannot trust individual
    selector probes.
    """
    # Wildcard probe: a random selector should NOT exist
    canary = secrets.token_hex(8) + "no-such-selector"
    canary_records = _query_txt(f"{canary}._domainkey.{domain}")
    wildcard = bool(next(
        (r for r in canary_records if "v=DKIM1" in r or "k=rsa" in r), False))
    if wildcard:
        return {"selectors_found": [], "raw": {}, "wildcard": True,
                "wildcard_record": canary_records[0] if canary_records else ""}

    found: list[str] = []
    raw_per_sel: dict[str, str] = {}
    for sel in DKIM_SELECTORS:
        records = _query_txt(f"{sel}._domainkey.{domain}")
        # Require real keys, not just "v=DKIM1; p=" (revoked).
        dkim = next(
            (r for r in records
             if ("v=DKIM1" in r or "k=rsa" in r) and re.search(r"p=[A-Za-z0-9+/=]{20,}", r)),
            "",
        )
        if dkim:
            found.append(sel)
            raw_per_sel[sel] = dkim
    return {"selectors_found": found, "raw": raw_per_sel, "wildcard": False}


@router.get("/email/audit/{domain}")
async def email_audit(domain: str, request: Request,
                      confirm: bool = Query(default=False)) -> dict[str, Any]:
    # `validate_domain` strips whitespace, enforces length, rejects IP
    # literals (no dots-only labels), and requires at least one dot.
    domain = validate_domain(domain, field="domain")
    scope.enforce_rest(
        domain, get_engagement_id(request), get_mode(request), confirm=confirm,
    )

    if not DIG:
        raise MhpError(
            "`dig` not found on PATH — install BIND tools "
            "(`brew install bind` on macOS, `apt install dnsutils` on Debian/Ubuntu)",
            code=ErrorCode.TOOL_MISSING,
            status_code=503,
        )

    # Resolve check — bail early on NXDOMAIN so we don't emit spurious findings.
    try:
        socket.gethostbyname(domain)
        resolves = True
    except socket.gaierror:
        # Some domains (parked) only have NS / SOA but no A. Fall back to SOA check.
        try:
            r = subprocess.run([DIG, "+short", domain, "SOA"],
                               capture_output=True, text=True, timeout=3.0)
            resolves = bool(r.stdout.strip())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            resolves = False

    if not resolves:
        return {
            "domain": domain,
            "spf":     {"present": False, "raw": "", "mechanisms": [], "all_qualifier": ""},
            "dmarc":   {"present": False, "raw": "", "tags": {}},
            "mta_sts": {"present": False, "raw": ""},
            "bimi":    {"present": False, "raw": ""},
            "dkim":    {"selectors_found": [], "raw": {}, "wildcard": False},
            "findings": [{"severity": "warn", "label": "Domain does not exist",
                          "detail": "No A or SOA record returned"}],
            "elapsed_seconds": 0.0,
            "policy": {"verdict": verdict, "reason": reason},
        }

    t0 = time.monotonic()

    spf = _parse_spf(_query_txt(domain))
    dmarc = _parse_dmarc(_query_txt(f"_dmarc.{domain}"))
    mta_sts = _parse_mta_sts(_query_txt(f"_mta-sts.{domain}"))
    bimi = _parse_bimi(_query_txt(f"default._bimi.{domain}"))
    dkim = _find_dkim(domain)

    # ── Findings ────────────────────────────────────────────────────────────
    findings: list[dict[str, Any]] = []

    if not spf["present"]:
        findings.append({"severity": "high", "label": "No SPF record",
                         "detail": "Domain has no v=spf1 record"})
    else:
        q = spf["all_qualifier"]
        if q == "+":
            findings.append({"severity": "high", "label": "SPF +all (permissive)",
                             "detail": "SPF allows anyone to send — equivalent to no SPF"})
        elif q == "?":
            findings.append({"severity": "warn", "label": "SPF ?all (neutral)",
                             "detail": "No policy declared for unauthorised senders"})
        elif q == "~":
            findings.append({"severity": "info", "label": "SPF ~all (soft fail)",
                             "detail": "Consider tightening to -all"})
        elif q == "":
            findings.append({"severity": "warn", "label": "SPF has no 'all' mechanism",
                             "detail": "Default action on unmatched senders is undefined"})

    if not dmarc["present"]:
        findings.append({"severity": "high", "label": "No DMARC record",
                         "detail": "_dmarc subdomain has no v=DMARC1 record"})
    else:
        tags = dmarc["tags"]
        p = tags.get("p", "").lower()
        if p == "none":
            findings.append({"severity": "warn", "label": "DMARC p=none (monitoring only)",
                             "detail": "Policy doesn't reject or quarantine — only collects reports"})
        elif p == "":
            findings.append({"severity": "warn", "label": "DMARC missing 'p' tag",
                             "detail": "Required policy tag absent"})
        pct = tags.get("pct", "100")
        try:
            if int(pct) < 100:
                findings.append({"severity": "info", "label": f"DMARC pct={pct}",
                                 "detail": "Policy only applied to a sample"})
        except ValueError:
            pass
        if "rua" not in tags:
            findings.append({"severity": "info", "label": "DMARC no rua (aggregate reports)",
                             "detail": "Aggregate failure reports disabled"})
        if "sp" in tags and tags["sp"].lower() == "none":
            findings.append({"severity": "warn", "label": "DMARC sp=none (subdomain policy)",
                             "detail": "Subdomains have no DMARC enforcement"})

    if not mta_sts["present"]:
        findings.append({"severity": "info", "label": "No MTA-STS record",
                         "detail": "TLS enforcement policy not declared"})

    if dkim.get("wildcard"):
        findings.append({"severity": "info", "label": "Wildcard *._domainkey DNS",
                         "detail": "Domain returns DKIM-shaped records for any selector — "
                                   "individual selector probing is meaningless. "
                                   "Often used to declare 'this domain doesn't sign mail'."})
    elif not dkim["selectors_found"]:
        findings.append({"severity": "info", "label": "No DKIM selectors found",
                         "detail": f"Probed common selectors: {', '.join(DKIM_SELECTORS[:6])}…"})

    elapsed = round(time.monotonic() - t0, 2)

    # ── HIDS emit ────────────────────────────────────────────────────────────
    high_count = sum(1 for f in findings if f["severity"] == "high")
    sev = "warning" if high_count else "info"
    await hids_notify.notify(
        sev, "email-security",
        f"Email audit — {domain} ({high_count} high)",
        {"domain": domain, "high_findings": high_count,
         "spf_present": spf["present"], "dmarc_present": dmarc["present"],
         "dkim_selectors": dkim["selectors_found"]},
    )

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "mta_sts": mta_sts,
        "bimi": bimi,
        "dkim": dkim,
        "findings": findings,
        "elapsed_seconds": elapsed,
        "policy": {"verdict": verdict, "reason": reason},
    }
