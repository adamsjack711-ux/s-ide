"""WHOIS / ASN lookup.

REST  GET /whois/{target}
      target may be an IP, CIDR, or domain. Returns:
        - target / target_type
        - resolved_ip
        - asn: { number, name, country, registry, prefix, allocated }
        - domain: { registrar, registrant, created, updated, expires,
                    nameservers, status } (only when target is a domain)
        - network: { netrange, cidr, org, country } (only for IPs)
        - findings: list of {severity, label, detail}
        - policy: { verdict, reason }   ← informational; does NOT block here
        - raw: truncated whois output for debugging

Policy is applied in "passive" mode: warn surfaces a hint to the UI but
doesn't 409. Only deny blocks.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request

from lib import hids_notify, scope
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import get_engagement_id, get_mode
from lib.target_policy import check_target
from lib.validators import MAX_TARGET_LEN, validate_hostname

logger = logging.getLogger(__name__)

router = APIRouter(tags=["whois"], dependencies=[Depends(require_local_auth)])


def _validate_whois_target(target: str) -> str:
    """Validate a whois lookup target: IP, CIDR, or hostname/domain.

    The whois endpoint is more permissive than the rest of the validators
    because CIDR notation is a legitimate input shape. Returns the
    stripped value on success.
    """
    s = (target or "").strip()
    if not s:
        raise MhpError("target is required", code=ErrorCode.INVALID_TARGET)
    if len(s) > MAX_TARGET_LEN:
        raise MhpError(
            f"target is too long (max {MAX_TARGET_LEN} chars)",
            code=ErrorCode.INVALID_TARGET,
        )
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False)
            return s
        except ValueError:
            raise MhpError(
                "target is not a valid CIDR block",
                code=ErrorCode.INVALID_TARGET,
            ) from None
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    # Fall through to hostname/domain validation.
    return validate_hostname(s, field="target")

import shutil as _shutil
WHOIS = _shutil.which("whois") or "/usr/bin/whois"
DIG   = _shutil.which("dig")   or "/usr/bin/dig"


def _classify(target: str) -> tuple[str, str | None]:
    """Return (type, resolved_ip).

    type ∈ {'ip', 'cidr', 'domain'}.
    """
    s = target.strip()
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False)
            return "cidr", s.split("/")[0]
        except ValueError:
            pass
    try:
        ipaddress.ip_address(s)
        return "ip", s
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(s)
        return "domain", ip
    except socket.gaierror:
        return "domain", None


def _run(cmd: list[str], timeout: float = 10.0) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _parse_whois(text: str) -> dict[str, list[str]]:
    """Whois has wildly varying formats. Collect Key: Value pairs case-insensitively."""
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("%", "#", ">>>")):
            continue
        m = re.match(r"\s*([A-Za-z][A-Za-z0-9\-_ ]{0,40})\s*:\s+(.+?)\s*$", line)
        if not m:
            continue
        k = m.group(1).strip().lower()
        v = m.group(2).strip()
        fields.setdefault(k, []).append(v)
    return fields


def _first(fields: dict[str, list[str]], *keys: str) -> str:
    for k in keys:
        if k in fields and fields[k]:
            return fields[k][0]
    return ""


def _all(fields: dict[str, list[str]], *keys: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for k in keys:
        for v in fields.get(k, []):
            if v.lower() not in seen:
                seen.add(v.lower())
                out.append(v)
    return out


def _parse_date(s: str) -> datetime | None:
    if not s:
        return None
    s = s.strip().split(" ")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y", "%Y%m%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _cymru_origin(ip: str) -> dict[str, Any]:
    """Reverse-IP lookup against Cymru — gives the announcing ASN and prefix."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.version == 4:
        reversed_octets = ".".join(reversed(ip.split(".")))
        host = f"{reversed_octets}.origin.asn.cymru.com"
    else:
        # IPv6 reverse: full nibble form
        expanded = addr.exploded.replace(":", "")
        host = ".".join(reversed(expanded)) + ".origin6.asn.cymru.com"

    out = _run([DIG, "+short", "+time=2", "+tries=1", host, "TXT"])
    line = out.strip().strip('"').strip()
    if not line:
        return {}
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 5:
        return {}
    return {
        "number": parts[0].split(" ")[0],   # may contain multiple if multi-origin
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated": parts[4],
    }


def _cymru_asn(asn_number: str) -> dict[str, Any]:
    """Look up the ASN's human name via Cymru."""
    if not asn_number:
        return {}
    out = _run([DIG, "+short", "+time=2", "+tries=1",
                f"AS{asn_number}.asn.cymru.com", "TXT"])
    line = out.strip().strip('"').strip()
    if not line:
        return {}
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 5:
        return {}
    return {"name": parts[4]}


HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "gcp", "microsoft", "azure", "digitalocean",
    "linode", "ovh", "hetzner", "vultr", "scaleway", "akamai", "cloudflare",
    "fastly", "alibaba", "tencent", "oracle", "ibm cloud", "rackspace",
)


@router.get("/whois/{target:path}")
async def whois_lookup(target: str, request: Request) -> dict[str, Any]:
    target = _validate_whois_target(target)

    # Passive lookup — `warn` is informational only and surfaced in response.
    verdict, reason, _ = scope.enforce_rest(
        target, get_engagement_id(request), get_mode(request), deny_only=True,
    )

    ttype, resolved_ip = _classify(target)

    raw_whois = _run([WHOIS, target], timeout=12.0)
    fields = _parse_whois(raw_whois)

    domain_info: dict[str, Any] = {}
    network_info: dict[str, Any] = {}

    if ttype == "domain":
        created = _first(fields, "creation date", "created", "created on", "registered on")
        updated = _first(fields, "updated date", "last updated", "changed", "last modified")
        expires = _first(fields, "registry expiry date", "registrar registration expiration date",
                         "expiration date", "expires on", "expires", "expiry date", "paid-till")
        domain_info = {
            "registrar":   _first(fields, "registrar"),
            "registrant":  _first(fields, "registrant organization", "registrant name", "registrant",
                                  "org", "organisation"),
            "created":     created,
            "updated":     updated,
            "expires":     expires,
            "nameservers": _all(fields, "name server", "nserver"),
            "status":      _all(fields, "domain status", "status"),
        }

    if ttype in ("ip", "cidr"):
        network_info = {
            "netrange": _first(fields, "netrange", "inetnum", "inet6num", "cidr"),
            "cidr":     _first(fields, "cidr", "route"),
            "org":      _first(fields, "orgname", "org-name", "owner", "organization",
                               "netname"),
            "country":  _first(fields, "country"),
        }

    # ASN — always try if we have an IP
    asn: dict[str, Any] = {}
    if resolved_ip:
        asn = _cymru_origin(resolved_ip)
        if asn.get("number"):
            asn_first = asn["number"].split(" ")[0]
            name_lookup = _cymru_asn(asn_first)
            if name_lookup:
                asn["name"] = name_lookup.get("name", "")

    # ── Findings ─────────────────────────────────────────────────────────────
    findings: list[dict[str, Any]] = []

    # Detect a "this name doesn't exist" response so we suppress noisy findings
    raw_lower = raw_whois.lower()
    nxdomain_signals = (
        "no match for", "not found", "no entries found", "no data found",
        "invalid query", "object does not exist", "domain not found",
    )
    nxdomain = (ttype == "domain" and resolved_ip is None and any(s in raw_lower for s in nxdomain_signals))

    if not raw_whois.strip():
        findings.append({"severity": "warn", "label": "WHOIS empty",
                         "detail": "whois returned no data (rate-limited or unsupported TLD)"})

    if nxdomain:
        findings.append({"severity": "info", "label": "Domain does not exist",
                         "detail": "WHOIS returned a not-found response"})
    elif ttype == "domain":
        exp = _parse_date(domain_info.get("expires", ""))
        if exp:
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append({"severity": "high", "label": "Domain expired",
                                 "detail": f"expired {-days} day(s) ago"})
            elif days < 30:
                findings.append({"severity": "warn", "label": "Domain expiring soon",
                                 "detail": f"{days} day(s) remaining"})
        if not domain_info.get("registrar") and resolved_ip:
            findings.append({"severity": "info", "label": "No registrar field",
                             "detail": "WHOIS did not include a registrar — uncommon"})

    asn_name = asn.get("name", "").lower()
    hosting = next((k for k in HOSTING_KEYWORDS if k in asn_name), None)
    if hosting:
        findings.append({"severity": "info", "label": "Hosted infrastructure",
                         "detail": f"ASN belongs to {hosting}"})

    response = {
        "target": target,
        "target_type": ttype,
        "resolved_ip": resolved_ip,
        "asn": asn,
        "domain": domain_info,
        "network": network_info,
        "findings": findings,
        "policy": {"verdict": verdict, "reason": reason},
        "raw": raw_whois[:4000],
    }

    # Push a quiet info event so it shows up in the HIDS feed alongside scans
    await hids_notify.notify(
        "info", "whois",
        f"WHOIS lookup — {target}{(' · AS' + asn['number']) if asn.get('number') else ''}",
        {"target": target, "type": ttype, "asn": asn.get("number", ""),
         "asn_name": asn.get("name", ""), "findings": len(findings)},
    )
    return response
