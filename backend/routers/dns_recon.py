"""DNS Recon — record dump + subdomain enumeration.

REST  GET  /dns/recon/{domain}?confirm=true
      Returns a one-shot report: A/AAAA/MX/NS/TXT/CAA/SOA records, reverse
      DNS for resolved IPs, DNSSEC presence, zone-transfer attempt against
      every authoritative NS.

WS    /ws/dns-recon
      Streaming subdomain enumeration.
        client -> server: {"domain": "example.com", "wordlist": "small"|"medium",
                           "confirm": false}
        server -> client:
          {"type":"started",   "domain", "ns": [...], "wordlist_size": N}
          {"type":"hit",       "subdomain", "ip"}
          {"type":"progress",  "done", "total", "found"}
          {"type":"done",      "elapsed", "found", "stopped"}
          {"type":"error",     "detail"}
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import subprocess
import time
from typing import Any

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from lib import hids_notify
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError, ws_error
from lib import scope
from lib.mode import get_mode
from lib.target_policy import check_target, require_target
from lib.validators import validate_domain


def _reject_if_ip(domain: str, *, field: str = "domain") -> None:
    """Reject IP-shaped input on DNS recon endpoints.

    `validate_domain` accepts all-numeric labels like "127.0.0.1" because
    they technically satisfy the hostname grammar, but DNS recon on a bare
    IP is meaningless and produces a confusingly empty result. Detect
    IPv4/IPv6 literals here and reject with INVALID_DOMAIN so the caller
    sees the same error envelope shape as the localhost rejection.
    """
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return
    raise MhpError(
        f"{field} is an IP address — use /whois/<ip> for IP intel",
        code=ErrorCode.INVALID_DOMAIN,
    )

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dns-recon"], dependencies=[Depends(require_local_auth)])

import shutil as _shutil
DIG = _shutil.which("dig") or "/usr/bin/dig"

# Short, opinionated subdomain wordlist. Kept inline so we don't have to ship
# an asset file alongside the PyInstaller bundle.
_WORDLIST_SMALL = [
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "webmail", "ns1", "ns2",
    "ns3", "dns", "dns1", "dns2", "vpn", "remote", "ssh", "secure", "test", "dev",
    "staging", "stage", "qa", "uat", "preprod", "prod", "api", "api1", "api2",
    "app", "apps", "admin", "portal", "intranet", "internal", "corp", "office",
    "blog", "shop", "store", "static", "cdn", "media", "img", "images", "assets",
    "files", "download", "downloads", "upload", "uploads", "git", "gitlab",
    "github", "jenkins", "ci", "build", "jira", "confluence", "wiki", "docs",
    "support", "help", "kb", "status", "metrics", "monitor", "monitoring",
    "grafana", "prometheus", "kibana", "elastic", "search", "auth", "sso", "ldap",
    "ad", "dc", "exchange", "owa", "outlook", "lync", "skype", "teams", "zoom",
    "voip", "pbx", "sip", "fax", "print", "printer", "scan", "router", "firewall",
    "fw", "gw", "gateway", "proxy", "lb", "edge", "ingress", "egress", "dmz",
    "old", "legacy", "new", "v1", "v2", "v3", "beta", "alpha", "demo", "sandbox",
]

_WORDLIST_MEDIUM = _WORDLIST_SMALL + [
    "m", "mobile", "wap", "wifi", "guest", "captive", "hotspot", "voice", "video",
    "stream", "live", "broadcast", "tv", "radio", "podcast", "feed", "rss",
    "newsletter", "list", "subscribe", "marketing", "campaign", "promo",
    "events", "calendar", "schedule", "booking", "reservation", "billing",
    "invoice", "payment", "pay", "checkout", "cart", "order", "orders",
    "customer", "customers", "client", "clients", "partner", "partners",
    "vendor", "vendors", "supplier", "suppliers", "hr", "people", "employee",
    "employees", "training", "learning", "academy", "library", "archive",
    "backup", "backups", "restore", "snapshot", "snap", "tape", "vault",
    "log", "logs", "logging", "audit", "audits", "report", "reports",
    "analytics", "stats", "insights", "data", "etl", "warehouse", "lake",
    "spark", "hadoop", "kafka", "rabbit", "redis", "memcache", "memcached",
    "mongo", "mongodb", "postgres", "psql", "pg", "mysql", "mariadb", "oracle",
    "mssql", "sqlserver", "cassandra", "couch", "couchdb", "influx", "influxdb",
    "graphite", "statsd", "consul", "etcd", "vault", "nomad", "k8s",
    "kubernetes", "rancher", "swarm", "docker", "containers", "registry",
    "harbor", "nexus", "artifactory", "npm", "pypi", "rubygems", "maven",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_dig(args: list[str], timeout: float = 4.0) -> tuple[int, str, str]:
    try:
        r = subprocess.run([DIG] + args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "dig not found"
    except subprocess.TimeoutExpired:
        return 124, "", "dig timed out"


def _query(domain: str, rtype: str, server: str | None = None) -> list[str]:
    args = ["+short", "+time=2", "+tries=1", domain, rtype]
    if server:
        args = ["@" + server] + args
    rc, out, _ = _run_dig(args)
    if rc != 0:
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def _reverse(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def _try_axfr(domain: str, ns: str) -> tuple[bool, int, str]:
    """Attempt a zone transfer. Returns (succeeded, record_count, sample)."""
    rc, out, err = _run_dig(["@" + ns, domain, "AXFR", "+time=3"], timeout=5.0)
    if rc != 0:
        return False, 0, err.strip()
    if "Transfer failed" in out or "connection refused" in out.lower():
        return False, 0, "refused"
    lines = [ln for ln in out.splitlines() if ln and not ln.startswith(";")]
    if len(lines) < 3:
        return False, 0, "empty"
    return True, len(lines), "\n".join(lines[:5])


# ── REST: one-shot recon ──────────────────────────────────────────────────────

@router.get("/dns/recon/{domain}")
async def dns_recon(domain: str, confirm: bool = Query(default=False)) -> dict[str, Any]:
    _reject_if_ip(domain.strip().rstrip("."))
    domain = validate_domain(domain)
    require_target(domain, confirm=confirm)

    a = _query(domain, "A")
    aaaa = _query(domain, "AAAA")
    mx = _query(domain, "MX")
    ns = _query(domain, "NS")
    txt = _query(domain, "TXT")
    caa = _query(domain, "CAA")
    soa = _query(domain, "SOA")

    # DNSSEC
    dnskey = _query(domain, "DNSKEY")
    ds = _query(domain, "DS")

    # Reverse for A records
    reverses = [{"ip": ip, "ptr": _reverse(ip)} for ip in a[:10]]

    # AXFR against each NS (concurrent would be nice but fine sequential at ~4)
    axfr_results = []
    for ns_record in ns[:8]:
        ns_host = ns_record.rstrip(".")
        ok, count, sample = _try_axfr(domain, ns_host)
        axfr_results.append({
            "ns": ns_host,
            "succeeded": ok,
            "record_count": count,
            "sample": sample if ok else "",
        })
        if ok:
            # This is a huge finding — push to HIDS as critical
            await hids_notify.notify(
                "critical", "dns-recon",
                f"DNS zone transfer succeeded — {domain} via {ns_host}",
                {"domain": domain, "ns": ns_host, "record_count": count},
            )

    findings: list[dict[str, Any]] = []
    domain_resolves = bool(a or aaaa or ns or soa)
    if not domain_resolves:
        findings.append({"severity": "warn",
                         "label": "Domain does not exist",
                         "detail": "No A/AAAA/NS/SOA records returned"})
    else:
        if not dnskey:
            findings.append({"severity": "info",
                             "label": "DNSSEC not signed",
                             "detail": "No DNSKEY records returned"})
        if any(r["succeeded"] for r in axfr_results):
            findings.append({"severity": "high",
                             "label": "Zone transfer allowed",
                             "detail": "AXFR succeeded against at least one NS"})
        if not caa:
            findings.append({"severity": "info",
                             "label": "No CAA records",
                             "detail": "Any CA can issue certs for this domain"})

    return {
        "domain": domain,
        "records": {
            "A": a, "AAAA": aaaa, "MX": mx, "NS": ns,
            "TXT": txt, "CAA": caa, "SOA": soa,
        },
        "reverse_dns": reverses,
        "dnssec": {
            "signed": bool(dnskey),
            "dnskey_count": len(dnskey),
            "ds_count": len(ds),
        },
        "zone_transfer": axfr_results,
        "findings": findings,
    }


@router.get("/dns/policy/{target}")
async def dns_policy_check(target: str) -> dict[str, Any]:
    """Pre-flight policy check the UI can use to decide whether to prompt."""
    verdict, reason = check_target(target)
    return {"target": target, "verdict": verdict, "reason": reason}


# ── WS: subdomain enumeration ─────────────────────────────────────────────────

@router.websocket("/ws/dns-recon")
async def dns_recon_ws(ws: WebSocket) -> None:
    await ws.accept()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    async def listen_for_stop() -> None:
        try:
            while True:
                msg = await ws.receive_json()
                if isinstance(msg, dict) and msg.get("action") == "stop":
                    stop.set(); return
        except WebSocketDisconnect:
            stop.set()
        except Exception:
            stop.set()

    try:
        init = await ws.receive_json()
        raw_domain = str(init.get("domain", "")).strip().lower()
        wordlist_key = str(init.get("wordlist", "small"))
        confirm = bool(init.get("confirm", False))
        engagement_id = init.get("engagement_id") or None
        init_mode = str(init.get("mode", "")).strip().lower()
        mode = "engagement" if init_mode == "engagement" else (
            "lab" if init_mode == "lab" else get_mode(ws)
        )

        try:
            _reject_if_ip(raw_domain.rstrip("."))
            domain = validate_domain(raw_domain, field="domain")
        except Exception as exc:
            await ws.send_json(ws_error(
                ErrorCode.INVALID_DOMAIN,
                getattr(exc, "message", str(exc)) or "domain is required",
            ))
            await ws.close(); return

        if not await scope.enforce_ws(ws, domain, engagement_id, mode, confirm=confirm):
            return

        wordlist = _WORDLIST_MEDIUM if wordlist_key == "medium" else _WORDLIST_SMALL

        listener = asyncio.create_task(listen_for_stop())
        try:
            ns_records = _query(domain, "NS")
            await ws.send_json({
                "type": "started",
                "domain": domain,
                "ns": [n.rstrip(".") for n in ns_records],
                "wordlist_size": len(wordlist),
            })

            t0 = time.monotonic()
            found = 0
            done = 0

            # Resolve each candidate via getaddrinfo on a small thread pool.
            # Keep it lightweight: 16 workers, async dispatched via to_thread.
            sem = asyncio.Semaphore(16)

            async def probe(sub: str) -> None:
                nonlocal done, found
                if stop.is_set():
                    return
                fqdn = f"{sub}.{domain}"
                async with sem:
                    if stop.is_set():
                        return
                    try:
                        ips = await asyncio.to_thread(_resolve_a, fqdn)
                    except Exception:
                        ips = []
                done += 1
                if ips:
                    found += 1
                    await ws.send_json({"type": "hit", "subdomain": fqdn, "ip": ips[0]})
                if done % 8 == 0 or done == len(wordlist):
                    await ws.send_json({"type": "progress",
                                        "done": done,
                                        "total": len(wordlist),
                                        "found": found})

            tasks = [asyncio.create_task(probe(w)) for w in wordlist]
            await asyncio.gather(*tasks, return_exceptions=True)

            elapsed = round(time.monotonic() - t0, 2)
            await ws.send_json({
                "type": "done",
                "elapsed": elapsed,
                "found": found,
                "stopped": stop.is_set(),
            })
            if not stop.is_set():
                await hids_notify.notify(
                    "info", "dns-recon",
                    f"Subdomain enum done — {found} hits on {domain}",
                    {"domain": domain, "found": found,
                     "tried": len(wordlist), "elapsed_seconds": elapsed},
                )
        finally:
            listener.cancel()
    except WebSocketDisconnect:
        stop.set()
    except Exception:
        logger.exception("dns_recon_ws unhandled exception")
        try:
            await ws.send_json(ws_error(
                ErrorCode.INTERNAL,
                "internal error during subdomain enumeration",
            ))
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass


def _resolve_a(fqdn: str) -> list[str]:
    """getaddrinfo-based resolver — fast and matches OS resolver caching."""
    try:
        infos = socket.getaddrinfo(fqdn, None, family=socket.AF_INET)
        return list(dict.fromkeys(i[4][0] for i in infos))
    except socket.gaierror:
        return []
