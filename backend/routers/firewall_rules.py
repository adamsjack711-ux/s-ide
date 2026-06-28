"""Firewall rule viewer (Linux-only).

  GET /firewall/rules

Reads the active rule set, preferring nftables (modern) and falling back to
iptables-save (legacy). Returns chains + rules in a structured shape the
frontend can render.

Reading rules generally requires CAP_NET_ADMIN — i.e. root. We try the
unprivileged binaries first; if they error with a permissions message we
surface a clear hint in the response (`needs_root: true`) rather than 500.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from lib import scope
from lib.auth import require_local_auth
from lib.mode import get_engagement_id, get_mode

router = APIRouter(tags=["firewall"], dependencies=[Depends(require_local_auth)])

IS_LINUX = sys.platform.startswith("linux")


def _require_linux() -> None:
    if not IS_LINUX:
        raise HTTPException(501, "firewall rules viewer is Linux-only")


def _run(cmd: list[str], timeout: int = 8) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        # Fake a CompletedProcess so callers can branch without try/except
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


# ── nftables parser ──────────────────────────────────────────────────────────

def _parse_nft(text: str) -> list[dict[str, Any]]:
    """Parse `nft list ruleset` output into [{table, family, chains: [{name,
    type, hook, priority, rules: [str]}]}, …].

    nft syntax is structured:
        table inet filter {
            chain input {
                type filter hook input priority filter; policy drop;
                iif "lo" accept
                ct state established,related accept
                tcp dport 22 accept
            }
            chain forward { ... }
        }
    """
    tables: list[dict[str, Any]] = []
    current_table: dict[str, Any] | None = None
    current_chain: dict[str, Any] | None = None
    depth = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"table\s+(\w+)\s+(\S+)\s*\{", line)
        if m:
            current_table = {"family": m.group(1), "name": m.group(2), "chains": []}
            tables.append(current_table)
            depth = 1
            continue
        m = re.match(r"chain\s+(\S+)\s*\{", line)
        if m and current_table is not None:
            current_chain = {"name": m.group(1), "type": "", "hook": "",
                             "priority": "", "policy": "", "rules": []}
            current_table["chains"].append(current_chain)
            depth = 2
            continue
        if line == "}":
            if depth == 2:
                current_chain = None
                depth = 1
            else:
                current_table = None
                depth = 0
            continue
        if current_chain is not None:
            # First-line "type filter hook input priority filter; policy drop;"
            tm = re.search(r"type\s+(\w+)\s+hook\s+(\w+)\s+priority\s+([^;]+);", line)
            if tm:
                current_chain["type"]     = tm.group(1)
                current_chain["hook"]     = tm.group(2)
                current_chain["priority"] = tm.group(3).strip()
                pol = re.search(r"policy\s+(\w+)", line)
                if pol:
                    current_chain["policy"] = pol.group(1)
                continue
            # Skip standalone "policy drop;" if it's separate
            if line.startswith("policy "):
                current_chain["policy"] = line.split()[1].rstrip(";")
                continue
            current_chain["rules"].append(line)
    return tables


# ── iptables-save parser ─────────────────────────────────────────────────────

def _parse_iptables(text: str) -> list[dict[str, Any]]:
    """Parse `iptables-save` output. One table per `*name` line, chains per
    `:name policy [counters]`, rules per `-A name ...` line."""
    tables: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            current = {"family": "ip", "name": line[1:], "chains": []}
            tables.append(current)
            continue
        if current is None:
            continue
        if line.startswith(":"):
            # ":INPUT ACCEPT [0:0]"
            parts = line[1:].split()
            if not parts:
                continue
            current["chains"].append({
                "name":   parts[0],
                "type":   "filter",
                "hook":   parts[0].lower(),
                "priority": "",
                "policy": parts[1] if len(parts) > 1 else "",
                "rules":  [],
            })
            continue
        if line.startswith("-A "):
            # "-A INPUT -p tcp --dport 22 -j ACCEPT"
            try:
                chain_name = line.split()[1]
            except IndexError:
                continue
            for c in current["chains"]:
                if c["name"] == chain_name:
                    c["rules"].append(line)
                    break
        if line == "COMMIT":
            current = None
    return tables


# ── public endpoint ──────────────────────────────────────────────────────────

@router.get("/firewall/rules")
def rules(request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    _require_linux()

    nft = shutil.which("nft")
    iptsave = shutil.which("iptables-save")

    backend = "none"
    raw = ""
    tables: list[dict[str, Any]] = []
    needs_root = False
    error = ""

    if nft:
        r = _run([nft, "list", "ruleset"], timeout=6)
        combined = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0:
            backend = "nftables"
            raw = r.stdout
            tables = _parse_nft(r.stdout)
        elif "Operation not permitted" in combined or "must be root" in combined.lower():
            needs_root = True
            error = combined.strip()
        else:
            error = combined.strip()

    if not tables and iptsave:
        r = _run([iptsave], timeout=6)
        combined = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0 and r.stdout.strip():
            backend = "iptables"
            raw = r.stdout
            tables = _parse_iptables(r.stdout)
        elif "Permission denied" in combined or "must be root" in combined.lower() \
             or "fetch rule set generation" in combined.lower():
            needs_root = True
            error = error or combined.strip()
        elif not error:
            error = combined.strip()

    # Aggregate counts for the summary card on the frontend.
    chain_count = sum(len(t["chains"]) for t in tables)
    rule_count  = sum(len(c["rules"])  for t in tables for c in t["chains"])

    return {
        "backend":    backend,
        "needs_root": needs_root,
        "error":      error if not tables else "",
        "tables":     tables,
        "summary":    {"tables": len(tables), "chains": chain_count, "rules": rule_count},
        "raw":        raw[:8000],   # cap raw payload to keep response bounded
    }
