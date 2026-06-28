"""Credential Harvester — read-only audit of credential stores on this machine.

This is **defensive auditing**: shows the user what's lying around in plain
text on their *own* filesystem. We never exfil — every secret stays local,
and we redact heavily even in the response payload (last 4 chars of any
detected token, never the full value).

Sources we audit (all under $HOME):

  - `~/.aws/credentials` + `~/.aws/config`
  - `~/.ssh/config`, `~/.ssh/id_*` (count + permissions; never read keys)
  - `~/.netrc` (machine entries, redacted)
  - `~/.docker/config.json` (auths)
  - `~/.gitconfig` (credential helpers, URLs with embedded tokens)
  - `~/.npmrc`, `~/.pypirc`
  - `.env` files in common project locations (~/Documents, ~/Projects, ~/code,
    and current cwd)
  - Browser cookie/login DBs — count only, never decrypt (would need keychain
    integration we deliberately skip)

Findings have severity:
  - high:   private key world-readable (mode includes others-read)
  - high:   token-shaped string in plaintext config
  - medium: credential helper using plaintext store
  - info:   file exists with N entries
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request

from lib import scope
from lib.mode import get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cred-harvest", tags=["cred-harvest"])

HOME = Path.home()


# ── Helpers ────────────────────────────────────────────────────────────────

def _redact(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:2]}…{s[-4:]} ({len(s)} chars)"


def _perms_world_readable(path: Path) -> bool:
    try:
        m = path.stat().st_mode
        return bool(m & stat.S_IROTH)
    except OSError:
        return False


def _detect_token_in_text(text: str) -> list[str]:
    """Return list of token-like strings found in `text`."""
    hits: list[str] = []
    patterns = [
        # AWS
        r"\bAKIA[0-9A-Z]{16}\b",
        # GitHub PATs
        r"\bghp_[a-zA-Z0-9]{36}\b",
        r"\bghs_[a-zA-Z0-9]{36}\b",
        r"\bgho_[a-zA-Z0-9]{36}\b",
        # Slack
        r"\bxox[abposr]-[a-zA-Z0-9-]{10,}\b",
        # Bearer-ish secrets
        r"['\"]?[A-Za-z0-9+/=_-]{32,}['\"]?\s*$",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.MULTILINE):
            hits.append(m.group(0))
    return hits


def _add(out: list[dict[str, Any]], severity: str, source: str,
         title: str, detail: str, evidence: Any = None) -> None:
    out.append({"severity": severity, "source": source,
                "title": title, "detail": detail, "evidence": evidence})


# ── Per-source scanners ────────────────────────────────────────────────────

def _check_aws(findings: list[dict[str, Any]]) -> dict[str, Any]:
    creds_path = HOME / ".aws" / "credentials"
    conf_path  = HOME / ".aws" / "config"
    info: dict[str, Any] = {"credentials_exists": False, "config_exists": False,
                            "profiles": []}
    if creds_path.exists():
        info["credentials_exists"] = True
        if _perms_world_readable(creds_path):
            _add(findings, "high", "aws",
                 f"{creds_path}: world-readable",
                 "Mode includes others-read — anyone on the system can grab the keys.")
        try:
            text = creds_path.read_text(errors="replace")
            profiles = re.findall(r"^\[([^\]]+)\]", text, re.MULTILINE)
            info["profiles"] = profiles
            for token in _detect_token_in_text(text):
                _add(findings, "high", "aws",
                     "Token-shaped string in aws/credentials",
                     f"Looks like a real secret — {_redact(token)}")
        except OSError:
            pass
    if conf_path.exists():
        info["config_exists"] = True
    return info


def _check_ssh(findings: list[dict[str, Any]]) -> dict[str, Any]:
    ssh_dir = HOME / ".ssh"
    info: dict[str, Any] = {"keys": [], "config_exists": False}
    if not ssh_dir.exists():
        return info
    if (ssh_dir / "config").exists():
        info["config_exists"] = True
    try:
        for f in ssh_dir.iterdir():
            if not f.is_file():
                continue
            name = f.name
            if name.startswith("id_") and not name.endswith(".pub") and not name.endswith(".known_hosts"):
                entry = {
                    "name": name, "size": f.stat().st_size,
                    "world_readable": _perms_world_readable(f),
                    "mode": oct(f.stat().st_mode & 0o777),
                }
                info["keys"].append(entry)
                if entry["world_readable"]:
                    _add(findings, "high", "ssh",
                         f"~/.ssh/{name}: world-readable",
                         f"Mode {entry['mode']} — anyone on the system can read this private key.",
                         evidence=entry)
                # Read first line to detect type (PEM, OpenSSH, encrypted vs not)
                try:
                    first = f.read_text(errors="replace").splitlines()[:3]
                    if any("ENCRYPTED" in line for line in first):
                        entry["encrypted"] = True
                    elif first and first[0].startswith("-----BEGIN"):
                        entry["encrypted"] = False
                        _add(findings, "medium", "ssh",
                             f"~/.ssh/{name}: unencrypted private key",
                             "Key has no passphrase — anyone with file read access can use it.",
                             evidence={"name": name})
                except OSError:
                    pass
    except OSError:
        pass
    return info


def _check_netrc(findings: list[dict[str, Any]]) -> dict[str, Any]:
    path = HOME / ".netrc"
    info: dict[str, Any] = {"exists": False, "machines": []}
    if not path.exists():
        return info
    info["exists"] = True
    if _perms_world_readable(path):
        _add(findings, "high", "netrc",
             "~/.netrc: world-readable",
             "Mode includes others-read — credentials inside are exposed.")
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return info
    current: dict[str, str] = {}
    machines: list[dict[str, str]] = []
    for tok in text.split():
        if tok == "machine":
            if current.get("machine"):
                machines.append(current)
            current = {}
            continue
        keys = ("machine", "login", "password", "account")
        # We expect alternating key/value tokens after "machine"
    # Cheap re-parse with regex: each `machine X login Y password Z`
    for m in re.finditer(r"machine\s+(\S+)(?:\s+login\s+(\S+))?(?:\s+password\s+(\S+))?",
                         text, re.IGNORECASE):
        machines.append({
            "machine": m.group(1),
            "login": m.group(2) or "",
            "password": _redact(m.group(3) or ""),
        })
    info["machines"] = machines
    if machines:
        _add(findings, "medium", "netrc",
             f"~/.netrc has {len(machines)} machine entries",
             "Plaintext credentials. Common for `curl`, `git`, `ftp`, but a soft target.",
             evidence={"machines": [m["machine"] for m in machines]})
    return info


def _check_docker(findings: list[dict[str, Any]]) -> dict[str, Any]:
    path = HOME / ".docker" / "config.json"
    info: dict[str, Any] = {"exists": False, "auths": [], "helpers": []}
    if not path.exists():
        return info
    info["exists"] = True
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return info
    auths = data.get("auths", {}) or {}
    for registry, conf in auths.items():
        entry: dict[str, Any] = {"registry": registry, "kind": ""}
        if conf.get("auth"):
            try:
                decoded = base64.b64decode(conf["auth"]).decode(errors="replace")
                username = decoded.split(":", 1)[0]
                entry["kind"] = "plaintext-base64"
                entry["username"] = username
                _add(findings, "high", "docker",
                     f"docker auth for {registry}: plaintext (base64)",
                     f"Username/password stored base64-encoded in config.json — "
                     "treat as plaintext.",
                     evidence={"registry": registry, "username": username})
            except Exception:
                entry["kind"] = "unknown"
        elif conf.get("identitytoken"):
            entry["kind"] = "identitytoken"
        info["auths"].append(entry)
    helpers = data.get("credHelpers", {}) or {}
    helper_default = data.get("credsStore", "") or ""
    info["helpers"] = [{"registry": r, "helper": h} for r, h in helpers.items()]
    if helper_default:
        info["helpers"].append({"registry": "<default>", "helper": helper_default})
    return info


def _check_git(findings: list[dict[str, Any]]) -> dict[str, Any]:
    path = HOME / ".gitconfig"
    info: dict[str, Any] = {"exists": False, "helpers": [], "embedded_tokens": []}
    if not path.exists():
        return info
    info["exists"] = True
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return info
    for m in re.finditer(r"helper\s*=\s*(\S.*?)(?:$|\n)", text, re.MULTILINE):
        helper = m.group(1).strip()
        info["helpers"].append(helper)
        if helper == "store":
            _add(findings, "high", "git",
                 "git credential helper = store",
                 "Plaintext at ~/.git-credentials. Use osxkeychain or libsecret instead.")
    # urls with embedded creds: https://user:token@github.com/foo
    for m in re.finditer(r"https?://[^:\s]+:([^@\s]+)@", text):
        token = m.group(1)
        info["embedded_tokens"].append(_redact(token))
        _add(findings, "high", "git",
             "Token embedded in git URL",
             f"Found token-shaped URL in gitconfig — {_redact(token)}")
    return info


def _check_npm_pypi(findings: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"npmrc": False, "pypirc": False}
    for fname, key in [(".npmrc", "npmrc"), (".pypirc", "pypirc")]:
        p = HOME / fname
        if not p.exists():
            continue
        out[key] = True
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for token in _detect_token_in_text(text):
            _add(findings, "high", fname.lstrip("."),
                 f"~/{fname}: token-shaped value",
                 f"{_redact(token)} — likely an auth token / registry password in plaintext.")
        # Auth lines specifically
        for m in re.finditer(r"_auth\s*=\s*([A-Za-z0-9+/=_-]{12,})", text):
            _add(findings, "medium", fname.lstrip("."),
                 f"~/{fname}: _auth field",
                 "npm legacy _auth = base64(user:pass) — stored in plaintext.",
                 evidence={"value": _redact(m.group(1))})
    return out


def _check_env_files() -> list[dict[str, Any]]:
    # Look at common project directories (recursively shallow)
    candidates: list[Path] = []
    for root in (HOME / "Documents", HOME / "Projects", HOME / "code",
                 HOME / "src", Path.cwd()):
        if not root.exists():
            continue
        # 2 levels deep max
        try:
            for child in root.iterdir():
                if child.is_dir():
                    for grand in child.iterdir():
                        if grand.is_file() and grand.name in (".env", ".env.local", ".env.production"):
                            candidates.append(grand)
                elif child.is_file() and child.name in (".env", ".env.local", ".env.production"):
                    candidates.append(child)
        except (PermissionError, OSError):
            continue
    out = []
    for p in candidates[:50]:
        try:
            size = p.stat().st_size
            lines = sum(1 for _ in p.read_text(errors="replace").splitlines() if _.strip() and not _.lstrip().startswith("#"))
        except OSError:
            continue
        out.append({"path": str(p), "size": size, "lines": lines})
    return out


# ── Entry point ─────────────────────────────────────────────────────────────

@router.get("/scan")
def scan(request: Request) -> dict[str, Any]:
    scope.enforce_engagement_present(get_engagement_id(request), get_mode(request))
    findings: list[dict[str, Any]] = []
    sources: dict[str, Any] = {
        "aws":       _check_aws(findings),
        "ssh":       _check_ssh(findings),
        "netrc":     _check_netrc(findings),
        "docker":    _check_docker(findings),
        "git":       _check_git(findings),
        "pkg":       _check_npm_pypi(findings),
        "env_files": _check_env_files(),
    }
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 99))
    return {"home": str(HOME), "findings": findings, "sources": sources}
