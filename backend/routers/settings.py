"""Per-user settings (Anthropic API key) stored in the macOS Keychain.

Uses the `security` CLI shipped with macOS — no extra Python deps, and the key
stays encrypted at rest under the user's login keychain.
"""
from __future__ import annotations

import logging
import os
import subprocess

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from lib import audit_log
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.mode import Mode, get_engagement_id, get_mode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings", tags=["settings"], dependencies=[Depends(require_local_auth)])

KEYCHAIN_SERVICE = "HackingPal"
# Old service name kept as a read-only fallback so keys stored before the
# MyHackingPal → HackingPal rebrand are still discoverable. On first read
# we copy the value forward to the new service. Safe to remove in a later
# release once early testers have re-launched the app at least once.
_LEGACY_KEYCHAIN_SERVICE = "MyHackingPal"
KEYCHAIN_ACCOUNT = "anthropic_api_key"

# Additional named keys for external services (subdomain enum sources etc.).
# Naming convention: the keychain account is the value passed to keychain_get_named.
NAMED_KEYS = {
    "securitytrails_api_key": "SecurityTrails API key",
    "virustotal_api_key":     "VirusTotal API key",
    "shodan_api_key":         "Shodan API key",
    "hibp_api_key":           "HaveIBeenPwned API key",
    "github_token":           "GitHub personal access token",
    "google_cse_api_key":     "Google Custom Search API key",
    "google_cse_id":          "Google Custom Search engine ID (cx)",
    "censys_api_id":          "Censys API ID",
    "censys_api_secret":      "Censys API secret",
    "hunter_api_key":         "Hunter.io API key",
}


def _keychain_read(account: str, service: str) -> str | None:
    try:
        r = subprocess.run(
            ["security", "find-generic-password",
             "-a", account, "-s", service, "-w"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def keychain_get_named(account: str) -> str | None:
    v = _keychain_read(account, KEYCHAIN_SERVICE)
    if v is not None:
        return v
    legacy = _keychain_read(account, _LEGACY_KEYCHAIN_SERVICE)
    if legacy is None:
        return None
    try:
        keychain_set_named(account, legacy)
    except Exception:
        logger.exception("keychain forward-copy failed for %s", account)
    return legacy


def keychain_set_named(account: str, value: str) -> None:
    r = subprocess.run(
        ["security", "add-generic-password",
         "-a", account, "-s", KEYCHAIN_SERVICE, "-w", value, "-U"],
        capture_output=True, text=True, timeout=5,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "keychain write failed")


def keychain_delete_named(account: str) -> bool:
    r = subprocess.run(
        ["security", "delete-generic-password",
         "-a", account, "-s", KEYCHAIN_SERVICE],
        capture_output=True, text=True, timeout=5,
    )
    return r.returncode == 0


# Back-compat helpers — the original chat router uses these.
def keychain_get() -> str | None:
    # Env var first so Linux/Docker deployments (no `security` CLI) can still
    # supply an Anthropic key without writing to disk.
    env_key = os.environ.get("ANTHROPIC_API_KEY")
    if env_key:
        return env_key.strip()
    return keychain_get_named(KEYCHAIN_ACCOUNT)


def keychain_set(value: str) -> None:
    keychain_set_named(KEYCHAIN_ACCOUNT, value)


def keychain_delete() -> bool:
    return keychain_delete_named(KEYCHAIN_ACCOUNT)


class ApiKeyStatus(BaseModel):
    present: bool
    last4: str = ""


class ApiKeyBody(BaseModel):
    api_key: str = Field(..., min_length=10)


@router.get("/api-key/status", response_model=ApiKeyStatus)
def api_key_status() -> ApiKeyStatus:
    k = keychain_get()
    if not k:
        return ApiKeyStatus(present=False)
    return ApiKeyStatus(present=True, last4=k[-4:])


@router.post("/api-key", response_model=ApiKeyStatus)
def api_key_set(body: ApiKeyBody) -> ApiKeyStatus:
    key = body.api_key.strip()
    if not key.startswith("sk-ant-"):
        raise HTTPException(400, "Key must start with 'sk-ant-'")
    try:
        keychain_set(key)
    except RuntimeError:
        logger.exception("keychain_set failed for anthropic_api_key")
        raise MhpError(
            "keychain write failed",
            code=ErrorCode.INTERNAL,
            status_code=500,
        )
    return ApiKeyStatus(present=True, last4=key[-4:])


@router.delete("/api-key", response_model=ApiKeyStatus)
def api_key_delete() -> ApiKeyStatus:
    keychain_delete()
    return ApiKeyStatus(present=False)


# ── Named-key endpoints (SecurityTrails / VirusTotal / Shodan etc.) ─────────

class NamedKeyStatus(BaseModel):
    name: str
    label: str
    present: bool
    last4: str = ""


class NamedKeyBody(BaseModel):
    value: str = Field(..., min_length=4)


@router.get("/keys", response_model=list[NamedKeyStatus])
def list_named_keys() -> list[NamedKeyStatus]:
    out: list[NamedKeyStatus] = []
    for name, label in NAMED_KEYS.items():
        v = keychain_get_named(name)
        out.append(NamedKeyStatus(
            name=name, label=label,
            present=bool(v), last4=v[-4:] if v else "",
        ))
    return out


@router.post("/keys/{name}", response_model=NamedKeyStatus)
def set_named_key(name: str, body: NamedKeyBody) -> NamedKeyStatus:
    if name not in NAMED_KEYS:
        raise HTTPException(404, f"Unknown key name: {name}")
    try:
        keychain_set_named(name, body.value.strip())
    except RuntimeError:
        logger.exception("keychain_set_named failed name=%s", name)
        raise MhpError(
            "keychain write failed",
            code=ErrorCode.INTERNAL,
            status_code=500,
        )
    return NamedKeyStatus(name=name, label=NAMED_KEYS[name],
                          present=True, last4=body.value.strip()[-4:])


@router.delete("/keys/{name}", response_model=NamedKeyStatus)
def delete_named_key(name: str) -> NamedKeyStatus:
    if name not in NAMED_KEYS:
        raise HTTPException(404, f"Unknown key name: {name}")
    keychain_delete_named(name)
    return NamedKeyStatus(name=name, label=NAMED_KEYS[name], present=False)


# ── Audit-log writes for high-leverage settings changes ─────────────────────
#
# Both endpoints below are "log-only" — they don't mutate any setting, they
# just record that a change happened. The live state still lives in
# localStorage (mode) or on disk (system prompt); the audit row is the
# tamper-evident history of *when* the change happened and what it changed
# from/to. Each call writes exactly one row (started → completed in one shot).

class ModeSwitchBody(BaseModel):
    old: Mode
    new: Mode


@router.post("/audit/mode-switch", status_code=204)
def audit_mode_switch(body: ModeSwitchBody, request: Request) -> Response:
    if body.old == body.new:
        return Response(status_code=204)
    aid = audit_log.start(
        tool="mode-switch",
        argv=[body.old, body.new],
        engagement_id=get_engagement_id(request),
        mode=body.new,
    )
    audit_log.complete(aid, summary=f"{body.old} → {body.new}")
    return Response(status_code=204)


class PromptEditBody(BaseModel):
    chars_before: int = Field(..., ge=0, le=1_000_000)
    chars_after:  int = Field(..., ge=0, le=1_000_000)
    model:        str = Field(default="", max_length=200)


@router.post("/audit/prompt-edit", status_code=204)
def audit_prompt_edit(body: PromptEditBody, request: Request) -> Response:
    delta = body.chars_after - body.chars_before
    sign = "+" if delta >= 0 else ""
    summary = f"{body.chars_before} → {body.chars_after} chars ({sign}{delta})"
    if body.model:
        summary += f" · {body.model}"
    aid = audit_log.start(
        tool="prompt-edit",
        argv=[f"chars_before={body.chars_before}",
              f"chars_after={body.chars_after}"],
        engagement_id=get_engagement_id(request),
        mode=get_mode(request),
    )
    audit_log.complete(aid, summary=summary)
    return Response(status_code=204)
