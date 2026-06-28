"""Target triage — Claude-tailored playbook for a single target.

The user pastes a target and answers a couple of intake questions
("what kind of thing is this?", "where is it exposed?"). We do a small,
bounded passive probe (DNS, HTTP HEAD, TLS handshake), hand everything to
Claude with a tight system prompt, and get back a structured playbook in
the same JSON shape that `preset_engine.save_preset` already accepts.

The UI renders the result as approval cards (AI proposes → human approves),
matches the engagement-first / safety-first stance from ROADMAP.md.

The endpoint never *executes* anything — it only suggests. Run the playbook
via the existing `/ws/preset-run` WebSocket (POST it to `/presets` first if
the user wants to save it).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import ssl
import time
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import anthropic
import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from lib import preset_engine
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.platform_util import app_data_dir
from lib.validators import validate_target

from .chat import resolve_model, _read_prompt_file, _PROMPTS_DIR
from .settings import keychain_get

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/triage", tags=["triage"],
                   dependencies=[Depends(require_local_auth)])


TRIAGE_PROMPT_PATH = _PROMPTS_DIR / "triage.md"

# Bounded probe — every call gets its own short timeout so a slow target
# can't block the whole triage. Total wall-clock budget ~6s.
DNS_TIMEOUT = 2.0
HTTP_TIMEOUT = 4.0
TLS_TIMEOUT = 3.0

# Cap the Claude call so a runaway response doesn't burn tokens.
MAX_TOKENS = 2048


TargetKind = Literal["web_app", "api", "network_host", "iot", "unknown"]
Exposure   = Literal["localhost", "lan", "public", "unknown"]


class TriageRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    kind: TargetKind = "unknown"
    exposure: Exposure = "unknown"
    stack_hints: str = Field("", max_length=512)
    notes: str = Field("", max_length=1024)


class ProbeSummary(BaseModel):
    canonical_target: str
    resolved_ips: list[str]
    http_status: int | None
    http_server: str | None
    http_powered_by: str | None
    http_redirect: str | None
    security_headers_present: list[str]
    security_headers_missing: list[str]
    cms_hint: str | None
    tls_version: str | None
    tls_cert_cn: str | None
    tls_cert_expiry: str | None
    tls_alpn: str | None
    elapsed_ms: int


class TriageResponse(BaseModel):
    probe: ProbeSummary
    narrative: str
    severity_guess: Literal["low", "medium", "high"]
    severity_reason: str
    playbook: dict[str, Any]


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


# ── Probe ───────────────────────────────────────────────────────────────────


def _parse_target(raw: str, kind: TargetKind) -> tuple[str, str | None, int | None]:
    """Return (host, scheme, port).

    Accepts a hostname, an IP, or a URL. For URLs we keep the scheme + port
    so the HTTP probe can hit the exact endpoint the user actually runs.
    """
    raw = raw.strip()
    if "://" in raw:
        u = urlparse(raw)
        host = u.hostname or ""
        port = u.port
        scheme = u.scheme or None
    else:
        # Bare host:port form.
        if ":" in raw and not raw.count(":") > 1:  # not an IPv6 literal
            host, _, p = raw.partition(":")
            try:
                port = int(p)
            except ValueError:
                port = None
            scheme = None
        else:
            host = raw
            port = None
            scheme = None
    if not host:
        raise MhpError("target missing hostname", code=ErrorCode.INVALID_TARGET)
    # Reuse the project-wide validator so weird input fails uniformly.
    validate_target(host, field="target")
    return host, scheme, port


async def _probe_dns(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=DNS_TIMEOUT,
        )
    except (asyncio.TimeoutError, socket.gaierror, OSError):
        return []
    ips: list[str] = []
    seen: set[str] = set()
    for entry in infos:
        ip = entry[4][0]
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips[:8]


async def _probe_http(host: str, scheme: str | None, port: int | None) -> dict[str, Any]:
    """One HEAD-then-GET attempt against the most plausible URL.

    Falls back to https → http if scheme is unknown. Captures status,
    Server / X-Powered-By, redirect target, security-header presence, and
    a coarse CMS hint from any HTML we ended up with.
    """
    candidates: list[str] = []
    base_port = f":{port}" if port else ""
    if scheme:
        candidates.append(f"{scheme}://{host}{base_port}/")
    else:
        # Default sweep: https first, then http.
        candidates.append(f"https://{host}{base_port}/")
        candidates.append(f"http://{host}{base_port}/")

    result: dict[str, Any] = {
        "status": None, "server": None, "powered_by": None, "redirect": None,
        "headers_present": [], "headers_missing": [], "cms_hint": None,
    }

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        follow_redirects=False,
        verify=False,  # we audit TLS separately; let weak/self-signed certs through here
        headers={"User-Agent": "HackingPal-Triage/0.1"},
    ) as client:
        for url in candidates:
            try:
                r = await client.get(url)
            except (httpx.RequestError, httpx.HTTPError):
                continue
            result["status"] = r.status_code
            result["server"] = r.headers.get("Server")
            result["powered_by"] = r.headers.get("X-Powered-By")
            if 300 <= r.status_code < 400:
                result["redirect"] = r.headers.get("Location")
            present: list[str] = []
            missing: list[str] = []
            for h in SECURITY_HEADERS:
                (present if h in r.headers else missing).append(h)
            result["headers_present"] = present
            result["headers_missing"] = missing
            ct = (r.headers.get("Content-Type") or "").lower()
            if "html" in ct and r.text:
                result["cms_hint"] = _guess_cms(r.text, r.headers)
            break

    return result


_CMS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("WordPress", re.compile(r"/wp-(content|includes|admin)/", re.I)),
    ("Drupal",    re.compile(r"Drupal\.settings|/sites/default/", re.I)),
    ("Joomla",    re.compile(r"/media/jui/|content=\"Joomla", re.I)),
    ("Ghost",     re.compile(r"name=\"generator\"[^>]*Ghost", re.I)),
    ("Next.js",   re.compile(r"__next|/_next/static/", re.I)),
    ("Nuxt",      re.compile(r"window\.__NUXT__|/_nuxt/", re.I)),
    ("Django",    re.compile(r"csrfmiddlewaretoken|/static/admin/", re.I)),
    ("Rails",     re.compile(r"csrf-param|/rails/", re.I)),
    ("Express",   re.compile(r"X-Powered-By:\s*Express", re.I)),
]


def _guess_cms(body: str, headers: httpx.Headers) -> str | None:
    sniff = body[:8192]
    for name, pat in _CMS_PATTERNS:
        if pat.search(sniff) or pat.search(str(headers)):
            return name
    return None


async def _probe_tls(host: str, port: int | None) -> dict[str, Any]:
    out: dict[str, Any] = {"version": None, "cert_cn": None, "cert_expiry": None, "alpn": None}
    target_port = port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    loop = asyncio.get_running_loop()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=target_port, ssl=ctx,
                                    server_hostname=host),
            timeout=TLS_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return out
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return out
        out["version"] = ssl_obj.version()
        alpn = ssl_obj.selected_alpn_protocol()
        if alpn:
            out["alpn"] = alpn
        cert = ssl_obj.getpeercert()
        if cert:
            subj = dict(x[0] for x in cert.get("subject", []) if x)
            out["cert_cn"] = subj.get("commonName")
            out["cert_expiry"] = cert.get("notAfter")
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (asyncio.TimeoutError, Exception):
            pass
    return out


async def _run_probe(req: TriageRequest) -> ProbeSummary:
    t0 = time.monotonic()
    host, scheme, port = _parse_target(req.target, req.kind)
    canonical = host if not scheme else f"{scheme}://{host}{':' + str(port) if port else ''}"

    dns_task = asyncio.create_task(_probe_dns(host))
    http_task = asyncio.create_task(_probe_http(host, scheme, port))
    tls_task = asyncio.create_task(_probe_tls(host, port if scheme == "https" else None))

    ips, http_info, tls_info = await asyncio.gather(dns_task, http_task, tls_task)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    return ProbeSummary(
        canonical_target=canonical,
        resolved_ips=ips,
        http_status=http_info.get("status"),
        http_server=http_info.get("server"),
        http_powered_by=http_info.get("powered_by"),
        http_redirect=http_info.get("redirect"),
        security_headers_present=http_info.get("headers_present", []),
        security_headers_missing=http_info.get("headers_missing", []),
        cms_hint=http_info.get("cms_hint"),
        tls_version=tls_info.get("version"),
        tls_cert_cn=tls_info.get("cert_cn"),
        tls_cert_expiry=tls_info.get("cert_expiry"),
        tls_alpn=tls_info.get("alpn"),
        elapsed_ms=elapsed_ms,
    )


# ── Claude call ─────────────────────────────────────────────────────────────


def _build_user_message(req: TriageRequest, probe: ProbeSummary,
                        available_tools: list[str]) -> str:
    return (
        "## Target\n"
        f"- raw: {req.target}\n"
        f"- canonical: {probe.canonical_target}\n"
        f"- kind: {req.kind}\n"
        f"- exposure: {req.exposure}\n"
        f"- stack hints: {req.stack_hints or '(none)'}\n"
        f"- user notes: {req.notes or '(none)'}\n\n"
        "## Probe results\n"
        f"```json\n{probe.model_dump_json(indent=2)}\n```\n\n"
        "## Available tools\n"
        "Pick step `tool` values only from this list:\n"
        f"{', '.join(available_tools)}\n\n"
        "Return the JSON object now."
    )


def _resolve_system_prompt() -> str:
    text = _read_prompt_file(TRIAGE_PROMPT_PATH)
    if text:
        return text
    # Last-ditch fallback so a missing prompt file doesn't break triage.
    return ("You are the target triage copilot for HackingPal. "
            "Return a JSON object with keys: narrative, severity_guess, "
            "severity_reason, playbook. Use only tools from available_tools.")


def _extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first balanced JSON object out of a model response.

    Claude usually returns clean JSON when asked to, but occasionally
    surrounds it with code fences or a one-line preamble. We scan for the
    first `{` and walk braces to find the matching `}`.
    """
    start = text.find("{")
    if start < 0:
        raise MhpError("triage response had no JSON object",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502)
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError as e:
                    raise MhpError(f"triage JSON parse failed: {e}",
                                   code=ErrorCode.UPSTREAM_FAILED,
                                   status_code=502) from e
    raise MhpError("triage JSON object was unterminated",
                   code=ErrorCode.UPSTREAM_FAILED, status_code=502)


def _sanitize_playbook(pb: dict[str, Any], req: TriageRequest,
                       available_tools: set[str]) -> dict[str, Any]:
    """Drop unknown tools, normalize required fields, and ensure ids are unique.

    Claude is generally well-behaved but we trust nothing — anything that
    doesn't fit the preset schema gets dropped or fixed before we hand the
    playbook back to the frontend.
    """
    name = str(pb.get("name") or f"Triage plan for {req.target}").strip()[:120]
    description = str(pb.get("description") or "").strip()[:600]
    target_type = pb.get("target_type") or _guess_target_type(req)
    if target_type not in preset_engine.ALLOWED_TARGET_TYPES:
        target_type = _guess_target_type(req)
    category = pb.get("category") or "surface_inventory"
    if category not in preset_engine.ALLOWED_CATEGORIES:
        category = "surface_inventory"
    mode_required = pb.get("mode_required") or "either"
    if mode_required not in preset_engine.ALLOWED_MODES:
        mode_required = "either"

    raw_steps = pb.get("steps") or []
    seen_ids: set[str] = set()
    clean_steps: list[dict[str, Any]] = []
    for s in raw_steps:
        if not isinstance(s, dict):
            continue
        tool = str(s.get("tool", "")).strip()
        if tool not in available_tools:
            continue
        sid = str(s.get("id") or tool).strip() or tool
        # De-dupe ids so the preset engine doesn't reject the whole playbook.
        base = sid
        n = 2
        while sid in seen_ids:
            sid = f"{base}_{n}"
            n += 1
        seen_ids.add(sid)
        step = {
            "id": sid,
            "tool": tool,
            "rationale": str(s.get("rationale") or "")[:600],
            "success": str(s.get("success") or "")[:300],
            "approval": bool(s.get("approval", True)),
            "options": s.get("options") if isinstance(s.get("options"), dict) else {},
        }
        clean_steps.append(step)

    if not clean_steps:
        raise MhpError("triage produced no usable steps",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502)

    # Stable, predictable id; the frontend can POST this to /presets if the
    # user clicks "save as my playbook".
    slug_target = re.sub(r"[^a-z0-9]+", "_", req.target.lower()).strip("_")[:40]
    suggested_id = f"triage_{slug_target}" if slug_target else "triage_unknown"

    return {
        "id": suggested_id,
        "name": name,
        "description": description,
        "category": category,
        "target_type": target_type,
        "mode_required": mode_required,
        "author": "triage",
        "steps": clean_steps,
    }


def _guess_target_type(req: TriageRequest) -> str:
    if "://" in req.target:
        return "url"
    if req.kind == "network_host":
        return "host"
    return "domain"


@router.post("", response_model=TriageResponse)
async def triage(req: TriageRequest) -> TriageResponse:
    """Probe + Claude → structured playbook.

    The probe is bounded to a few seconds. Claude is a single non-streaming
    call returning JSON. Anything malformed comes back as a 502 with the
    parse error so the UI can fall back to the baseline preset.
    """
    api_key = keychain_get()
    if not api_key:
        raise MhpError(
            "Anthropic API key not set. Add one in Settings to use AI triage.",
            code=ErrorCode.UNAUTHORIZED, status_code=401,
        )

    probe = await _run_probe(req)

    available_tools = preset_engine.known_tools()
    user_msg = _build_user_message(req, probe, available_tools)
    system_prompt = _resolve_system_prompt()

    client = anthropic.Anthropic(api_key=api_key)
    try:
        msg = client.messages.create(
            model=resolve_model(),
            max_tokens=MAX_TOKENS,
            system=[{
                "type": "text", "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": user_msg}],
        )
    except anthropic.AuthenticationError as e:
        raise MhpError("Anthropic rejected the API key.",
                       code=ErrorCode.UNAUTHORIZED, status_code=401) from e
    except anthropic.RateLimitError as e:
        raise MhpError("Rate limited by Anthropic. Retry shortly.",
                       code=ErrorCode.RATE_LIMITED, status_code=429) from e
    except anthropic.APIError as e:
        logger.warning("triage anthropic api error type=%s", type(e).__name__)
        raise MhpError("Anthropic API error — check the logs.",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502) from e

    raw_text = ""
    for block in msg.content:
        if getattr(block, "type", "") == "text":
            raw_text += getattr(block, "text", "")
    if not raw_text.strip():
        raise MhpError("triage response was empty",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502)

    parsed = _extract_json_object(raw_text)
    narrative = str(parsed.get("narrative") or "")[:1000]
    sev_guess = parsed.get("severity_guess") or "low"
    if sev_guess not in ("low", "medium", "high"):
        sev_guess = "low"
    sev_reason = str(parsed.get("severity_reason") or "")[:400]
    raw_playbook = parsed.get("playbook") or {}
    if not isinstance(raw_playbook, dict):
        raise MhpError("triage playbook had wrong shape",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502)
    playbook = _sanitize_playbook(raw_playbook, req, set(available_tools))

    return TriageResponse(
        probe=probe,
        narrative=narrative,
        severity_guess=sev_guess,  # type: ignore[arg-type]
        severity_reason=sev_reason,
        playbook=playbook,
    )
