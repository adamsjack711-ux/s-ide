"""Custom playbook suggester — Copilot helps a home-app builder design a
playbook for their own application.

POST /playbook/suggest takes a target plus a free-text description of the
app and asks Claude to propose a tailored 3-7 step playbook drawn from
the engine's known-tools registry. The endpoint NEVER executes anything;
the response is rendered as approval cards in the UI and can be saved as
a regular `.mhp` preset via POST /presets.

Mirrors triage.py but skips the live probe — the user already knows what
they built, and the value here is the AI shaping a plan around their
self-description rather than re-discovering basics.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

import anthropic
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from lib import preset_engine
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError
from lib.validators import validate_target

from .chat import resolve_model, _read_prompt_file, _PROMPTS_DIR
from .settings import keychain_get

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/playbook", tags=["playbook-suggest"],
                   dependencies=[Depends(require_local_auth)])

# Token cap matched to triage — a 3-7 step playbook with rationale fits
# comfortably under 2048 output tokens even with verbose rationales.
MAX_TOKENS = 2048

SUGGEST_PROMPT_PATH = _PROMPTS_DIR / "playbook_suggest.md"


class SuggestRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    app_description: str = Field("", max_length=2000)


class SuggestedStep(BaseModel):
    id: str
    tool: str
    rationale: str
    options: dict[str, Any] = Field(default_factory=dict)


class SuggestedPhase(BaseModel):
    name: str
    steps: list[SuggestedStep]


class SuggestedPlaybook(BaseModel):
    id: str
    name: str
    description: str
    target_type: str
    category: str
    mode_required: str
    author: str
    # Flat `steps` is what /presets POST expects today; we also emit the
    # phase breakdown so the UI can render a phase grouping without a
    # second round-trip.
    steps: list[dict[str, Any]]
    phases: list[SuggestedPhase]


class SuggestResponse(BaseModel):
    playbook_name: str
    rationale: str
    playbook: SuggestedPlaybook


# ── Helpers ─────────────────────────────────────────────────────────────────


def _parse_target(raw: str) -> tuple[str, str]:
    """Return (canonical_label, host_for_validation).

    Accepts URL / host:port / bare host. The label keeps whatever the user
    typed (used for the playbook id/name); the host is the part we hand to
    `validate_target` so we reject e.g. command-injection-shaped input.
    """
    s = raw.strip()
    label = s
    host = s
    if "://" in s:
        from urllib.parse import urlparse
        u = urlparse(s)
        host = u.hostname or ""
    elif ":" in s and s.count(":") == 1:
        host, _, _ = s.partition(":")
    if not host:
        raise MhpError("target missing hostname", code=ErrorCode.INVALID_TARGET)
    validate_target(host, field="target")
    return label, host


def _guess_target_type(raw: str) -> str:
    if "://" in raw:
        return "url"
    # Bare IP? Treat as ip for the engine. Falls back to domain otherwise.
    parts = raw.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"


def _system_prompt() -> str:
    text = _read_prompt_file(SUGGEST_PROMPT_PATH)
    if text:
        return text
    # Inline fallback — kept short. The frontend won't see this if the
    # prompt file ships in the bundle; the fallback exists so a missing
    # asset doesn't take the feature down.
    return (
        "You are the playbook-builder copilot for s-ide. The user is "
        "testing their OWN application — a personal project, a home server, "
        "an internal tool. They want a tailored security playbook.\n\n"
        "Return JSON ONLY with this shape:\n"
        "{\n"
        '  "playbook_name": "<short name>",\n'
        '  "rationale": "<2-3 sentences on why this plan>",\n'
        '  "phases": [\n'
        '    {"name": "Recon", "steps": [\n'
        '       {"tool": "<from available_tools>", "rationale": "...", "options": {}}\n'
        "    ]}\n"
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- 3 to 7 steps total across all phases.\n"
        "- Use ONLY tools from the supplied available_tools list.\n"
        "- Order: passive recon → surface mapping → targeted active checks.\n"
        "- Conservative defaults — this is the user's own app, not a red team.\n"
        "- First character of your response MUST be `{`."
    )


def _build_user_message(req: SuggestRequest, canonical: str,
                        available_tools: list[str]) -> str:
    return (
        "## Target\n"
        f"- raw: {req.target}\n"
        f"- canonical: {canonical}\n\n"
        "## App description (from the user)\n"
        f"{req.app_description.strip() or '(none provided)'}\n\n"
        "## Available tools\n"
        "Pick step `tool` values only from this list:\n"
        f"{', '.join(available_tools)}\n\n"
        "Return the JSON object now."
    )


def _extract_json_object(text: str) -> dict[str, Any]:
    start = text.find("{")
    if start < 0:
        raise MhpError("suggestion had no JSON object",
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
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError as e:
                    raise MhpError(f"suggestion JSON parse failed: {e}",
                                   code=ErrorCode.UPSTREAM_FAILED,
                                   status_code=502) from e
    raise MhpError("suggestion JSON object was unterminated",
                   code=ErrorCode.UPSTREAM_FAILED, status_code=502)


def _slugify(s: str, maxlen: int = 40) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")[:maxlen]


def _shape_playbook(parsed: dict[str, Any], req: SuggestRequest,
                    available: set[str]) -> SuggestedPlaybook:
    """Filter out unknown tools, normalise ids, and emit both phase and
    flat-step views so the UI can render either and the save path uses the
    flat form `/presets` already accepts.
    """
    raw_phases = parsed.get("phases") or []
    if not isinstance(raw_phases, list):
        raise MhpError("phases must be a list",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502)

    seen_ids: set[str] = set()
    phases: list[SuggestedPhase] = []
    flat_steps: list[dict[str, Any]] = []

    for ph in raw_phases:
        if not isinstance(ph, dict):
            continue
        ph_name = str(ph.get("name") or "Phase").strip()[:80] or "Phase"
        ph_steps_raw = ph.get("steps") or []
        if not isinstance(ph_steps_raw, list):
            continue
        ph_steps: list[SuggestedStep] = []
        for s in ph_steps_raw:
            if not isinstance(s, dict):
                continue
            tool = str(s.get("tool", "")).strip()
            if tool not in available:
                continue
            sid_base = str(s.get("id") or tool).strip() or tool
            sid = sid_base
            n = 2
            while sid in seen_ids:
                sid = f"{sid_base}_{n}"
                n += 1
            seen_ids.add(sid)
            options = s.get("options") if isinstance(s.get("options"), dict) else {}
            rationale = str(s.get("rationale") or "")[:600]
            step = SuggestedStep(id=sid, tool=tool, rationale=rationale,
                                 options=options)
            ph_steps.append(step)
            flat_steps.append({
                "id": sid,
                "tool": tool,
                "rationale": rationale,
                "approval": True,
                "options": options,
            })
        if ph_steps:
            phases.append(SuggestedPhase(name=ph_name, steps=ph_steps))

    if not flat_steps:
        raise MhpError("suggestion produced no usable steps",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502)

    target_type = _guess_target_type(req.target)
    name = str(parsed.get("playbook_name") or f"Custom plan for {req.target}").strip()[:120]
    description = str(parsed.get("rationale") or "")[:600]
    suggested_id = f"copilot_{_slugify(req.target) or 'plan'}"
    category = "custom"
    if target_type == "url":
        category = "web_app"

    return SuggestedPlaybook(
        id=suggested_id,
        name=name,
        description=description,
        target_type=target_type,
        category=category,
        mode_required="either",
        author="copilot",
        steps=flat_steps,
        phases=phases,
    )


# ── Endpoint ────────────────────────────────────────────────────────────────


@router.post("/suggest", response_model=SuggestResponse)
async def suggest_playbook(req: SuggestRequest) -> SuggestResponse:
    api_key = keychain_get()
    if not api_key:
        raise MhpError(
            "Anthropic API key not set. Add one in Settings to use the copilot.",
            code=ErrorCode.UNAUTHORIZED, status_code=401,
        )

    canonical, _host = _parse_target(req.target)

    available_tools = preset_engine.known_tools()
    user_msg = _build_user_message(req, canonical, available_tools)
    system_prompt = _system_prompt()

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
        logger.warning("playbook suggest anthropic api error type=%s",
                       type(e).__name__)
        raise MhpError("Anthropic API error — check the logs.",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502) from e

    raw_text = ""
    for block in msg.content:
        if getattr(block, "type", "") == "text":
            raw_text += getattr(block, "text", "")
    if not raw_text.strip():
        raise MhpError("suggestion response was empty",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502)

    parsed = _extract_json_object(raw_text)
    playbook = _shape_playbook(parsed, req, set(available_tools))

    return SuggestResponse(
        playbook_name=playbook.name,
        rationale=str(parsed.get("rationale") or "")[:1000],
        playbook=playbook,
    )
