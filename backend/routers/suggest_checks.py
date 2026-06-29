"""POST /chat/suggest-checks — the chat "Suggest checks" affordance.

Given the recent conversation (and optionally the active target), asks the
copilot to propose a handful of concrete next checks drawn from a bounded
catalog (lib/suggested_checks). Returns card-ready items the chat UI renders
as Approve / Skip / Modify cards. The copilot proposes only — approving a
card navigates to the tool page with the target pre-filled; nothing here
executes a scan.

Mirrors routers/playbook_suggest: same key/model resolution, same
prompt-instructed-JSON + tolerant-parse approach, same error mapping.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

import anthropic
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from lib import suggested_checks
from lib.auth import require_local_auth
from lib.errors import ErrorCode, MhpError

from .chat import resolve_model
from .settings import keychain_get

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chat"], dependencies=[Depends(require_local_auth)])

MAX_TOKENS = 1024
# How much conversation tail to feed the model — enough for intent, bounded
# so the proposal call stays cheap.
_CONTEXT_TURNS = 8


class SuggestChecksMessage(BaseModel):
    role: str
    content: str


class SuggestChecksRequest(BaseModel):
    messages: list[SuggestChecksMessage] = Field(default_factory=list)
    active_page: str = ""
    target: str = Field("", max_length=512)


class SuggestedCheck(BaseModel):
    tool: str
    nav_id: str
    label: str
    target: str
    rationale: str


class SuggestChecksResponse(BaseModel):
    checks: list[SuggestedCheck]


def _system_prompt() -> str:
    catalog = "\n".join(
        f"  - {c['id']}: {c['label']}" for c in suggested_checks.catalog_for_prompt()
    )
    return (
        "You are the s-ide security copilot. Based on the conversation, "
        "propose 2-5 concrete next checks the operator could run. You PROPOSE "
        "only — you never run anything; the operator approves each card.\n\n"
        "Choose only from this catalog (use the exact `id`):\n"
        f"{catalog}\n\n"
        "Rules:\n"
        "- Pick the checks that actually fit what the conversation is about. "
        "Don't pad to 5; 2-3 well-chosen checks beat a generic sweep.\n"
        "- Set `target` to the host/domain/URL each check should run against. "
        "If the conversation has a clear target, reuse it.\n"
        "- `rationale` is one short sentence on why this check, now.\n\n"
        'Return JSON ONLY, no prose, exactly:\n'
        '{"checks": [{"tool": "<id>", "target": "<host>", '
        '"rationale": "<why>"}]}'
    )


def _user_message(req: SuggestChecksRequest) -> str:
    parts: list[str] = []
    if req.active_page:
        parts.append(f"[context] Operator is on the {req.active_page} page.")
    if req.target.strip():
        parts.append(f"[context] Active target: {req.target.strip()}")
    tail = req.messages[-_CONTEXT_TURNS:]
    if tail:
        parts.append("Conversation:")
        for m in tail:
            who = "Operator" if m.role == "user" else "Assistant"
            parts.append(f"{who}: {m.content.strip()[:1500]}")
    parts.append("Propose the checks now as JSON.")
    return "\n".join(parts)


def _extract_json(text: str) -> dict[str, Any]:
    """Tolerant parse: whole-string JSON, else the first balanced object."""
    text = text.strip()
    # Strip a ```json … ``` fence if present.
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(text[start:end + 1])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    return {}


@router.post("/chat/suggest-checks", response_model=SuggestChecksResponse)
async def suggest_checks(req: SuggestChecksRequest) -> SuggestChecksResponse:
    api_key = keychain_get()
    if not api_key:
        raise MhpError(
            "Anthropic API key not set. Add one in Settings to use the copilot.",
            code=ErrorCode.UNAUTHORIZED, status_code=401,
        )

    client = anthropic.Anthropic(api_key=api_key)
    try:
        msg = client.messages.create(
            model=resolve_model(),
            max_tokens=MAX_TOKENS,
            system=[{
                "type": "text", "text": _system_prompt(),
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": _user_message(req)}],
        )
    except anthropic.AuthenticationError as e:
        raise MhpError("Anthropic rejected the API key.",
                       code=ErrorCode.UNAUTHORIZED, status_code=401) from e
    except anthropic.RateLimitError as e:
        raise MhpError("Rate limited by Anthropic. Retry shortly.",
                       code=ErrorCode.RATE_LIMITED, status_code=429) from e
    except anthropic.APIError as e:
        logger.warning("suggest-checks anthropic api error type=%s", type(e).__name__)
        raise MhpError("Anthropic API error — check the logs.",
                       code=ErrorCode.UPSTREAM_FAILED, status_code=502) from e

    raw_text = "".join(
        getattr(b, "text", "") for b in msg.content
        if getattr(b, "type", "") == "text"
    )
    parsed = _extract_json(raw_text)
    raw_checks = parsed.get("checks")
    if not isinstance(raw_checks, list):
        raw_checks = []

    checks = suggested_checks.normalize_checks(raw_checks, default_target=req.target)
    return SuggestChecksResponse(checks=[SuggestedCheck(**c) for c in checks])
