"""Claude-powered chat that explains HackingPal tool output to the user.

Streams responses via SSE. The system prompt (large, stable) is prompt-cached;
per-turn user messages carry a snapshot of recent tool results from the
frontend's session log so Claude can answer "what does this scan mean".
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Literal

import anthropic
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from lib.auth import require_local_auth
from lib.platform_util import app_data_dir
from .settings import keychain_get

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["chat"],
                   dependencies=[Depends(require_local_auth)])

# ── Defaults + persisted chat settings ──────────────────────────────────────

# Sonnet is the default — ~3-4× faster than Opus, plenty smart for explaining
# scan output. Override via env var or the /chat/settings endpoint (which
# writes chat_settings.json to the per-user app data dir).
DEFAULT_MODEL = "claude-sonnet-4-6"
ALLOWED_MODELS = (
    "claude-opus-4-7",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
)

# System prompt lives in backend/prompts/assistant.md by default so it can be
# edited without recompiling the sidecar. Override path via
# MHP_CHAT_SYSTEM_PROMPT_FILE, or supply a raw prompt via MHP_CHAT_SYSTEM_PROMPT.
def _default_prompts_dir() -> Path:
    # Inside a PyInstaller bundle the prompts/ folder ships alongside the
    # bundled modules at sys._MEIPASS. Outside the bundle (dev / pytest) the
    # repo layout is backend/routers/chat.py + backend/prompts/.
    import sys as _sys
    meipass = getattr(_sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass) / "prompts"
    return Path(__file__).resolve().parent.parent / "prompts"


_PROMPTS_DIR = _default_prompts_dir()
DEFAULT_PROMPT_PATH = _PROMPTS_DIR / "assistant.md"


def _settings_path() -> Path:
    return app_data_dir() / "chat_settings.json"


def _load_settings() -> dict[str, Any]:
    p = _settings_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        logger.exception("failed to read chat_settings.json")
        return {}


def _save_settings(data: dict[str, Any]) -> None:
    _settings_path().write_text(json.dumps(data, indent=2))


def resolve_model() -> str:
    env = os.getenv("MHP_CHAT_MODEL", "").strip()
    if env:
        return env
    stored = _load_settings().get("model")
    if isinstance(stored, str) and stored.strip():
        return stored.strip()
    return DEFAULT_MODEL


def _read_prompt_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception("failed to read prompt file %s", path)
        return None


def resolve_system_prompt() -> str:
    raw = os.getenv("MHP_CHAT_SYSTEM_PROMPT", "").strip()
    if raw:
        return raw
    path_env = os.getenv("MHP_CHAT_SYSTEM_PROMPT_FILE", "").strip()
    if path_env:
        loaded = _read_prompt_file(Path(path_env))
        if loaded is not None:
            return loaded
        logger.warning("MHP_CHAT_SYSTEM_PROMPT_FILE %s unreadable; falling back", path_env)
    loaded = _read_prompt_file(DEFAULT_PROMPT_PATH)
    if loaded is not None:
        return loaded
    # Last-ditch fallback so the chat never crashes if the file goes missing.
    return "You are the in-app assistant for HackingPal."


# Provider selection.
#
# - "anthropic"  → direct Anthropic SDK call, requires Anthropic API key in Keychain.
# - "claude-cli" → shells out to the local `claude` CLI in headless `-p` mode,
#                  uses the user's Claude Code login (no API key needed).
#
# Override via MHP_AI_PROVIDER env var. Default: claude-cli when no API key is
# configured AND the CLI is on PATH; anthropic otherwise.
CLAUDE_BIN = os.getenv("MHP_CLAUDE_BIN", "claude")

# CLI cold-start timeout (seconds). If the CLI produces no output by this point
# we assume something's wrong (e.g. credit exhaustion, no network) and emit a
# concrete error rather than letting the request hang forever.
CLI_FIRST_BYTE_TIMEOUT_SEC = 90


def _resolve_provider() -> str:
    override = os.getenv("MHP_AI_PROVIDER", "").strip().lower()
    if override in ("anthropic", "claude-cli"):
        return override
    if keychain_get() is None and shutil.which(CLAUDE_BIN) is not None:
        return "claude-cli"
    return "anthropic"



class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class SessionLogEntry(BaseModel):
    ts: str  # ISO timestamp from the frontend
    category: str
    summary: str  # short string; full JSON tail


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(..., min_length=1)
    session_log: list[SessionLogEntry] = Field(default_factory=list)
    active_page: str | None = None


def build_user_prefix(req: ChatRequest) -> str:
    """Build the per-turn context block prepended to the latest user message."""
    parts: list[str] = []
    if req.active_page:
        parts.append(f"**Current page:** {req.active_page}")
    if req.session_log:
        parts.append("**Recent tool activity in this session** "
                     "(most recent last; truncated):")
        for e in req.session_log[-30:]:
            parts.append(f"- [{e.ts}] {e.category}: {e.summary}")
    if not parts:
        return ""
    return "\n".join(parts) + "\n\n---\n\n"


def sse_event(data: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(data)}\n\n".encode()


@router.get("/config")
def chat_config() -> dict[str, Any]:
    """Tells the frontend whether the chat is usable + which provider is active."""
    key_present = keychain_get() is not None
    cli_present = shutil.which(CLAUDE_BIN) is not None
    provider = _resolve_provider()
    return {
        "key_present": key_present,
        "model": resolve_model(),
        "provider": provider,
        "cli_present": cli_present,
        "usable": (provider == "anthropic" and key_present)
                  or (provider == "claude-cli" and cli_present),
    }


# ── Persisted settings endpoints ────────────────────────────────────────────


class ChatSettings(BaseModel):
    model: str
    available_models: list[str]
    system_prompt: str
    system_prompt_path: str | None
    system_prompt_editable: bool


class ChatSettingsUpdate(BaseModel):
    model: str | None = Field(default=None)
    system_prompt: str | None = Field(default=None)


def _system_prompt_path_for_settings() -> Path | None:
    raw = os.getenv("MHP_CHAT_SYSTEM_PROMPT", "").strip()
    if raw:
        return None
    path_env = os.getenv("MHP_CHAT_SYSTEM_PROMPT_FILE", "").strip()
    if path_env:
        return Path(path_env)
    return DEFAULT_PROMPT_PATH


@router.get("/settings", response_model=ChatSettings, dependencies=[Depends(require_local_auth)])
def get_chat_settings() -> ChatSettings:
    path = _system_prompt_path_for_settings()
    return ChatSettings(
        model=resolve_model(),
        available_models=list(ALLOWED_MODELS),
        system_prompt=resolve_system_prompt(),
        system_prompt_path=str(path) if path else None,
        # Editable when we have a real file path (not the raw env var case).
        system_prompt_editable=path is not None,
    )


@router.put("/settings", response_model=ChatSettings, dependencies=[Depends(require_local_auth)])
def update_chat_settings(body: ChatSettingsUpdate) -> ChatSettings:
    if body.model is not None:
        if body.model not in ALLOWED_MODELS:
            raise HTTPException(400, f"Model must be one of {ALLOWED_MODELS}")
        settings = _load_settings()
        settings["model"] = body.model
        _save_settings(settings)
    if body.system_prompt is not None:
        path = _system_prompt_path_for_settings()
        if path is None:
            raise HTTPException(
                400,
                "System prompt is locked because MHP_CHAT_SYSTEM_PROMPT env var is set.",
            )
        # Ensure parent dir exists before write.
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body.system_prompt, encoding="utf-8")
    return get_chat_settings()


@router.post("/stream")
def chat_stream(req: ChatRequest) -> StreamingResponse:
    if _resolve_provider() == "claude-cli":
        return _stream_via_cli(req)
    return _stream_via_anthropic(req)


def _stream_via_anthropic(req: ChatRequest) -> StreamingResponse:
    api_key = keychain_get()
    if not api_key:
        raise HTTPException(401, "Anthropic API key not set. Add one in Settings.")

    client = anthropic.Anthropic(api_key=api_key)

    # Convert messages, prepending session-log context to the LAST user message
    # only. Earlier turns already saw their own context; re-injecting on every
    # turn would balloon the prompt and break caching of the trailing prefix.
    api_messages: list[dict[str, Any]] = []
    last_user_idx = len(req.messages) - 1
    while last_user_idx >= 0 and req.messages[last_user_idx].role != "user":
        last_user_idx -= 1

    for i, m in enumerate(req.messages):
        if i == last_user_idx:
            prefix = build_user_prefix(req)
            api_messages.append({
                "role": m.role,
                "content": prefix + m.content if prefix else m.content,
            })
        else:
            api_messages.append({"role": m.role, "content": m.content})

    model_name = resolve_model()
    system_prompt = resolve_system_prompt()

    def gen():
        try:
            with client.messages.stream(
                model=model_name,
                max_tokens=4096,
                # Adaptive thinking with summarized display so a "thinking…"
                # state can show on long answers without surfacing raw CoT.
                thinking={"type": "adaptive", "display": "summarized"},
                system=[{
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=api_messages,
            ) as stream:
                for event in stream:
                    if event.type == "content_block_start":
                        if event.content_block.type == "thinking":
                            yield sse_event({"type": "thinking_start"})
                        elif event.content_block.type == "text":
                            yield sse_event({"type": "text_start"})
                    elif event.type == "content_block_delta":
                        if event.delta.type == "thinking_delta":
                            yield sse_event({
                                "type": "thinking_delta",
                                "text": event.delta.thinking,
                            })
                        elif event.delta.type == "text_delta":
                            yield sse_event({
                                "type": "text_delta",
                                "text": event.delta.text,
                            })

                final = stream.get_final_message()
                yield sse_event({
                    "type": "done",
                    "stop_reason": final.stop_reason,
                    "usage": {
                        "input_tokens": final.usage.input_tokens,
                        "output_tokens": final.usage.output_tokens,
                        "cache_read": getattr(
                            final.usage, "cache_read_input_tokens", 0),
                        "cache_creation": getattr(
                            final.usage, "cache_creation_input_tokens", 0),
                    },
                })
        except anthropic.AuthenticationError:
            yield sse_event({"type": "error",
                             "detail": "Anthropic rejected the API key. "
                                       "Check it in Settings."})
        except anthropic.RateLimitError:
            yield sse_event({"type": "error",
                             "detail": "Rate limited by Anthropic. Retry shortly."})
        except anthropic.APIError as e:
            logger.warning("anthropic api error type=%s", type(e).__name__)
            yield sse_event({"type": "error",
                             "detail": "Anthropic API error — check the logs"})
        except Exception as e:
            logger.exception("chat stream failed")
            yield sse_event({"type": "error",
                             "detail": f"Chat stream failed ({type(e).__name__})"})

    return StreamingResponse(gen(), media_type="text/event-stream")


# ── claude-cli provider ──────────────────────────────────────────────────────
#
# Spawns the local `claude` CLI in headless print mode and re-emits its
# stream-json output as the same SSE events the frontend already consumes.
# Tools are disabled (`--tools ""`) and the system prompt is fully replaced
# so Claude Code's default agentic context doesn't bleed in. Session
# persistence is off so the user's ~/.claude/projects history isn't polluted.


def _render_conversation(req: ChatRequest) -> str:
    """Render the conversation history + current turn as a single prompt string.

    The CLI's `-p` mode takes one prompt, so multi-turn is achieved by
    inlining prior turns. The current user message gets the session-log
    prefix prepended (same shape as the Anthropic SDK path)."""
    last_user_idx = len(req.messages) - 1
    while last_user_idx >= 0 and req.messages[last_user_idx].role != "user":
        last_user_idx -= 1

    history: list[str] = []
    for i, m in enumerate(req.messages):
        if i >= last_user_idx:
            continue
        speaker = "User" if m.role == "user" else "Assistant"
        history.append(f"{speaker}: {m.content}")

    prefix = build_user_prefix(req)
    current = (prefix + req.messages[last_user_idx].content) if last_user_idx >= 0 else ""

    if history:
        return (
            "<previous_conversation>\n"
            + "\n\n".join(history)
            + "\n</previous_conversation>\n\n"
            + current
        )
    return current


def _stream_via_cli(req: ChatRequest) -> StreamingResponse:
    prompt = _render_conversation(req)
    system_prompt = resolve_system_prompt()

    cmd = [
        CLAUDE_BIN,
        "-p",
        "--system-prompt", system_prompt,
        "--tools", "",
        "--no-session-persistence",
        "--output-format", "stream-json",
        "--include-partial-messages",
        "--verbose",
    ]

    def gen():
        import selectors
        import time
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            if proc.stdin is not None:
                proc.stdin.write(prompt)
                proc.stdin.close()

            text_started = False
            input_tokens = 0
            output_tokens = 0
            stop_reason = "end_turn"
            credits_blocked = False  # set true if CLI emits an "out_of_credits"
            rate_limited_msg: str | None = None

            assert proc.stdout is not None

            # Drain stdout via selector so we can apply a first-byte timeout.
            # Once anything has streamed, the original line-loop behavior is fine.
            sel = selectors.DefaultSelector()
            sel.register(proc.stdout, selectors.EVENT_READ)
            first_byte_seen = False
            t0 = time.monotonic()
            buffer = ""

            while True:
                events = sel.select(timeout=2.0)
                if not events:
                    if proc.poll() is not None:
                        # Process exited without producing more output.
                        break
                    if not first_byte_seen and (time.monotonic() - t0) > CLI_FIRST_BYTE_TIMEOUT_SEC:
                        try: proc.kill()
                        except Exception: pass
                        yield sse_event({
                            "type": "error",
                            "detail": (
                                f"claude CLI gave no output in {CLI_FIRST_BYTE_TIMEOUT_SEC}s. "
                                "Likely out of Claude Code credits — add an Anthropic API "
                                "key in Settings to use the SDK directly."
                            ),
                        })
                        return
                    continue

                chunk = proc.stdout.read1() if hasattr(proc.stdout, "read1") else proc.stdout.readline()
                if not chunk:
                    if proc.poll() is not None:
                        break
                    continue
                first_byte_seen = True
                buffer += chunk
                while "\n" in buffer:
                    raw_line, buffer = buffer.split("\n", 1)
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    etype = evt.get("type")
                    if etype == "stream_event":
                        inner = evt.get("event", {}) or {}
                        if inner.get("type") == "content_block_delta":
                            delta = inner.get("delta", {}) or {}
                            if delta.get("type") == "text_delta":
                                text = delta.get("text", "")
                                if text:
                                    if not text_started:
                                        yield sse_event({"type": "text_start"})
                                        text_started = True
                                    yield sse_event({
                                        "type": "text_delta",
                                        "text": text,
                                    })
                    elif etype == "result":
                        usage = evt.get("usage", {}) or {}
                        input_tokens = int(usage.get("input_tokens", 0) or 0)
                        output_tokens = int(usage.get("output_tokens", 0) or 0)
                        if evt.get("subtype") and evt["subtype"] != "success":
                            stop_reason = str(evt["subtype"])
                    elif etype == "rate_limit_event":
                        info = evt.get("rate_limit_info", {}) or {}
                        # CLI's stream-json emits this even on success ("status":"allowed").
                        # We only flag it as a hard error when the user is *blocked* —
                        # i.e. overage rejected because of exhausted credits.
                        overage = (info.get("overageStatus") or "").lower()
                        reason = (info.get("overageDisabledReason") or "").lower()
                        status = (info.get("status") or "").lower()
                        if status == "blocked" or reason == "out_of_credits":
                            credits_blocked = True
                            rate_limited_msg = (
                                "Claude Code subscription is out of credits "
                                f"(reset {info.get('resetsAt')}). "
                                "Add an Anthropic API key in Settings to use the SDK directly."
                            )

            rc = proc.wait()
            if credits_blocked and not text_started:
                yield sse_event({"type": "error",
                                 "detail": rate_limited_msg
                                           or "Claude Code subscription is out of credits."})
                return
            if rc != 0:
                err = (proc.stderr.read() if proc.stderr else "")[:500]
                logger.warning("claude CLI exited %d: %s", rc, err)
                yield sse_event({
                    "type": "error",
                    "detail": f"claude CLI exited {rc}. {err}".strip(),
                })
                return

            yield sse_event({
                "type": "done",
                "stop_reason": stop_reason,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cache_read": 0,
                    "cache_creation": 0,
                },
            })
        except FileNotFoundError:
            yield sse_event({
                "type": "error",
                "detail": f"`{CLAUDE_BIN}` not found on PATH. Install Claude Code or "
                          "set MHP_AI_PROVIDER=anthropic with an API key.",
            })
        except Exception as e:
            logger.exception("claude-cli stream failed")
            yield sse_event({
                "type": "error",
                "detail": f"Chat stream failed ({type(e).__name__})",
            })
            if proc and proc.poll() is None:
                try: proc.kill()
                except Exception: pass

    return StreamingResponse(gen(), media_type="text/event-stream")
