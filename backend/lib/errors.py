"""Error envelope, error codes, and global FastAPI exception handlers.

Every endpoint that fails should produce a body of the shape:

    {"error": "human-readable message", "code": "ERROR_CODE", ...optional extras}

Routers should raise `MhpError(...)` (or a plain `HTTPException` if the
existing semantics suffice — the handler below normalises both into the
same envelope). Unhandled exceptions are caught and reported as a generic
500/INTERNAL without ever leaking a stack trace to the frontend; the full
traceback is logged server-side.

WebSocket frames don't go through FastAPI's exception machinery, so each
WS router builds its own error frame. Use `ws_error(...)` for that — it
emits the same shape plus the legacy `type:"error"` discriminator and a
`detail` alias for older frontend pages that haven't migrated yet.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("s-ide.errors")


class ErrorCode(str, Enum):
    # 4xx — caller's fault
    BAD_REQUEST       = "BAD_REQUEST"
    VALIDATION_ERROR  = "VALIDATION_ERROR"
    INVALID_TARGET    = "INVALID_TARGET"
    INVALID_HOSTNAME  = "INVALID_HOSTNAME"
    INVALID_IP        = "INVALID_IP"
    INVALID_URL       = "INVALID_URL"
    INVALID_DOMAIN    = "INVALID_DOMAIN"
    INVALID_PORT      = "INVALID_PORT"
    INVALID_RANGE     = "INVALID_RANGE"
    TARGET_DENIED     = "TARGET_DENIED"
    NEED_CONFIRM      = "NEED_CONFIRM"
    NOT_FOUND         = "NOT_FOUND"
    RESOLVE_FAILED    = "RESOLVE_FAILED"
    UNAUTHORIZED      = "UNAUTHORIZED"
    FORBIDDEN         = "FORBIDDEN"
    CONFLICT          = "CONFLICT"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    RATE_LIMITED      = "RATE_LIMITED"
    # 5xx — our fault
    INTERNAL          = "INTERNAL"
    TIMEOUT           = "TIMEOUT"
    TOOL_MISSING      = "TOOL_MISSING"
    TOOL_FAILED       = "TOOL_FAILED"
    UPSTREAM_FAILED   = "UPSTREAM_FAILED"
    UNSUPPORTED       = "UNSUPPORTED"
    NOT_IMPLEMENTED   = "NOT_IMPLEMENTED"


class MhpError(Exception):
    """Application-level error.

    Routers raise this instead of `HTTPException` when they want to attach
    an explicit error code or extra metadata. The global handler turns it
    into the standard envelope shape and logs at WARNING — *not* ERROR,
    because by definition we expected this branch.
    """

    def __init__(
        self,
        message: str,
        *,
        code: "ErrorCode | str" = ErrorCode.BAD_REQUEST,
        status_code: int = 400,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code.value if isinstance(code, ErrorCode) else str(code)
        self.status_code = status_code
        self.extra = extra or {}


# ── Default code / message lookups ──────────────────────────────────────────

_DEFAULT_CODES: dict[int, ErrorCode] = {
    400: ErrorCode.BAD_REQUEST,
    401: ErrorCode.UNAUTHORIZED,
    403: ErrorCode.FORBIDDEN,
    404: ErrorCode.NOT_FOUND,
    409: ErrorCode.CONFLICT,
    413: ErrorCode.PAYLOAD_TOO_LARGE,
    422: ErrorCode.VALIDATION_ERROR,
    429: ErrorCode.RATE_LIMITED,
    500: ErrorCode.INTERNAL,
    501: ErrorCode.UNSUPPORTED,
    503: ErrorCode.UPSTREAM_FAILED,
    504: ErrorCode.TIMEOUT,
}

_DEFAULT_MESSAGES: dict[int, str] = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    409: "Conflict",
    413: "Payload too large",
    422: "Validation error",
    429: "Too many requests",
    500: "Internal server error",
    501: "Not implemented",
    503: "Upstream service unavailable",
    504: "Timeout",
}


def _default_code(status_code: int) -> str:
    return _DEFAULT_CODES.get(status_code, ErrorCode.INTERNAL).value


def _default_message(status_code: int) -> str:
    return _DEFAULT_MESSAGES.get(status_code, "Error")


def _envelope(
    message: str, code: str, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"error": message, "code": code}
    if extra:
        # Don't let extras overwrite the canonical fields
        for k, v in extra.items():
            if k not in ("error", "code"):
                body[k] = v
    return body


# ── Public helpers ──────────────────────────────────────────────────────────

def ws_error(
    code: "ErrorCode | str",
    message: str,
    **extra: Any,
) -> dict[str, Any]:
    """Build a WebSocket error frame in the canonical shape.

    Keeps the legacy `type:"error"` discriminator and a `detail` alias so
    pages that haven't been migrated still surface the message.
    """
    code_str = code.value if isinstance(code, ErrorCode) else str(code)
    frame: dict[str, Any] = {
        "type": "error",
        "error": message,
        "code": code_str,
        "detail": message,
    }
    for k, v in extra.items():
        if k not in frame:
            frame[k] = v
    return frame


def install_handlers(app: FastAPI) -> None:
    """Register all global exception handlers on the FastAPI app."""

    @app.exception_handler(MhpError)
    async def mhp_error_handler(request: Request, exc: MhpError) -> JSONResponse:
        logger.warning(
            "mhp_error path=%s status=%s code=%s msg=%s",
            request.url.path, exc.status_code, exc.code, exc.message,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(exc.message, exc.code, exc.extra),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        # FastAPI's HTTPException.detail may be a str, dict, or anything JSON-able.
        # Translate to the {error, code} envelope while preserving any extras
        # the caller put on a dict-shaped detail (need_confirm, target, etc.).
        if isinstance(exc.detail, dict):
            msg = str(
                exc.detail.get("reason")
                or exc.detail.get("message")
                or exc.detail.get("error")
                or _default_message(exc.status_code)
            )
            code = str(exc.detail.get("code") or _default_code(exc.status_code))
            extra = {
                k: v for k, v in exc.detail.items()
                if k not in ("reason", "message", "error", "code")
            }
        else:
            msg = str(exc.detail) if exc.detail else _default_message(exc.status_code)
            code = _default_code(exc.status_code)
            extra = {}
        logger.info(
            "http_exception path=%s status=%s code=%s msg=%s",
            request.url.path, exc.status_code, code, msg,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(msg, code, extra),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = exc.errors()
        first = errors[0] if errors else {"msg": "validation error", "loc": []}
        loc_parts = [str(p) for p in (first.get("loc") or [])[1:]]
        loc = ".".join(loc_parts)
        msg = (
            f"{loc}: {first.get('msg', 'invalid')}"
            if loc
            else str(first.get("msg", "validation error"))
        )
        logger.info(
            "validation_error path=%s msg=%s field_count=%s",
            request.url.path, msg, len(errors),
        )
        # Strip the `ctx` field on each error — it sometimes contains
        # un-JSON-serializable objects (pydantic shoves the raw exc in there).
        safe_errors = [
            {k: v for k, v in e.items() if k != "ctx"} for e in errors
        ]
        return JSONResponse(
            status_code=422,
            content=_envelope(
                msg,
                ErrorCode.VALIDATION_ERROR.value,
                {"fields": safe_errors},
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        # Full traceback in the server log, generic envelope to the client.
        logger.exception(
            "unhandled_exception path=%s exc_type=%s",
            request.url.path, type(exc).__name__,
        )
        return JSONResponse(
            status_code=500,
            content=_envelope(
                "Internal server error",
                ErrorCode.INTERNAL.value,
            ),
        )
