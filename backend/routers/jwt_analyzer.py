"""JWT analyzer.

REST  POST /jwt/decode  body { "token": "...", "weak_secrets"?: bool }

Splits the token, base64-decodes header + payload, surfaces algorithm and
claims, and flags common red flags:
  - alg = none
  - alg = HS256 with a key in a small weak-key dictionary
  - expired (exp in past)
  - no exp claim
  - iat in the future (clock-skew or tampered)
  - kid path traversal (../../...)
  - missing iss / aud
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from lib import hids_notify

router = APIRouter(tags=["jwt"])


WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test", "changeme",
    "your-256-bit-secret", "your-secret", "jwt-secret", "jwt_secret",
    "supersecret", "topsecret", "key", "private", "default",
    "qwerty", "letmein", "hello", "abc123", "iloveyou",
    "0", "00000000", "1234567890",
]


class JwtRequest(BaseModel):
    token: str
    weak_secrets: bool = True


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _try_decode_json(b: bytes) -> dict[str, Any] | None:
    try:
        return json.loads(b)
    except Exception:
        return None


def _format_ts(v: Any) -> str:
    if not isinstance(v, (int, float)):
        return ""
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
    except (OSError, ValueError):
        return ""


def _hs_verify(signing_input: bytes, signature: bytes, secret: str, alg: str) -> bool:
    digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    h = digest_map.get(alg)
    if not h:
        return False
    mac = hmac.new(secret.encode("utf-8"), signing_input, h).digest()
    return hmac.compare_digest(mac, signature)


@router.post("/jwt/decode")
async def jwt_decode(req: JwtRequest) -> dict[str, Any]:
    token = req.token.strip()
    # Strip a literal "Bearer " prefix if present (case-insensitive).
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        raise HTTPException(status_code=400, detail="token is required")

    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise HTTPException(status_code=400,
                            detail=f"not a JWT (expected 2-3 dot-separated parts, got {len(parts)})")
    header_b64, payload_b64 = parts[0], parts[1]
    sig_b64 = parts[2] if len(parts) == 3 else ""

    try:
        header_bytes = _b64url_decode(header_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"bad header b64: {exc}")
    try:
        payload_bytes = _b64url_decode(payload_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"bad payload b64: {exc}")
    try:
        sig_bytes = _b64url_decode(sig_b64) if sig_b64 else b""
    except Exception:
        sig_bytes = b""

    header = _try_decode_json(header_bytes) or {}
    payload = _try_decode_json(payload_bytes) or {}

    alg = str(header.get("alg", "")).upper()
    typ = header.get("typ", "")
    kid = header.get("kid", "")

    now = time.time()
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    findings: list[dict[str, Any]] = []
    weak_match: dict[str, Any] | None = None

    if alg == "NONE":
        findings.append({"severity": "high", "label": "alg=none",
                         "detail": "Token is unsigned — accepting it would be a critical vuln"})

    if not exp:
        findings.append({"severity": "warn", "label": "No exp claim",
                         "detail": "Token has no expiry"})
    elif isinstance(exp, (int, float)) and exp < now:
        findings.append({"severity": "warn", "label": "Token expired",
                         "detail": f"exp was {_format_ts(exp)} ({int(now - exp)}s ago)"})

    if isinstance(iat, (int, float)) and iat > now + 300:
        findings.append({"severity": "warn", "label": "iat in the future",
                         "detail": f"iat={_format_ts(iat)} — clock skew or tampered"})

    if isinstance(nbf, (int, float)) and nbf > now:
        findings.append({"severity": "info", "label": "nbf in the future",
                         "detail": f"Not valid until {_format_ts(nbf)}"})

    if kid and ("/" in kid or ".." in kid or kid.startswith("..")):
        findings.append({"severity": "high", "label": "Suspicious kid header",
                         "detail": f"kid={kid!r} looks like a path traversal attempt"})

    if "iss" not in payload:
        findings.append({"severity": "info", "label": "No iss claim",
                         "detail": "Issuer claim missing"})
    if "aud" not in payload:
        findings.append({"severity": "info", "label": "No aud claim",
                         "detail": "Audience claim missing"})

    # Weak-secret dictionary attack (only for HS*)
    if req.weak_secrets and alg in ("HS256", "HS384", "HS512") and sig_bytes:
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        for secret in WEAK_SECRETS:
            if _hs_verify(signing_input, sig_bytes, secret, alg):
                weak_match = {"secret": secret, "alg": alg}
                findings.append({
                    "severity": "high", "label": "Weak HMAC secret",
                    "detail": f"Signature verifies with the trivial secret {secret!r}",
                })
                break

    if weak_match:
        await hids_notify.notify(
            "critical", "jwt",
            f"JWT signed with weak secret {weak_match['secret']!r}",
            {"alg": alg, "secret": weak_match["secret"]},
        )

    return {
        "header": header,
        "payload": payload,
        "alg": alg, "typ": typ, "kid": kid,
        "signature_present": bool(sig_bytes),
        "claims_meta": {
            "exp_iso": _format_ts(exp) if exp else "",
            "iat_iso": _format_ts(iat) if iat else "",
            "nbf_iso": _format_ts(nbf) if nbf else "",
            "expired": isinstance(exp, (int, float)) and exp < now,
        },
        "weak_secret_match": weak_match,
        "findings": findings,
    }
