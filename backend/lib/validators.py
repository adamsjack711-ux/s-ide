"""Input validators for hostnames, IPs, URLs, domains, and ports.

Use these as the first line of defence on every endpoint that takes
network-shaped input. Each validator:

- Strips leading/trailing whitespace before checking anything.
- Enforces a maximum length (rejects pathological input before regex work).
- Validates format with stdlib + a tight regex — no DNS lookups here, that
  belongs in `target_policy.check_target`.
- Returns the *normalised* value (lowercased, trailing-dot stripped, etc).
- Raises `MhpError` with a precise `ErrorCode` on failure, so the global
  handler turns it into a clean 400 with the right `code`.

These functions are designed to be called from pydantic `field_validator`s
*and* directly from path-parameter handlers — both forms convert MhpError
into a clean envelope thanks to the global exception handler.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .errors import ErrorCode, MhpError

# ── Limits ──────────────────────────────────────────────────────────────────
MAX_HOSTNAME_LEN = 253       # RFC 1035 §2.3.4
MAX_DOMAIN_LEN   = 253
MAX_LABEL_LEN    = 63        # RFC 1035 §2.3.4
MAX_URL_LEN      = 2048      # de-facto browser limit
MAX_IP_LEN       = 45        # IPv6 textual max ("...::ffff:192.168.0.1" with zone-id)
MAX_TARGET_LEN   = 253       # generic "target" field — host or IP

# Hostname label: alnum + hyphen + underscore (for _dmarc, _srv, etc.); hyphen
# not at start or end of a label. Length enforced separately.
_LABEL = r"(?!-)(?:[A-Za-z0-9_-]{1,63})(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
# Domain must have at least one dot (i.e. at least two labels).
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
# Cheap pre-filter: if a string looks like it might be an IP literal we let
# ipaddress decide rather than the hostname regex.
_IP_LITERAL_RE = re.compile(r"^[0-9.:a-fA-F]+$")


def _require(value: str | None, *, field: str, code: ErrorCode) -> str:
    if value is None:
        raise MhpError(f"{field} is required", code=code)
    s = value.strip()
    if not s:
        raise MhpError(f"{field} is required", code=code)
    return s


# ── IP ──────────────────────────────────────────────────────────────────────

def validate_ip(
    value: str,
    *,
    field: str = "ip",
    version: int | None = None,
) -> str:
    """Validate an IPv4 or IPv6 literal. Returns the normalised form."""
    s = _require(value, field=field, code=ErrorCode.INVALID_IP)
    if len(s) > MAX_IP_LEN:
        raise MhpError(
            f"{field} is too long (max {MAX_IP_LEN} chars)",
            code=ErrorCode.INVALID_IP,
        )
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        raise MhpError(
            f"{field} is not a valid IP address",
            code=ErrorCode.INVALID_IP,
        ) from None
    if version is not None and addr.version != version:
        raise MhpError(
            f"{field} must be IPv{version}",
            code=ErrorCode.INVALID_IP,
        )
    return str(addr)


# ── Hostname (accepts IP literals by default) ───────────────────────────────

def validate_hostname(
    value: str,
    *,
    field: str = "hostname",
    allow_ip: bool = True,
) -> str:
    """Validate a DNS hostname. Accepts IP literals by default.

    Returns the lowercased, trailing-dot-stripped value.
    """
    s = _require(value, field=field, code=ErrorCode.INVALID_HOSTNAME).rstrip(".")
    if not s:
        raise MhpError(f"{field} is required", code=ErrorCode.INVALID_HOSTNAME)
    if len(s) > MAX_HOSTNAME_LEN:
        raise MhpError(
            f"{field} is too long (max {MAX_HOSTNAME_LEN} chars)",
            code=ErrorCode.INVALID_HOSTNAME,
        )
    # Try IP literal first — bare IPs are valid hostnames for our scanners.
    if _IP_LITERAL_RE.match(s):
        try:
            return str(ipaddress.ip_address(s)) if allow_ip else _reject_ip(field)
        except ValueError:
            # Not actually an IP — fall through to hostname regex.
            pass
    if not _HOSTNAME_RE.match(s):
        raise MhpError(
            f"{field} is not a valid hostname",
            code=ErrorCode.INVALID_HOSTNAME,
        )
    # Reject any single label longer than 63 chars (regex already enforces this
    # via {1,63}, but double-check after rstrip).
    for label in s.split("."):
        if len(label) > MAX_LABEL_LEN:
            raise MhpError(
                f"{field} has a label longer than {MAX_LABEL_LEN} chars",
                code=ErrorCode.INVALID_HOSTNAME,
            )
    return s.lower()


def _reject_ip(field: str) -> str:
    raise MhpError(
        f"{field} must be a hostname, not an IP address",
        code=ErrorCode.INVALID_HOSTNAME,
    )


# ── Domain (requires at least one dot) ──────────────────────────────────────

def validate_domain(value: str, *, field: str = "domain") -> str:
    """Validate a fully-qualified domain name. Returns lowercased value.

    Stricter than `validate_hostname`: must have at least one dot (so
    "example.com" passes, "localhost" does not), and does not accept IP
    literals.
    """
    s = _require(value, field=field, code=ErrorCode.INVALID_DOMAIN).rstrip(".").lower()
    if not s:
        raise MhpError(f"{field} is required", code=ErrorCode.INVALID_DOMAIN)
    if len(s) > MAX_DOMAIN_LEN:
        raise MhpError(
            f"{field} is too long (max {MAX_DOMAIN_LEN} chars)",
            code=ErrorCode.INVALID_DOMAIN,
        )
    if "." not in s:
        raise MhpError(
            f"{field} must include a top-level domain (e.g. example.com)",
            code=ErrorCode.INVALID_DOMAIN,
        )
    if not _DOMAIN_RE.match(s):
        raise MhpError(
            f"{field} is not a valid domain",
            code=ErrorCode.INVALID_DOMAIN,
        )
    return s


# ── URL ─────────────────────────────────────────────────────────────────────

def validate_url(
    value: str,
    *,
    field: str = "url",
    schemes: tuple[str, ...] = ("http", "https"),
    require_host: bool = True,
) -> str:
    """Validate a URL. Returns the trimmed value (not re-serialised)."""
    s = _require(value, field=field, code=ErrorCode.INVALID_URL)
    if len(s) > MAX_URL_LEN:
        raise MhpError(
            f"{field} is too long (max {MAX_URL_LEN} chars)",
            code=ErrorCode.INVALID_URL,
        )
    try:
        parsed = urlparse(s)
    except ValueError:
        raise MhpError(f"{field} is malformed", code=ErrorCode.INVALID_URL) from None
    scheme = (parsed.scheme or "").lower()
    if scheme not in schemes:
        raise MhpError(
            f"{field} must use one of: {', '.join(schemes)}",
            code=ErrorCode.INVALID_URL,
        )
    if require_host:
        host = parsed.hostname or ""
        if not host:
            raise MhpError(f"{field} is missing a host", code=ErrorCode.INVALID_URL)
        try:
            validate_hostname(host, field=f"{field} host")
        except MhpError:
            raise MhpError(
                f"{field} has an invalid host",
                code=ErrorCode.INVALID_URL,
            ) from None
    # urlparse defers port parsing until `.port` is accessed — force it
    # here so a malformed port (e.g. "https://x:alert(1)") fails validation
    # rather than blowing up downstream.
    try:
        _ = parsed.port
    except ValueError:
        raise MhpError(
            f"{field} has a malformed port",
            code=ErrorCode.INVALID_URL,
        ) from None
    return s


# ── Port ────────────────────────────────────────────────────────────────────

def validate_port(value: int | str, *, field: str = "port") -> int:
    """Validate a TCP/UDP port number. Returns the int."""
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise MhpError(
            f"{field} must be a number",
            code=ErrorCode.INVALID_PORT,
        ) from None
    if not 1 <= n <= 65535:
        raise MhpError(
            f"{field} must be between 1 and 65535",
            code=ErrorCode.INVALID_PORT,
        )
    return n


# ── Target — "host or IP", the common shape across most red/blue tools ──────

def validate_target(value: str, *, field: str = "target") -> str:
    """Validate a generic scan target — hostname OR IP literal.

    Equivalent to `validate_hostname` with `allow_ip=True` and a slightly
    different error label.
    """
    return validate_hostname(value, field=field, allow_ip=True)
