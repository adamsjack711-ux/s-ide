"""Fetch-time .side validator (mirror of frontend/src/themes/validate.ts).

Declarative-only schema + WCAG contrast floor + severity ΔE distinctness. Runs
at fetch so malformed/unsafe themes never enter the cache; the renderer
re-validates at apply (the authoritative gate).
"""
from __future__ import annotations

import math
import re
from typing import Any

from lib.theme_schema import (
    COLOR_TOKENS,
    FONT_TOKENS,
    HEX_RE,
    KIND,
    MUST_DEFINE,
    PROTECTED,
)

UNSAFE_RE = re.compile(r"[<>{}\\]|javascript:|url\s*\(|script|@import|expression\s*\(", re.I)

TEXT_FLOOR = 4.5
SECONDARY_FLOOR = 3.0
SEVERITY_FLOOR = 3.0
ACCENT_FLOOR = 3.0
DELTA_FLOOR = 15.0


def _rgb(hex_str: str) -> tuple[int, int, int]:
    h = hex_str.lstrip("#")
    n = int(h[:6], 16)
    return (n >> 16) & 255, (n >> 8) & 255, n & 255


def _lin(c: int) -> float:
    s = c / 255
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def _luminance(hex_str: str) -> float:
    r, g, b = _rgb(hex_str)
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast_ratio(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _lab(hex_str: str) -> tuple[float, float, float]:
    r, g, b = (_lin(c) for c in _rgb(hex_str))
    x = (r * 0.4124 + g * 0.3576 + b * 0.1805) / 0.95047
    y = r * 0.2126 + g * 0.7152 + b * 0.0722
    z = (r * 0.0193 + g * 0.1192 + b * 0.9505) / 1.08883

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116

    fx, fy, fz = f(x), f(y), f(z)
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def delta_e(a: str, b: str) -> float:
    l1, a1, b1 = _lab(a)
    l2, a2, b2 = _lab(b)
    return math.sqrt((l1 - l2) ** 2 + (a1 - a2) ** 2 + (b1 - b2) ** 2)


def validate_side(obj: Any) -> list[str]:
    """Return a list of validation errors (empty == valid).

    Envelope: {version, kind:"theme", name, author?, theme:{}}. version is
    mandatory; unknown TOP-LEVEL keys are rejected. Inside `theme`, unknown
    token keys are ignored (forward-compat) but every value is safety-scanned;
    known color tokens must be valid hex.
    """
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["theme must be a JSON object"]

    for k in obj:
        if k not in ("version", "kind", "name", "author", "theme"):
            errors.append(f"unexpected top-level key: {k}")
    if not isinstance(obj.get("version"), str) or not obj.get("version", "").strip():
        errors.append("version is required")
    if obj.get("kind") != KIND:
        errors.append(f'kind must be "{KIND}"')
    if not isinstance(obj.get("name"), str) or not obj.get("name"):
        errors.append("name is required")
    if obj.get("author") is not None and not isinstance(obj.get("author"), str):
        errors.append("author must be a string")

    tokens = obj.get("theme")
    if not isinstance(tokens, dict):
        errors.append("theme map is required")
        return errors

    for k, val in tokens.items():
        if not isinstance(val, str):
            errors.append(f"token {k} must be a string")
            continue
        if UNSAFE_RE.search(val):
            errors.append(f"token {k} contains disallowed content")
            continue
        if k in COLOR_TOKENS and not HEX_RE.match(val):
            errors.append(f"token {k} must be a hex color (got {val})")
        elif k not in COLOR_TOKENS and k not in FONT_TOKENS:
            pass  # unknown — ignored (forward-compat)
    for need in MUST_DEFINE:
        if need not in tokens:
            errors.append(f"required token missing: {need}")

    def hexv(k: str) -> str | None:
        v = tokens.get(k)
        return v if isinstance(v, str) and HEX_RE.match(v) else None

    base, surface = hexv("--bg-base"), hexv("--bg-surface")
    tp, ts, accent = hexv("--text-primary"), hexv("--text-secondary"), hexv("--accent")

    if tp and base and contrast_ratio(tp, base) < TEXT_FLOOR:
        errors.append(f"text-primary on bg-base contrast {contrast_ratio(tp, base):.2f} < {TEXT_FLOOR}")
    if tp and surface and contrast_ratio(tp, surface) < TEXT_FLOOR:
        errors.append(f"text-primary on bg-surface contrast {contrast_ratio(tp, surface):.2f} < {TEXT_FLOOR}")
    if ts and surface and contrast_ratio(ts, surface) < SECONDARY_FLOOR:
        errors.append(f"text-secondary on bg-surface contrast {contrast_ratio(ts, surface):.2f} < {SECONDARY_FLOOR}")
    if accent and base and contrast_ratio(accent, base) < ACCENT_FLOOR:
        errors.append(f"accent on bg-base contrast {contrast_ratio(accent, base):.2f} < {ACCENT_FLOOR}")

    sev = {k: hexv(k) for k in PROTECTED}
    for k, c in sev.items():
        if c and surface and contrast_ratio(c, surface) < SEVERITY_FLOOR:
            errors.append(f"{k} on bg-surface contrast {contrast_ratio(c, surface):.2f} < {SEVERITY_FLOOR}")
    keys = list(PROTECTED)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = sev[keys[i]], sev[keys[j]]
            if a and b and delta_e(a, b) < DELTA_FLOOR:
                errors.append(f"{keys[i]} and {keys[j]} are too similar (ΔE {delta_e(a, b):.1f} < {DELTA_FLOOR})")

    return errors
