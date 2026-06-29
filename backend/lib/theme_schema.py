"""Canonical .side token spec — mirror of frontend/src/themes/tokens.json.

The packaged backend can't read the frontend tree at runtime, so this is a
hand-maintained copy. Drift is caught by tests/test_theme_schema_parity.py,
which reads the JSON and asserts equality with these sets.
"""
from __future__ import annotations

import re

KIND = "theme"
HEX_RE = re.compile(r"^#([0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")

# Free-string (non-hex) tokens a theme may set.
FONT_TOKENS = ("--font-sans", "--font-mono")

REQUIRED = (
    "--bg-base",
    "--bg-surface",
    "--bg-elevated",
    "--bg-hover",
    "--bg-active",
    "--text-primary",
    "--text-secondary",
    "--text-muted",
    "--border",
    "--border-bright",
    "--accent",
)

PROTECTED = (
    "--critical",
    "--high",
    "--medium",
    "--low",
    "--success",
)

OPTIONAL = (
    "--accent-bright",
    "--accent-dim",
    "--accent-glow",
    "--text-accent",
    "--border-accent",
    "--critical-dim",
    "--high-dim",
    "--medium-dim",
    "--low-dim",
    "--success-dim",
    "--scrollbar-track",
    "--scrollbar-thumb",
    "--scrollbar-thumb-hover",
)

# Color tokens (hex-validated).
COLOR_TOKENS = frozenset(REQUIRED + PROTECTED + OPTIONAL)
MUST_DEFINE = REQUIRED + PROTECTED
