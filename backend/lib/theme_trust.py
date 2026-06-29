"""Theme trust — official vs community, anchored to the SOURCE URL only.

A theme is "official" iff its source URL lives under a project-controlled
prefix. This is never derived from anything inside the .side file (meta.author
is display-only and can claim anything), which is what kills the
"community theme masquerading as official" attack.
"""
from __future__ import annotations

# Project-controlled prefixes. The curated default manifest is hosted here too.
OFFICIAL_PREFIXES: tuple[str, ...] = (
    "https://github.com/s-ide/",
)


def is_official(url: str) -> bool:
    u = (url or "").strip().lower()
    return any(u.startswith(p.lower()) for p in OFFICIAL_PREFIXES)
