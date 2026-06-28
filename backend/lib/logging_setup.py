"""Centralised logger config. Call `configure()` once at app start.

We use a single-line `time level logger message` format so the sidecar
output stays grep-able in the Electron console and the Docker logs.
Modules then do:

    import logging
    logger = logging.getLogger(__name__)

…and `__name__` will inherit the level/handlers from the root logger.
"""
from __future__ import annotations

import logging
import os
import sys

_FMT = "%(asctime)s %(levelname)-7s %(name)s %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def configure(level: str | None = None) -> None:
    """Idempotent: safe to call from main.py and from tests."""
    lvl_name = (level or os.environ.get("MHP_LOG_LEVEL", "INFO")).upper()
    lvl = getattr(logging, lvl_name, logging.INFO)
    root = logging.getLogger()
    # Don't double-install if uvicorn / pytest already attached a handler.
    if not any(
        getattr(h, "_mhp_installed", False) for h in root.handlers
    ):
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter(_FMT, datefmt=_DATEFMT))
        h._mhp_installed = True  # type: ignore[attr-defined]
        root.addHandler(h)
    root.setLevel(lvl)
    # uvicorn's access log is noisy in dev — keep it at WARNING unless the
    # caller explicitly turned the root level up.
    logging.getLogger("uvicorn.access").setLevel(max(lvl, logging.WARNING))
