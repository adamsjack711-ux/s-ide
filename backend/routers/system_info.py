"""System info — tells the frontend what OS it's running on.

GET /system/info → {platform, arch, is_mac, is_windows, is_linux, hostname,
                    python_version, release}

Used by the renderer to hide platform-locked tools from the sidebar.
"""
from __future__ import annotations

import logging
import platform
import socket
import sys
from typing import Any

from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system"])


@router.get("/system/info")
def info() -> dict[str, Any]:
    plat = sys.platform   # "darwin" | "linux" | "win32"
    try:
        hostname = socket.gethostname()
    except Exception:
        # Hostname lookup can fail on weird container setups — fall back to
        # empty rather than leaking the raw exception to the client.
        logger.exception("system_info hostname lookup failed")
        hostname = ""
    return {
        "platform": plat,
        "is_mac":     plat == "darwin",
        "is_linux":   plat == "linux",
        "is_windows": plat == "win32",
        "arch":           platform.machine(),
        "release":        platform.release(),
        "system":         platform.system(),
        "hostname":       hostname,
        "python_version": sys.version.split()[0],
    }
