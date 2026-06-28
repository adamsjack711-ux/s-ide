# PyInstaller spec for the Network Tools FastAPI backend.
#
# Output: a onedir bundle at `dist/network-tools-backend/` containing the
# launcher binary plus `_internal/` deps. Onedir avoids the per-launch /tmp
# extraction step a onefile binary does, cutting cold start ~3-5x.
#
# Built by: `pyinstaller network-tools-backend.spec --noconfirm`

# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

_IS_DARWIN = sys.platform == "darwin"

# Optional data files — bundle only if present. Lets CI builds skip the 51 MB
# rockyou wordlist; hash_cracker handles its absence gracefully.
_optional_datas = []
if os.path.exists("wordlists/rockyou.txt.gz"):
    _optional_datas.append(("wordlists/rockyou.txt.gz", "wordlists"))

# Always-bundled runtime data. Every module that does
# ``Path(__file__).resolve().parent.parent / "<name>"`` to find its assets
# needs those assets shipped alongside the bundled binary. PyInstaller
# resolves the destination at runtime relative to ``_internal/``, which is
# exactly what those parent-parent lookups walk to.
#
# What lives where:
#   prompts/   — Anthropic system prompts for chat, playbook_suggest, triage,
#                report_rollup, summarize_tool (routers/chat.py,
#                routers/engagements.py, routers/playbook_suggest.py).
#   presets/   — Built-in .mhp playbooks loaded by lib/preset_engine.py.
#   labs/      — Dockerfiles + docker-compose.yml for every training lab
#                (lib/labs.py builds from these paths).
#   config.json — Default target_policy config (lib/target_policy.py falls
#                back to defaults if missing, but bundling it gives prod the
#                same starting policy as dev).
_required_datas = []
for src, dest in (
    ("prompts", "prompts"),
    ("presets", "presets"),
    ("labs",    "labs"),
    ("config.json", "."),
):
    if os.path.exists(src):
        _required_datas.append((src, dest))
    else:
        # Fail loud at build time rather than ship a half-working bundle.
        raise SystemExit(
            f"[spec] required runtime data missing: backend/{src!r} — refusing to build"
        )

hiddenimports = [
    # uvicorn runtime — pulled in dynamically by uvicorn.run()
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.logging",
    "h11",
    "wsproto",
    # FastAPI / Pydantic / Starlette
    *collect_submodules("fastapi"),
    *collect_submodules("starlette"),
    *collect_submodules("pydantic"),
    *collect_submodules("pydantic_core"),
    # Our routers/lib aren't importable until we add them to pathex
    "routers", "routers.audit", "routers.brew", "routers.cms",
    "routers.ct_log", "routers.dns_recon", "routers.email_security",
    "routers.fingerprint", "routers.graphql", "routers.hash_cracker",
    "routers.http_probe", "routers.ids", "routers.ip_checker",
    "routers.jwt_analyzer", "routers.lan_scan", "routers.local_discovery",
    "routers.macos_posture", "routers.persistence", "routers.ping",
    "routers.port_scanner", "routers.processes", "routers.reverse_ip",
    "routers.stego", "routers.takeover", "routers.tcpdump", "routers.terminal",
    "routers.tls_audit", "routers.vpn", "routers.whois", "routers.wifi",
    "lib", "lib.audit", "lib.forensics", "lib.hids_notify", "lib.ids",
    "lib.ip_intel", "lib.lan", "lib.scanner", "lib.target_policy",
    *collect_submodules("psutil"),
    # Hash cracker deps — passlib uses dynamic handler loading; argon2 has C bindings
    *collect_submodules("passlib"),
    *collect_submodules("argon2"),
    *collect_submodules("bcrypt"),
    # cryptography (already used by other tools) — ensure full coverage
    *collect_submodules("cryptography"),
    # Stego — Pillow for PNG/BMP/JPEG; wave is stdlib so no submodule sweep needed
    *collect_submodules("PIL"),
    # Anthropic SDK (chat assistant)
    *collect_submodules("anthropic"),
    *collect_submodules("httpx"),
    # reportlab — PDF report exporter has dynamic imports for fonts + colors
    *collect_submodules("reportlab"),
    # Cloud SDKs — only loaded on-demand by the recon routers but PyInstaller
    # needs the full submodule tree since boto3 etc. import lazily at runtime.
    *collect_submodules("boto3"),
    *collect_submodules("botocore"),
    *collect_submodules("azure"),
    *collect_submodules("azure.identity"),
    *collect_submodules("azure.mgmt"),
    *collect_submodules("msal"),
    *collect_submodules("google.auth"),
    *collect_submodules("google.api_core"),
    *collect_submodules("google.cloud"),
    *collect_submodules("grpc"),
    *collect_submodules("proto"),
    # AD tooling
    *collect_submodules("ldap3"),
    *collect_submodules("impacket"),
    *collect_submodules("pyasn1"),
    *collect_submodules("Cryptodome"),    # pycryptodomex
    *collect_submodules("Crypto"),        # pycryptodome (bloodhound dep)
    *collect_submodules("bloodhound"),    # SharpHound-equivalent collector
    *collect_submodules("dns"),           # dnspython
]

# Wireless — CoreWLAN + CoreBluetooth PyObjC bindings are macOS-only.
# Collecting them on Windows/Linux is wasted analysis time at best and
# triggers PyInstaller warnings ("module not found") at worst.
if _IS_DARWIN:
    hiddenimports += [
        *collect_submodules("CoreWLAN"),
        *collect_submodules("CoreBluetooth"),
        *collect_submodules("CoreFoundation"),
        *collect_submodules("Foundation"),
    ]

# Data files — botocore ships service models as JSON in its package; azure ships
# locale files; google ships proto descriptors. All need to land in the bundle.
_cloud_datas = (
    collect_data_files("botocore")
    + collect_data_files("boto3")
    + collect_data_files("azure")
    + collect_data_files("google.cloud")
    + collect_data_files("google.api_core")
)

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=_optional_datas + _required_datas + _cloud_datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "test", "_pytest", "matplotlib", "numpy",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="network-tools-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="network-tools-backend",
)
