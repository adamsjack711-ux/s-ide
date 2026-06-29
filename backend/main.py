"""FastAPI app entrypoint for the Network Tools backend.

In dev:   uvicorn main:app --reload --port 8765 --host 127.0.0.1
In prod:  Electron spawns this as a sidecar process on app start, pinned
          to 127.0.0.1 via NT_BACKEND_HOST (see frontend/electron/main.cjs).

Security: this backend MUST NOT be exposed to the network. It executes
shell commands, installs sudoers entries, and toggles the WireGuard
tunnel — all gated by loopback-only binding plus a per-launch token
(see backend/lib/auth.py). The startup guard below refuses to run if
NT_BACKEND_HOST or HOST is set to a wildcard address.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from lib import errors as mhp_errors
from lib import logging_setup
from lib import exposure
from lib.auth import (
    AUTH_TOKEN,
    require_local_auth,
    require_local_auth_or_report_nonce,
    require_local_origin,
    require_localhost,
)

from routers import (
    ad_spray, audit, audit_log, aws_recon, azure_recon, basic_check,
    bloodhound_ingest, breach, brew, bt_recon, c2_beacon, chat, cmdi, cms,
    codescan, cred_harvest, ct_log, cvss, dns_recon, dorking, email_harvest, email_security,
    engagements, evil_twin, exploits, findings, fingerprint, gcp_recon, github_leak,
    graphql, hash_cracker, http_probe, ids, idor, imds, ip_checker,
    jwt_analyzer, kerberos_roast, labs, lan_scan, lateral, ldap_enum, lfi,
    isolation, labfs, local_discovery, linux_posture, macos_posture, method,
    nmap, people_enum, playbook_run,
    persistence, ping, playbook_suggest, port_scanner, presets, processes,
    profile_finder, reports, reverse_ip, reverse_shell, s3_scanner, safety, scope, settings,
    shodan_censys, smb_enum, spine, sqli, ssrf, stego, subdomain_enum, suggest_checks, summarize,
    system_info, takeover, targets, tcpdump, terminal, themes, tls_audit,
    tool_requirements, triage, urlscan, wayback, whois, wifi, wifi_scan,
    windows_posture,
    wpa_capture, xss, systemd_units, firewall_rules, users_audit,
)

logging_setup.configure()
logger = logging.getLogger("s-ide")

# ── PATH augmentation for GUI-launched sidecars ─────────────────────────────
# macOS launchd hands GUI apps a minimal PATH like ``/usr/bin:/bin:/usr/sbin:
# /sbin``. That's missing Homebrew (`/opt/homebrew/bin`) and Docker Desktop's
# /usr/local symlinks — so `shutil.which("docker")` returns None and Labs
# fails with "Docker daemon is not running" even when colima is up. Electron's
# main.cjs already prepends these, but we belt-and-suspenders here so direct
# sidecar launches (or alternative GUI launchers) also work.
if sys.platform == "darwin":
    _TOOL_PATHS = ["/opt/homebrew/bin", "/opt/homebrew/sbin",
                   "/usr/local/bin", "/usr/local/sbin"]
    _existing = (os.environ.get("PATH") or "").split(":")
    _need = [p for p in _TOOL_PATHS if p not in _existing]
    if _need:
        os.environ["PATH"] = ":".join(_need + _existing)

# ── Startup guard: refuse to expose the backend to the network ───────────────
# We check both NT_BACKEND_HOST (used by the sidecar entrypoint below) and
# HOST (commonly read by container orchestration). If either is a wildcard,
# bail out hard before FastAPI ever binds a socket.
#
# Escape hatch for the Docker deployment (see SECURITY.md "Threat Model"):
# set SIDE_ALLOW_PUBLIC_HOST=1 to acknowledge that you are lifting
# the loopback restriction deliberately. Required because the container's
# `ports: 8765:8765` mapping in docker-compose.yml needs the app to bind
# the container's external interface.
_FORBIDDEN_HOSTS = {"0.0.0.0", "::", "*"}
_ALLOW_PUBLIC = os.environ.get("SIDE_ALLOW_PUBLIC_HOST", "").strip() == "1"
for _var in ("NT_BACKEND_HOST", "HOST"):
    _val = os.environ.get(_var, "").strip()
    if _val in _FORBIDDEN_HOSTS and not _ALLOW_PUBLIC:
        sys.stderr.write(
            f"[s-ide] {_var}={_val!r}: "
            "the backend must not be exposed to the network. "
            "Refusing to start.\n"
            "(Docker deployments: set SIDE_ALLOW_PUBLIC_HOST=1 to opt in.)\n"
        )
        raise SystemExit(2)
if _ALLOW_PUBLIC:
    sys.stderr.write(
        "[s-ide] SIDE_ALLOW_PUBLIC_HOST=1 — startup guard bypassed. "
        "Backend will accept non-loopback connections. The per-launch auth token "
        "is now the only thing protecting privileged endpoints.\n"
    )

app = FastAPI(title="s-ide", version="1.0.0")

# Global error envelope + handlers. Every uncaught exception becomes
# {"error": "...", "code": "..."} with the stack trace logged server-side
# instead of leaked to the client.
mhp_errors.install_handlers(app)

# Loopback-only CORS: the only thing that ever calls us is the local
# Electron renderer (or the Vite dev server during development).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev
        "http://127.0.0.1:5173",
        "app://-",                 # Electron production scheme
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every router is gated by the same loopback + token + origin trio.
# `/health`, `/version`, and `/auth/token` are direct on `app` (below) so
# they don't pick this up — and they have narrower deps appropriate to
# their roles (none for /health and /version; `require_localhost` for
# /auth/token so the renderer can fetch the token without already
# possessing it).
#
# Individual routers may stack additional dependencies on their own
# APIRouter(...) constructors — those compose. Running the gate twice is
# harmless: secrets.compare_digest is constant-time.
_PRIVILEGED = [Depends(require_local_auth), Depends(require_local_origin)]

# Report-serving routers accept either the bearer token (for authFetch
# callers) or a short-lived path-bound nonce (for the system-browser opens
# triggered by "Open report" buttons). The renderer uses
# requestReportLink()/window.open(); see frontend/src/lib/engagement.ts.
_REPORT_GATE = [
    Depends(require_local_auth_or_report_nonce),
    Depends(require_local_origin),
]


# ── Capability gate ─────────────────────────────────────────────────────────
# s-ide exposes only the zero-setup (Tier 1) toolset. `_inc` registers a router
# only when exposure.is_exposed(key) is true (Tier 1, or RAMPART_EXPOSE_ALL=1).
# Tier 2/3 routers ship in the codebase but 404 by default. See lib/exposure.py.
def _inc(key, router, deps):
    if exposure.is_exposed(key):
        app.include_router(router, dependencies=deps)

_inc("ip_checker", ip_checker.router, _PRIVILEGED)
_inc("ip_checker", ip_checker.shodan_router, _PRIVILEGED)
_inc("dns_recon", dns_recon.router, _PRIVILEGED)
_inc("whois", whois.router, _PRIVILEGED)
_inc("tls_audit", tls_audit.router, _PRIVILEGED)
_inc("fingerprint", fingerprint.router, _PRIVILEGED)
_inc("http_probe", http_probe.router, _PRIVILEGED)
_inc("ct_log", ct_log.router, _PRIVILEGED)
_inc("email_security", email_security.router, _PRIVILEGED)
_inc("takeover", takeover.router, _PRIVILEGED)
_inc("reverse_ip", reverse_ip.router, _PRIVILEGED)
_inc("cms", cms.router, _PRIVILEGED)
_inc("macos_posture", macos_posture.router, _PRIVILEGED)
_inc("linux_posture", linux_posture.router, _PRIVILEGED)
_inc("windows_posture", windows_posture.router, _PRIVILEGED)
_inc("systemd_units", systemd_units.router, _PRIVILEGED)
_inc("firewall_rules", firewall_rules.router, _PRIVILEGED)
_inc("users_audit", users_audit.router, _PRIVILEGED)
_inc("local_discovery", local_discovery.router, _PRIVILEGED)
_inc("jwt_analyzer", jwt_analyzer.router, _PRIVILEGED)
_inc("graphql", graphql.router, _PRIVILEGED)
_inc("hash_cracker", hash_cracker.router, _PRIVILEGED)
_inc("port_scanner", port_scanner.router, _PRIVILEGED)
_inc("nmap", nmap.router, _PRIVILEGED)
_inc("lan_scan", lan_scan.router, _PRIVILEGED)
_inc("audit", audit.router, _PRIVILEGED)
_inc("ids", ids.router, _PRIVILEGED)
_inc("ping", ping.router, _PRIVILEGED)
_inc("tcpdump", tcpdump.router, _PRIVILEGED)
_inc("wifi", wifi.router, _PRIVILEGED)
_inc("terminal", terminal.router, _PRIVILEGED)
_inc("brew", brew.router, _PRIVILEGED)
_inc("labs", labs.router, _PRIVILEGED)
_inc("targets", targets.router, _PRIVILEGED)
_inc("persistence", persistence.router, _PRIVILEGED)
_inc("processes", processes.router, _PRIVILEGED)
_inc("stego", stego.router, _PRIVILEGED)
_inc("reverse_shell", reverse_shell.router, _PRIVILEGED)
_inc("system_info", system_info.router, _PRIVILEGED)
_inc("settings", settings.router, _PRIVILEGED)
_inc("chat", chat.router, _PRIVILEGED)
_inc("engagements", engagements.router, _REPORT_GATE)
_inc("findings", findings.router, _PRIVILEGED)
_inc("cvss", cvss.router, _PRIVILEGED)
_inc("reports", reports.router, _REPORT_GATE)
_inc("summarize", summarize.router, _PRIVILEGED)
_inc("imds", imds.router, _PRIVILEGED)
_inc("s3_scanner", s3_scanner.router, _PRIVILEGED)
_inc("breach", breach.router, _PRIVILEGED)
_inc("dorking", dorking.router, _PRIVILEGED)
_inc("github_leak", github_leak.router, _PRIVILEGED)
_inc("shodan_censys", shodan_censys.router, _PRIVILEGED)
_inc("people_enum", people_enum.router, _PRIVILEGED)
_inc("aws_recon", aws_recon.router, _PRIVILEGED)
_inc("azure_recon", azure_recon.router, _PRIVILEGED)
_inc("gcp_recon", gcp_recon.router, _PRIVILEGED)
_inc("ldap_enum", ldap_enum.router, _PRIVILEGED)
_inc("smb_enum", smb_enum.router, _PRIVILEGED)
_inc("ad_spray", ad_spray.router, _PRIVILEGED)
_inc("kerberos_roast", kerberos_roast.router, _PRIVILEGED)
_inc("wifi_scan", wifi_scan.router, _PRIVILEGED)
_inc("evil_twin", evil_twin.router, _PRIVILEGED)
_inc("bt_recon", bt_recon.router, _PRIVILEGED)
_inc("wpa_capture", wpa_capture.router, _PRIVILEGED)
_inc("c2_beacon", c2_beacon.router, _PRIVILEGED)
_inc("cred_harvest", cred_harvest.router, _PRIVILEGED)
_inc("profile_finder", profile_finder.router, _PRIVILEGED)
_inc("bloodhound_ingest", bloodhound_ingest.router, _PRIVILEGED)
_inc("lateral", lateral.router, _PRIVILEGED)
_inc("subdomain_enum", subdomain_enum.router, _PRIVILEGED)
_inc("xss", xss.router, _PRIVILEGED)
_inc("sqli", sqli.router, _PRIVILEGED)
_inc("cmdi", cmdi.router, _PRIVILEGED)
_inc("lfi", lfi.router, _PRIVILEGED)
_inc("ssrf", ssrf.router, _PRIVILEGED)
_inc("idor", idor.router, _PRIVILEGED)
_inc("presets", presets.router, _PRIVILEGED)
_inc("exploits", exploits.router, _PRIVILEGED)
_inc("wayback", wayback.router, _PRIVILEGED)
_inc("urlscan", urlscan.router, _PRIVILEGED)
_inc("email_harvest", email_harvest.router, _PRIVILEGED)
_inc("dorking", dorking.osint_router, _PRIVILEGED)
_inc("audit_log", audit_log.router, _PRIVILEGED)
_inc("scope", scope.router, _PRIVILEGED)
_inc("triage", triage.router, _PRIVILEGED)
_inc("playbook_suggest", playbook_suggest.router, _PRIVILEGED)
_inc("suggest_checks", suggest_checks.router, _PRIVILEGED)
_inc("basic_check", basic_check.router, _PRIVILEGED)
_inc("tool_requirements", tool_requirements.router, _PRIVILEGED)
_inc("method", method.router, _PRIVILEGED)
_inc("codescan", codescan.router, _PRIVILEGED)
_inc("safety", safety.router, _PRIVILEGED)
_inc("spine", spine.router, _PRIVILEGED)
_inc("themes", themes.router, _PRIVILEGED)
_inc("isolation", isolation.router, _PRIVILEGED)
_inc("labfs", labfs.router, _PRIVILEGED)
_inc("playbook_run", playbook_run.router, _PRIVILEGED)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": app.version, "pid": str(os.getpid())}


@app.get("/version")
def version() -> dict[str, str]:
    return {"version": app.version}


@app.get("/system/tools")
def system_tools() -> dict[str, object]:
    """Registered route paths (HTTP + WebSocket) — the truthful source for the
    Workbench's per-tool live/offline status.

    A tool whose backend route is absent here was gated off server-side (Tier
    2/3 not exposed, or the capability gate hasn't opted it in) and will 404 if
    called. The frontend matches each tool's route prefix against this set to
    render a live / gated / offline dot. Loopback-only by binding; the paths are
    route templates, not data, so no auth is required (matching /health)."""
    paths = sorted({getattr(r, "path", "") for r in app.routes} - {""})
    return {"routes": paths, "exposeAll": exposure.expose_all()}


@app.get(
    "/auth/token",
    dependencies=[Depends(require_localhost), Depends(require_local_origin)],
)
def auth_token() -> dict[str, str]:
    """Return the per-launch auth token. Loopback-only (no header required).

    The Electron renderer fetches this on first api() call and attaches it
    via X-MHP-Token on every subsequent privileged request. The token is
    regenerated each process start, so anything cached from a previous run
    is automatically invalidated.

    Origin check belt-and-suspenders against a malicious browser tab
    reaching loopback via DNS rebinding before the renderer mounts.
    """
    return {"token": AUTH_TOKEN}


# ── Optional browser UI mount ────────────────────────────────────────────────
# The Docker image bundles the built React app under /app/frontend_dist and
# serves it at "/". The Electron PyInstaller sidecar has no such directory,
# so the mount is conditional and that build path remains unaffected.
# Registered after every explicit route so it only catches unmatched paths.
_FRONTEND_DIST = Path(__file__).parent / "frontend_dist"
if _FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=_FRONTEND_DIST, html=True), name="frontend")


# ── Sidecar entrypoint ────────────────────────────────────────────────────────
# Lets the PyInstaller-bundled binary launch uvicorn directly without needing
# `python -m uvicorn`. The dev workflow still uses uvicorn's CLI for --reload.
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("NT_BACKEND_PORT", "8765"))
    # Loopback-only by default. The startup guard above already rejects
    # wildcard hosts before we get here, so anything that survives to this
    # point is at worst a typo'd hostname that uvicorn itself will refuse.
    host = os.environ.get("NT_BACKEND_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=port, log_level="warning",
                # asyncio + h11 + wsproto are explicit so PyInstaller can find them
                loop="asyncio", http="h11", ws="wsproto")
