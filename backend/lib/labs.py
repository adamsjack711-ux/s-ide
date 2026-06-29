"""Docker-backed training labs (DVWA, Juice Shop, Metasploitable, vulhub-net).

Each lab is a self-contained Docker image, built from a Dockerfile that lives
under ``backend/labs/<id>/``. The Labs page in the UI calls the REST endpoints
in ``routers/labs.py`` to build / start / stop containers; this module owns
the actual ``docker`` subprocess invocations and the in-memory state machine.

State model
-----------
For each lab we track:

  * Container state — derived live from ``docker inspect``. One of:
    ``missing``, ``created``, ``running``, ``exited``, ``paused``, ``dead``.
  * Build state — owned by this module since ``docker build`` is a long
    background operation. One of: ``idle``, ``building``, ``built``, ``error``.
    A bounded build log is kept so the UI can poll for the tail.

Naming
------
  * Image:     ``mhp/lab-<id>:latest``
  * Container: ``mhp-lab-<id>``

Phase 1 ships only DVWA. Adding a lab is registering a new ``LabDef`` entry
plus dropping a Dockerfile (and any supporting files) under
``backend/labs/<id>/``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from lib.platform_util import app_data_dir

logger = logging.getLogger(__name__)


# ── Paths ────────────────────────────────────────────────────────────────────
LABS_DIR = Path(__file__).resolve().parent.parent / "labs"

# Per-user override of which labs are visible in the main grid. Stored as
# ``{id: bool}``. Anything missing falls back to ``LabDef.enabled_by_default``.
# Lives in the app data dir so it survives backend restarts.
_ENABLED_OVERRIDES_PATH = app_data_dir() / "labs_enabled.json"
_enabled_overrides: dict[str, bool] | None = None


# ── Lab registry ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class SuggestedStep:
    """One row in the "what to try next" panel on a lab card.

    `route` is a frontend nav id (matches `NavId` in components/Sidebar.tsx).
    `query` is appended to the URL the UI navigates to; pages that opt in
    read these (e.g. ``?target=127.0.0.1``) and pre-fill their form.
    """
    label: str
    route: str
    query: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass(frozen=True)
class LabDef:
    id: str
    name: str
    summary: str
    # Build / run identity. Computed from `id` but kept explicit so tests
    # can grep for them. For `kind="compose"` the `image_tag` is just a
    # readiness probe (we check it exists after `docker compose build`),
    # and `container_name` is informational.
    image_tag: str
    container_name: str
    # Maps container_port -> host_port. The first entry is taken as the
    # primary web port (used for the "Open" button URL).
    port_map: dict[int, int]
    # Optional default credentials surfaced in the UI as a hint.
    default_creds: str | None
    # The dir under backend/labs/ that contains the Dockerfile + assets.
    build_dir: str
    suggested_steps: tuple[SuggestedStep, ...]
    # Compose-only fields. Default `kind="single"` keeps existing labs unchanged.
    kind: Literal["single", "compose"] = "single"
    # Project name passed to `docker compose -p ...`. Conventionally
    # `mhp-lab-<id>` — kept explicit so it can be greppped.
    compose_project: str = ""
    # All service names declared in the compose file, in declaration order.
    # First service is treated as the "primary" for status aggregation.
    compose_services: tuple[str, ...] = ()
    # Service that the sidecar-exec endpoint targets (must declare a fixed
    # `container_name:` in the compose file so it's reachable by name).
    sidecar_service: str = ""
    sidecar_container: str = ""
    # Whitelist of commands the sidecar-exec endpoint will run.
    sidecar_allowed_cmds: tuple[str, ...] = ()
    # Whether this lab appears in the main grid out of the box. Newer
    # catalog-only labs ship with ``False`` so the grid stays tidy until
    # the user clicks "+ Add Lab" and opts in.
    enabled_by_default: bool = True
    # Short tag shown on catalog cards — "Web", "API", "CVE", "Network".
    category: str = "Web"

    @property
    def primary_url(self) -> str:
        if not self.port_map:
            return ""
        first_host_port = next(iter(self.port_map.values()))
        return f"http://127.0.0.1:{first_host_port}"

    @property
    def compose_file(self) -> Path:
        """Absolute path to the lab's docker-compose.yml."""
        return LABS_DIR / self.build_dir / "docker-compose.yml"


LABS: dict[str, LabDef] = {
    "juice-shop": LabDef(
        id="juice-shop",
        name="OWASP Juice Shop",
        summary=(
            "Modern JS-based vulnerable webapp covering the full OWASP Top 10 "
            "with a built-in score tracker. Pinned to v16.0.0 of the upstream repo."
        ),
        image_tag="mhp/lab-juice-shop:latest",
        container_name="mhp-lab-juice-shop",
        port_map={3000: 8083},
        default_creds="admin@juice-sh.op / admin123 (try registering, too)",
        build_dir="juice-shop",
        category="Web",
        suggested_steps=(
            SuggestedStep(
                label="Fingerprint the app",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8083"},
                description="Headers, framework, and server banner.",
            ),
            SuggestedStep(
                label="HTTP probe",
                route="http",
                query={"target": "http://127.0.0.1:8083"},
                description="Confirm endpoints + headers; spot the X-Recruiting easter egg.",
            ),
            SuggestedStep(
                label="SQL Injection — login bypass",
                route="sqli",
                query={"target": "http://127.0.0.1:8083/rest/user/login"},
                description="Classic SQLi at the login endpoint. Try email=' OR 1=1 --.",
            ),
            SuggestedStep(
                label="JWT analysis",
                route="jwt",
                query={"target": "http://127.0.0.1:8083"},
                description="Juice Shop hands out a JWT; weak signing key in some versions.",
            ),
            SuggestedStep(
                label="XSS playground",
                route="xss",
                query={"target": "http://127.0.0.1:8083/#/search"},
                description="Reflected XSS sandbox. Try q=<iframe src=javascript:alert(1)>.",
            ),
        ),
    ),
    "vulhub-net": LabDef(
        id="vulhub-net",
        name="vulhub-net (3-host LAN)",
        summary=(
            "Three vulnerable hosts on a private docker bridge (10.20.0.0/24): "
            "node-web (Apache + SQLi/cmdi), node-files (anonymous FTP + Samba), "
            "node-db (MariaDB root no-pw + Redis no-auth). Plus a scanner sidecar "
            "on the same bridge so the s-ide tools can reach the internal "
            "IPs that Docker Desktop hides from macOS."
        ),
        image_tag="mhp/lab-vulhub-net-scanner:latest",
        container_name="mhp-lab-vulhub-net-scanner",
        port_map={},  # nothing published — sidecar exec is the only entry
        default_creds="MySQL root (no pw) · admin/admin · dev/dev · FTP anon · SMB guest",
        build_dir="vulhub-net",
        category="Network",
        kind="compose",
        compose_project="mhp-lab-vulhub-net",
        compose_services=("scanner", "node-web", "node-files", "node-db"),
        sidecar_service="scanner",
        sidecar_container="mhp-lab-vulhub-net-scanner",
        sidecar_allowed_cmds=("nmap", "smbclient", "curl", "dig", "nc"),
        suggested_steps=(
            SuggestedStep(
                label="Sweep the subnet (nmap)",
                route="labs",
                query={"sidecar": "nmap", "target": "10.20.0.0/24", "args": "-sn"},
                description="Use the sidecar to ping-sweep the lab subnet — should find 3 hosts + the scanner itself.",
            ),
            SuggestedStep(
                label="Fingerprint node-web",
                route="labs",
                query={"sidecar": "nmap", "target": "10.20.0.10", "args": "-sV -F"},
                description="Service+version detection on the web host.",
            ),
            SuggestedStep(
                label="Enumerate node-files (SMB)",
                route="labs",
                query={"sidecar": "smbclient", "target": "//10.20.0.20/public", "args": "-N -L"},
                description="List Samba shares via guest access.",
            ),
            SuggestedStep(
                label="Probe Redis on node-db",
                route="labs",
                query={"sidecar": "nc", "target": "10.20.0.30", "args": "6379"},
                description="Connect to Redis with no auth; type INFO and PING.",
            ),
        ),
    ),
    "metasploitable": LabDef(
        id="metasploitable",
        name="Metasploitable",
        summary=(
            "Metasploitable-flavored multi-service host — 10 open ports with "
            "weak/outdated services and a vulnerable PHP webapp. vsftpd, "
            "OpenSSH, telnet, postfix, Apache, Samba, MariaDB, distccd, plus "
            "two emulated root-shell backdoors on 1524 and 6200. Default "
            "creds msfadmin/msfadmin and root/toor."
        ),
        image_tag="mhp/lab-metasploitable:latest",
        container_name="mhp-lab-metasploitable",
        # 80 → 8082 listed first so it becomes the "Open" button URL.
        port_map={
            80:   8082,   # apache + vulnerable PHP
            21:   2121,   # vsftpd
            22:   2122,   # ssh
            23:   2123,   # telnet
            25:   2125,   # postfix
            139:  2139,   # smb netbios
            445:  2445,   # smb
            1524: 1524,   # ingreslock bindshell
            3306: 2306,   # mariadb
            3632: 3632,   # distccd
            6200: 6200,   # vsftpd backdoor
        },
        default_creds="msfadmin / msfadmin · root / toor · MySQL root no pw",
        build_dir="metasploitable",
        category="Network",
        suggested_steps=(
            SuggestedStep(
                label="Port scan the lab",
                route="ports",
                query={"target": "127.0.0.1", "ports": "21,22,23,25,80,139,445,1524,2121,2122,2123,2125,2139,2306,2445,3306,3632,6200,8082"},
                description="Confirm all 10 published ports are listening on loopback.",
            ),
            SuggestedStep(
                label="Nmap service+version detection",
                route="nmap",
                query={"target": "127.0.0.1", "profile": "service_version"},
                description="Nmap fingerprints each service — outdated banners trigger NSE vuln scripts.",
            ),
            SuggestedStep(
                label="Network audit (full risk report)",
                route="audit",
                query={"target": "127.0.0.1"},
                description="Run the network audit — each insecure service should show up with a risk + fix.",
            ),
            SuggestedStep(
                label="SMB enumeration",
                route="smb",
                query={"target": "127.0.0.1", "port": "2445"},
                description="Null sessions + guest enabled — list shares and users.",
            ),
            SuggestedStep(
                label="Fingerprint the web server",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8082"},
                description="Apache/PHP banners + headers.",
            ),
            SuggestedStep(
                label="SQL Injection lab (login.php)",
                route="sqli",
                query={"target": "http://127.0.0.1:8082/login.php"},
                description="Concatenated SQL — try admin' OR '1'='1' -- as the username.",
            ),
            SuggestedStep(
                label="Command Injection lab (ping.php)",
                route="cmdi",
                query={"target": "http://127.0.0.1:8082/ping.php?host=127.0.0.1"},
                description="shell_exec with no escaping — try ;id or |whoami.",
            ),
            SuggestedStep(
                label="LFI lab (include.php)",
                route="lfi",
                query={"target": "http://127.0.0.1:8082/include.php?page=home"},
                description="include() with user-controlled path — try /etc/passwd.",
            ),
            SuggestedStep(
                label="Hash cracker (msfadmin from /etc/shadow)",
                route="hash",
                query={},
                description="Once you've stolen /etc/shadow via LFI or shell, crack msfadmin's hash here.",
            ),
        ),
    ),
    "webgoat": LabDef(
        id="webgoat",
        name="OWASP WebGoat + WebWolf",
        summary=(
            "OWASP's guided learn-by-doing platform — lessons across SQLi, XSS, "
            "auth, deserialization, JWT, and SSRF. WebWolf runs alongside as the "
            "attacker-controlled listener for the exfil/CSRF exercises."
        ),
        image_tag="mhp/lab-webgoat:latest",
        container_name="mhp-lab-webgoat",
        port_map={8080: 8084, 9090: 9094},
        default_creds="register any user — local-only DB",
        build_dir="webgoat",
        category="Web",
        enabled_by_default=False,
        kind="compose",
        compose_project="mhp-lab-webgoat",
        # WebGoat 2023.x serves both WebGoat (8080) and WebWolf (9090) from a
        # single image, so the stack is one service publishing two ports.
        compose_services=("webgoat",),
        suggested_steps=(
            SuggestedStep(
                label="Open WebGoat",
                route="http",
                query={"target": "http://127.0.0.1:8084/WebGoat"},
                description="Default landing path — register, then pick a lesson group.",
            ),
            SuggestedStep(
                label="Fingerprint the app",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8084/WebGoat"},
                description="Spring Boot / Tomcat banner + headers.",
            ),
            SuggestedStep(
                label="JWT analysis (WebGoat JWT lessons)",
                route="jwt",
                query={"target": "http://127.0.0.1:8084/WebGoat"},
                description="WebGoat hands out JWTs that are vulnerable in various ways — none/RS256-to-HS256/etc.",
            ),
            SuggestedStep(
                label="Open WebWolf (listener)",
                route="http",
                query={"target": "http://127.0.0.1:9094/WebWolf"},
                description="Companion service for CSRF / exfil exercises — your attacker-controlled origin.",
            ),
        ),
    ),
    "crapi": LabDef(
        id="crapi",
        name="OWASP crAPI",
        summary=(
            "Completely Ridiculous API — vulnerable car-service REST/GraphQL "
            "stack covering the full OWASP API Top 10 (BOLA, mass assignment, "
            "improper asset management, SSRF, JWT issues). Heavy stack: web + "
            "identity + community + workshop + mongo + postgres + mailhog."
        ),
        image_tag="mhp/lab-crapi:latest",
        container_name="mhp-lab-crapi-web",
        # Web (nginx :80) on host 8085 + mailhog UI (:8025) on host 8095.
        # Everything else stays internal to the compose network.
        port_map={80: 8085, 8025: 8095},
        default_creds="register a fresh account — uses mailhog at :8095 for verification",
        build_dir="crapi",
        category="API",
        enabled_by_default=False,
        kind="compose",
        compose_project="mhp-lab-crapi",
        compose_services=(
            "crapi-web", "crapi-identity", "crapi-community", "crapi-workshop",
            "mongodb", "postgresdb", "mailhog",
        ),
        suggested_steps=(
            SuggestedStep(
                label="Open crAPI",
                route="http",
                query={"target": "http://127.0.0.1:8085"},
                description="Landing page — register, verify via mailhog at :8095, then explore the API.",
            ),
            SuggestedStep(
                label="Open mailhog (read verification email)",
                route="http",
                query={"target": "http://127.0.0.1:8095"},
                description="crAPI emails the signup verification token here — copy/paste it back into the app.",
            ),
            SuggestedStep(
                label="Fingerprint the API",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8085/identity"},
                description="Reverse-proxied Spring + Go services — banners reveal the split.",
            ),
            SuggestedStep(
                label="JWT analysis",
                route="jwt",
                query={"target": "http://127.0.0.1:8085"},
                description="crAPI hands out JWTs with predictable secrets and key-confusion bugs.",
            ),
        ),
    ),
    "dvga": LabDef(
        id="dvga",
        name="Damn Vulnerable GraphQL App",
        summary=(
            "GraphQL-focused vulnerable app — introspection always on, batched "
            "queries, deep nesting DoS, IDOR via node IDs, and command injection "
            "via a vulnerable resolver. The reference target for GraphQL recon."
        ),
        image_tag="mhp/lab-dvga:latest",
        container_name="mhp-lab-dvga",
        port_map={5013: 8086},
        default_creds="no auth on most endpoints — introspection is open",
        build_dir="dvga",
        category="API",
        enabled_by_default=False,
        suggested_steps=(
            SuggestedStep(
                label="Open DVGA",
                route="http",
                query={"target": "http://127.0.0.1:8086"},
                description="GraphiQL IDE is mounted at /.",
            ),
            SuggestedStep(
                label="HTTP probe (find the GraphQL endpoint)",
                route="http",
                query={"target": "http://127.0.0.1:8086/graphql"},
                description="POST {\"query\":\"{__schema{types{name}}}\"} to dump the schema.",
            ),
            SuggestedStep(
                label="Command injection (systemUpdate)",
                route="cmdi",
                query={"target": "http://127.0.0.1:8086/graphql"},
                description="The systemUpdate mutation passes user input to a shell — try ; id.",
            ),
            SuggestedStep(
                label="Fingerprint",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8086"},
                description="Flask + Graphene banner; should leak the framework.",
            ),
        ),
    ),
    "log4shell": LabDef(
        id="log4shell",
        name="Log4Shell (CVE-2021-44228)",
        summary=(
            "Spring Boot app that logs the User-Agent header through a "
            "vulnerable log4j 2.14.x. Hitting it with a JNDI payload in the "
            "header triggers the classic outbound LDAP fetch. Pair with your "
            "own LDAP listener (marshalsec / JNDIExploit) on the host."
        ),
        image_tag="mhp/lab-log4shell:latest",
        container_name="mhp-lab-log4shell",
        port_map={8080: 8087},
        default_creds="no auth — just send a request",
        build_dir="log4shell",
        category="CVE",
        enabled_by_default=False,
        suggested_steps=(
            SuggestedStep(
                label="Hit the vulnerable endpoint",
                route="http",
                query={"target": "http://127.0.0.1:8087/"},
                description="GET / logs the User-Agent — set it to ${jndi:ldap://127.0.0.1:1389/Exploit} after starting a listener.",
            ),
            SuggestedStep(
                label="Fingerprint",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8087"},
                description="Spring Boot banner; X-Application-Context header on some routes.",
            ),
            SuggestedStep(
                label="Read the response headers",
                route="http",
                query={"target": "http://127.0.0.1:8087/", "method": "GET"},
                description="Confirm the app is up and reflective enough to trigger log4j on the User-Agent path.",
            ),
        ),
    ),
    "spring4shell": LabDef(
        id="spring4shell",
        name="Spring4Shell (CVE-2022-22965)",
        summary=(
            "Vulnerable Spring MVC + Tomcat stack — DataBinder reaches the "
            "ClassLoader through nested property paths and writes a JSP webshell "
            "into the webroot. Exploit lands at /shell.jsp after a single POST."
        ),
        image_tag="mhp/lab-spring4shell:latest",
        container_name="mhp-lab-spring4shell",
        port_map={8080: 8088},
        default_creds="no auth — POST a form to /",
        build_dir="spring4shell",
        category="CVE",
        enabled_by_default=False,
        suggested_steps=(
            SuggestedStep(
                label="Open the app",
                route="http",
                query={"target": "http://127.0.0.1:8088/"},
                description="Simple Spring MVC form — the DataBinder bug is reachable from the default endpoint.",
            ),
            SuggestedStep(
                label="Fingerprint",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8088/"},
                description="Spring MVC + Tomcat banner. Check headers for Spring Boot vs WAR-on-Tomcat.",
            ),
            SuggestedStep(
                label="Brute / probe parameters",
                route="dirb",
                query={"target": "http://127.0.0.1:8088/"},
                description="Spray endpoints — after exploitation, /shell.jsp shows up here.",
            ),
        ),
    ),
    "struts2-rce": LabDef(
        id="struts2-rce",
        name="Apache Struts2 RCE (CVE-2017-5638)",
        summary=(
            "Vulnerable Struts2 app — Jakarta multipart parser evaluates an "
            "OGNL expression in the Content-Type header, giving unauthenticated "
            "RCE. Pre-built image from piesecurity, used in countless walkthroughs."
        ),
        image_tag="mhp/lab-struts2-rce:latest",
        container_name="mhp-lab-struts2-rce",
        port_map={8080: 8089},
        default_creds="no auth — set a malicious Content-Type and POST anywhere",
        build_dir="struts2-rce",
        category="CVE",
        enabled_by_default=False,
        suggested_steps=(
            SuggestedStep(
                label="Open the demo app",
                route="http",
                query={"target": "http://127.0.0.1:8089/struts2-showcase/"},
                description="Struts2 showcase page — POST here with an OGNL Content-Type to trigger RCE.",
            ),
            SuggestedStep(
                label="Fingerprint",
                route="fingerprint",
                query={"target": "http://127.0.0.1:8089/struts2-showcase/"},
                description="Tomcat + Struts2 banner; framework leaks via action URLs.",
            ),
            SuggestedStep(
                label="Command injection probe",
                route="cmdi",
                query={"target": "http://127.0.0.1:8089/struts2-showcase/showcase.action"},
                description="OGNL injection via Content-Type: %{(#cmd='id')...}.",
            ),
        ),
    ),
    "dvwa": LabDef(
        id="dvwa",
        name="DVWA",
        summary=(
            "Damn Vulnerable Web Application — PHP/MySQL training app with "
            "SQLi, XSS, CSRF, file upload, command injection, and more, "
            "tunable from low to impossible. Default creds: admin / password."
        ),
        image_tag="mhp/lab-dvwa:latest",
        container_name="mhp-lab-dvwa",
        port_map={80: 8081},
        default_creds="admin / password",
        build_dir="dvwa",
        category="Web",
        suggested_steps=(
            SuggestedStep(
                label="Port scan the lab",
                route="ports",
                query={"target": "127.0.0.1", "ports": "8081"},
                description="Confirm the DVWA port is listening before attacking.",
            ),
            SuggestedStep(
                label="HTTP fingerprint",
                route="http",
                query={"target": "http://127.0.0.1:8081"},
                description="Server headers, technologies, redirects.",
            ),
            SuggestedStep(
                label="Try the SQL Injection page",
                route="sqli",
                query={"target": "http://127.0.0.1:8081/vulnerabilities/sqli/?id=1"},
                description="DVWA's classic SQLi lab. Log in first, then set DVWA Security to Low.",
            ),
            SuggestedStep(
                label="Try the XSS (reflected) page",
                route="xss",
                query={"target": "http://127.0.0.1:8081/vulnerabilities/xss_r/?name=test"},
                description="Reflected XSS lab. Set DVWA Security to Low before launching.",
            ),
            SuggestedStep(
                label="Try Command Injection",
                route="cmdi",
                query={"target": "http://127.0.0.1:8081/vulnerabilities/exec/"},
                description="OS command injection lab. Form param `ip`.",
            ),
        ),
    ),
}


# ── Build state (in-memory) ──────────────────────────────────────────────────
BuildStatus = Literal["idle", "building", "built", "error"]


@dataclass
class BuildState:
    status: BuildStatus = "idle"
    started_at: float | None = None
    finished_at: float | None = None
    # Bounded ring of recent log lines (kept small so the UI poll payload
    # is reasonable). The full log is in the docker daemon's build log.
    log: deque[str] = field(default_factory=lambda: deque(maxlen=400))
    error: str | None = None
    task: asyncio.Task | None = None


_build_states: dict[str, BuildState] = {}

# Last good compose status per lab. `docker compose ps` is flaky under load
# (slow daemon socket, builder lock contention) — caching the last successful
# response avoids the UI flapping to "NOT BUILT" between two healthy polls.
_compose_status_cache: dict[str, dict[str, Any]] = {}


def _build_state(lab_id: str) -> BuildState:
    st = _build_states.get(lab_id)
    if st is None:
        st = BuildState()
        _build_states[lab_id] = st
    return st


# ── Public API ───────────────────────────────────────────────────────────────
def _load_overrides() -> dict[str, bool]:
    """Read the enabled-overrides JSON. Cached after first call.

    Missing / corrupt file is treated as "no overrides" — every lab falls
    back to its ``enabled_by_default``.
    """
    global _enabled_overrides
    if _enabled_overrides is not None:
        return _enabled_overrides
    try:
        if _ENABLED_OVERRIDES_PATH.exists():
            raw = json.loads(_ENABLED_OVERRIDES_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                _enabled_overrides = {str(k): bool(v) for k, v in raw.items()}
                return _enabled_overrides
    except Exception as exc:
        logger.warning("labs_enabled.json read failed: %s", exc)
    _enabled_overrides = {}
    return _enabled_overrides


def _save_overrides() -> None:
    overrides = _load_overrides()
    try:
        _ENABLED_OVERRIDES_PATH.write_text(
            json.dumps(overrides, indent=2, sort_keys=True), encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("labs_enabled.json write failed: %s", exc)


def is_enabled(lab_id: str) -> bool:
    """True if ``lab_id`` should appear in the main grid.

    Resolution: user override → lab default → False (unknown lab).
    """
    overrides = _load_overrides()
    if lab_id in overrides:
        return overrides[lab_id]
    lab = LABS.get(lab_id)
    return bool(lab and lab.enabled_by_default)


def set_enabled(lab_id: str, enabled: bool) -> None:
    """Persist a user override for a lab's visibility in the main grid."""
    if lab_id not in LABS:
        raise KeyError(lab_id)
    overrides = _load_overrides()
    overrides[lab_id] = bool(enabled)
    _save_overrides()


def list_labs() -> list[dict[str, Any]]:
    """Enabled labs only — the data behind the main grid."""
    return [_lab_summary(lab) for lab in LABS.values() if is_enabled(lab.id)]


def list_catalog() -> list[dict[str, Any]]:
    """All labs, each tagged with its current effective enabled state.

    Drives the "+ Add Lab" drawer — disabled entries get an Enable button,
    enabled entries (especially non-default ones) get a Disable affordance.
    """
    out: list[dict[str, Any]] = []
    for lab in LABS.values():
        summary = _lab_summary(lab)
        summary["enabled"] = is_enabled(lab.id)
        summary["enabled_by_default"] = lab.enabled_by_default
        summary["category"] = lab.category
        out.append(summary)
    return out


def get_lab_def(lab_id: str) -> LabDef | None:
    return LABS.get(lab_id)


def docker_available() -> bool:
    return shutil.which("docker") is not None


async def docker_running() -> bool:
    """True if the docker daemon answers ``docker info`` within ~3s."""
    if not docker_available():
        return False
    try:
        rc, _, _ = await _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=3)
        return rc == 0
    except Exception:
        return False


async def detect_runtime() -> dict[str, Any]:
    """Identify which container runtime is providing the docker socket.

    Returns ``{kind, version, context, running}`` where ``kind`` is one of
    ``colima``, ``docker-desktop``, ``podman``, ``other``, or ``none``.
    The UI shows this as a pill in the Labs header so users know which
    runtime they're actually talking to (matters during the DD→colima
    migration since both can be installed concurrently).
    """
    if not docker_available():
        return {"kind": "none", "version": None, "context": None, "running": False}
    rc, ctx_out, _ = await _run(["docker", "context", "show"], timeout=3)
    context_name = (ctx_out or "").strip() if rc == 0 else None
    kind = _kind_from_context(context_name)
    daemon = await docker_running()
    version: str | None = None
    if daemon:
        rc, ver_out, _ = await _run(
            ["docker", "version", "--format", "{{.Server.Version}}"], timeout=3,
        )
        if rc == 0:
            version = (ver_out or "").strip() or None
    return {"kind": kind, "version": version, "context": context_name, "running": daemon}


# Homebrew bin dirs we explicitly include in every preflight PATH search.
# /opt/homebrew/bin is Apple-Silicon Brew; /usr/local/bin is Intel Brew. We
# scan both each call so the user can `brew install colima docker` and hit
# Re-check without relaunching the app — relying on the captured-at-launch
# os.environ["PATH"] would miss a fresh install.
_BREW_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")


def _live_which(binary: str) -> str | None:
    """Resolve ``binary`` against the live PATH + the Homebrew bin dirs.

    ``shutil.which`` doesn't cache, so each call re-stats the filesystem —
    exactly what we want for the Labs popup's "Re-check" button. Adding the
    Brew dirs explicitly covers the case where the sidecar was launched
    with a stripped PATH (Electron / GUI launchers often are).
    """
    current = (os.environ.get("PATH") or "").split(os.pathsep)
    search = list(dict.fromkeys([*current, *_BREW_BIN_DIRS]))
    return shutil.which(binary, path=os.pathsep.join(search))


async def _colima_vm_running(colima_bin: str) -> bool:
    """True if the colima VM reports itself as running.

    Tries ``colima status --json`` first (newer versions), falls back to
    parsing plain ``colima status`` text. Both forms exit 0 only when the
    VM is up, so the rc alone is a reasonable signal — we double-check the
    payload to defend against rc-quirks in older releases.
    """
    rc, out, err = await _run([colima_bin, "status", "--json"], timeout=5)
    if rc == 0 and out.strip():
        try:
            data = json.loads(out.strip().splitlines()[-1])
            status = str(data.get("status", "")).lower()
            if status:
                return status == "running"
            if "running" in data:
                return bool(data["running"])
        except json.JSONDecodeError:
            pass
    # Fall back to plain `colima status` — older versions just write
    # "colima is running" / "colima is not running" to stderr.
    rc2, out2, err2 = await _run([colima_bin, "status"], timeout=5)
    blob = (out2 + err2).lower()
    if "is running" in blob:
        return True
    if "is not running" in blob or "stopped" in blob:
        return False
    return rc2 == 0


async def preflight() -> dict[str, Any]:
    """State-specific runtime check that drives the Labs popup.

    Returns one of four states with a remediation hint and (where it
    applies) the shell command to fix it. The PATH check is live on every
    call — the user can install colima and hit Re-check without bouncing
    the app.

    States:
      - ``ok``                — runtime is ready; lab launch will work
      - ``binary_missing``    — neither colima nor docker binary on disk
      - ``daemon_stopped``    — colima installed but the VM isn't running
                                (or Docker Desktop installed but not running)
      - ``socket_unreachable`` — colima says the VM is up but ``docker info``
                                 still fails — usually means the socket
                                 dropped and the VM needs a restart
    """
    colima_bin = _live_which("colima")
    docker_bin = _live_which("docker")

    if not colima_bin and not docker_bin:
        return {
            "state":       "binary_missing",
            "colima_path": None,
            "docker_path": None,
            "hint":        "No container runtime installed.",
            "command":     "brew install colima docker",
        }

    # Colima path is the recommended one — check VM state first so we can
    # show the precise "colima start" vs "colima restart" remediation.
    vm_running: bool | None = None
    if colima_bin:
        vm_running = await _colima_vm_running(colima_bin)
        if not vm_running:
            return {
                "state":       "daemon_stopped",
                "colima_path": colima_bin,
                "docker_path": docker_bin,
                "hint":        "Colima is installed but the VM isn't running.",
                "command":     "colima start",
            }

    # VM is up (or only Docker Desktop is installed). Probe the daemon.
    if docker_bin:
        rc, _, _ = await _run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"], timeout=3,
        )
        if rc == 0:
            return {
                "state":       "ok",
                "colima_path": colima_bin,
                "docker_path": docker_bin,
                "hint":        "Container runtime is ready.",
                "command":     None,
            }

    # Daemon refused. Differentiate "colima says VM is up but socket is
    # silent" (restart needed) from "Docker Desktop is installed but the
    # app isn't running" (start the app).
    if colima_bin and vm_running:
        return {
            "state":       "socket_unreachable",
            "colima_path": colima_bin,
            "docker_path": docker_bin,
            "hint":        "Colima reports the VM is running but the Docker socket "
                           "isn't responding. Restart the VM to recover.",
            "command":     "colima restart",
        }
    return {
        "state":       "daemon_stopped",
        "colima_path": colima_bin,
        "docker_path": docker_bin,
        "hint":        "Docker is installed but the daemon isn't responding. "
                       "Open Docker Desktop to start it.",
        "command":     None,
    }


def _kind_from_context(name: str | None) -> str:
    if not name:
        return "unknown"
    if name == "colima":
        return "colima"
    if name == "desktop-linux" or name.startswith("desktop-"):
        return "docker-desktop"
    if name == "podman" or name.startswith("podman"):
        return "podman"
    return "other"


async def image_exists(image_tag: str) -> bool:
    rc, out, _ = await _run(["docker", "image", "inspect", image_tag], timeout=5)
    return rc == 0 and bool(out.strip())


async def container_state(container_name: str) -> dict[str, Any]:
    """Return ``{state, status, started_at, exit_code}``.

    ``state`` ∈ {missing, created, running, exited, paused, dead, unknown}.
    Anything other than ``missing`` means the container exists.
    """
    rc, out, _ = await _run(
        ["docker", "inspect", "--format", "{{json .State}}", container_name],
        timeout=5,
    )
    if rc != 0:
        return {"state": "missing", "status": "", "started_at": None, "exit_code": None}
    try:
        st = json.loads(out.strip().splitlines()[-1])
    except Exception:
        return {"state": "unknown", "status": "", "started_at": None, "exit_code": None}
    return {
        "state":      str(st.get("Status") or "unknown").lower(),
        "status":     str(st.get("Status") or ""),
        "started_at": st.get("StartedAt"),
        "exit_code":  st.get("ExitCode"),
    }


async def compose_status(lab: LabDef) -> dict[str, Any]:
    """Aggregate state of all services in a compose lab.

    Returns ``{state, services: [{name, state}], running_count, total}``.
    Overall ``state`` is ``running`` only if every declared service is
    running; ``missing`` if no containers exist; otherwise ``partial``.
    """
    rc, out, _ = await _run(
        ["docker", "compose", "-p", lab.compose_project,
         "-f", str(lab.compose_file), "ps", "--format", "json"],
        timeout=10,
    )
    if rc != 0:
        # Preserve the previous known state instead of flapping to "missing" —
        # a transient ps failure shouldn't make the UI claim the stack is gone.
        cached = _compose_status_cache.get(lab.id)
        if cached is not None:
            return cached
        return {"state": "missing", "services": [], "running_count": 0,
                "total": len(lab.compose_services)}

    # `docker compose ps --format json` returns either a single JSON object
    # per line (newer compose) or a single JSON array (older compose). Handle
    # both shapes defensively.
    services: list[dict[str, Any]] = []
    text = out.strip()
    try:
        if text.startswith("["):
            services = json.loads(text or "[]")
        else:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    services.append(json.loads(line))
    except json.JSONDecodeError:
        services = []

    parsed = [
        {"name": s.get("Service") or s.get("Name") or "",
         "state": str(s.get("State") or "unknown").lower()}
        for s in services
    ]
    running = sum(1 for s in parsed if s["state"] == "running")
    total = len(lab.compose_services) or len(parsed)
    overall = ("missing" if not parsed
               else "running" if running == total and total > 0
               else "partial")
    result = {"state": overall, "services": parsed,
              "running_count": running, "total": total}
    _compose_status_cache[lab.id] = result
    return result


async def compose_images_present(lab: LabDef) -> bool:
    """True if every image the compose file references exists locally.

    Used as the readiness signal for compose labs in place of the single
    ``image_tag`` probe, which only ever materializes for labs that *build*
    a local image (vulhub-net) and is permanently absent for pull-only labs
    (webgoat, crapi). ``docker compose config --images`` lists exactly the
    images ``up`` would need; we then ``image inspect`` each.
    """
    rc, out, _ = await _run(
        ["docker", "compose", "-p", lab.compose_project,
         "-f", str(lab.compose_file), "config", "--images"],
        timeout=10,
    )
    imgs = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    if rc != 0 or not imgs:
        # Fall back to the legacy probe tag if compose config is unavailable.
        return await image_exists(lab.image_tag)
    for img in imgs:
        if not await image_exists(img):
            return False
    return True


async def get_status(lab_id: str) -> dict[str, Any]:
    lab = LABS[lab_id]
    daemon = await docker_running()
    bs = _build_state(lab_id)
    # Reconcile orphaned "building" state. If the backend was reloaded mid-build
    # the asyncio Task is gone but bs.status still says "building" — the UI would
    # poll forever waiting for a finish event that can't arrive. Decide based on
    # whether the target image now exists.
    if bs.status == "building" and (bs.task is None or bs.task.done()):
        image_now = daemon and await image_exists(lab.image_tag)
        bs.finished_at = bs.finished_at or time.time()
        if image_now:
            bs.status = "built"
            bs.log.append("✓ build completed (state recovered after restart)")
        else:
            bs.status = "error"
            bs.error = "build interrupted (backend restarted)"
            bs.log.append("✗ build interrupted — backend restarted before completion")
    base = {
        "lab":              _lab_summary(lab),
        "docker_running":   daemon,
        "build_status":     bs.status,
        "build_error":      bs.error,
        "build_started_at": bs.started_at,
        "build_finished_at": bs.finished_at,
        "build_log_tail":   list(bs.log),
    }
    if not daemon:
        base["image_exists"] = False
        base["container"] = {"state": "missing"}
        if lab.kind == "compose":
            base["compose"] = {"state": "missing", "services": [],
                               "running_count": 0, "total": len(lab.compose_services)}
        return base

    if lab.kind == "single":
        base["image_exists"] = await image_exists(lab.image_tag)
        base["container"]    = await container_state(lab.container_name)
        return base

    # Compose lab. Readiness = every image the compose file references is
    # present locally (built or pulled). The single probe tag is unreliable
    # for pull-only stacks, so we ask compose what images it needs.
    base["image_exists"] = await compose_images_present(lab)
    comp = await compose_status(lab)
    base["compose"] = comp
    # Surface a single ``container`` field too so the UI can use the same
    # status-pill logic for both kinds: state="running" iff the compose
    # stack is fully up.
    base["container"] = {"state": comp["state"], "status": "", "started_at": None, "exit_code": None}
    return base


async def start_build(lab_id: str) -> dict[str, Any]:
    """Kick off ``docker build`` as a background task. Returns immediately.

    If a build is already running for this lab, the existing task is
    returned and a duplicate build is not started.
    """
    lab = LABS[lab_id]
    bs = _build_state(lab_id)
    if bs.status == "building" and bs.task and not bs.task.done():
        return {"status": "already_building"}

    if not await docker_running():
        return {"status": "error", "error": "Docker daemon is not running"}

    bs.status = "building"
    bs.started_at = time.time()
    bs.finished_at = None
    bs.error = None
    bs.log.clear()
    if lab.kind == "compose":
        bs.log.append(
            f"$ docker compose -p {lab.compose_project} "
            f"-f backend/labs/{lab.build_dir}/docker-compose.yml build"
        )
    else:
        bs.log.append(f"$ docker build -t {lab.image_tag} backend/labs/{lab.build_dir}/")
    bs.task = asyncio.create_task(_run_build(lab_id))
    return {"status": "building"}


async def start_lab(lab_id: str) -> dict[str, Any]:
    """Start the lab. For single-container labs runs ``docker run``; for
    compose labs runs ``docker compose up -d``."""
    lab = LABS[lab_id]
    if not await docker_running():
        return {"status": "error", "error": "Docker daemon is not running"}

    if lab.kind == "compose":
        # Compose stacks fetch their own images on `up -d`. We must NOT gate on
        # ``image_exists(lab.image_tag)`` here: pull-only labs (webgoat, crapi)
        # reference upstream ``image:`` refs and never produce the local probe
        # tag, so the old guard rejected every start with "Image not built".
        # ``up -d`` pulls/builds anything missing — give it a long timeout so a
        # cold pull of a multi-service stack (crapi) doesn't get killed.
        cmd = ["docker", "compose", "-p", lab.compose_project,
               "-f", str(lab.compose_file), "up", "-d"]
        rc, out, err = await _run(cmd, timeout=600)
        if rc != 0:
            return {"status": "error", "error": (err or out).strip()[:500]}
        return {"status": "running"}

    if not await image_exists(lab.image_tag):
        return {"status": "error", "error": "Image not built — build the lab first"}

    # Idempotent: if the container is already up, hand back the same shape we
    # return on a fresh start. Only wipe a stopped/dead container — never the
    # one the user might already be using.
    state = (await container_state(lab.container_name))["state"]
    if state == "running":
        return {"status": "running", "note": "already running"}
    if state != "missing":
        await _run(["docker", "rm", "-f", lab.container_name], timeout=15)

    cmd = ["docker", "run", "-d", "--name", lab.container_name]
    for cport, hport in lab.port_map.items():
        # Loopback-only publishing — labs must never be reachable off-host.
        cmd += ["-p", f"127.0.0.1:{hport}:{cport}"]
    cmd += [lab.image_tag]

    rc, out, err = await _run(cmd, timeout=30)
    if rc != 0:
        return {"status": "error", "error": (err or out).strip()[:500]}
    return {"status": "running", "container_id": out.strip()[:12]}


async def stop_lab(lab_id: str) -> dict[str, Any]:
    """Stop (and remove) the lab. Images are preserved."""
    lab = LABS[lab_id]
    if not await docker_running():
        return {"status": "error", "error": "Docker daemon is not running"}

    if lab.kind == "compose":
        cmd = ["docker", "compose", "-p", lab.compose_project,
               "-f", str(lab.compose_file), "down", "-v"]
        rc, _, err = await _run(cmd, timeout=60)
        if rc != 0:
            return {"status": "error", "error": err.strip()[:500]}
        _compose_status_cache.pop(lab.id, None)
        return {"status": "stopped"}

    state = (await container_state(lab.container_name))["state"]
    if state == "missing":
        return {"status": "stopped"}

    rc, _, err = await _run(["docker", "rm", "-f", lab.container_name], timeout=30)
    if rc != 0:
        return {"status": "error", "error": err.strip()[:500]}
    return {"status": "stopped"}


async def _image_size(image_tag: str) -> int:
    """Bytes on disk for ``image_tag`` (0 if missing/unknown)."""
    rc, out, _ = await _run(
        ["docker", "image", "inspect", "--format", "{{.Size}}", image_tag], timeout=5,
    )
    if rc != 0:
        return 0
    try:
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


async def remove_lab(lab_id: str, purge_image: bool = True) -> dict[str, Any]:
    """Tear a lab down completely: stop + remove containers, and (by default)
    delete its image(s) to reclaim disk.

    Returns ``{status: "removed", purged, bytes_freed, images_removed}``.
    ``bytes_freed`` is best-effort — it sums the sizes of the images we knew
    about before deletion. The in-memory build state is reset so the UI flips
    back to "NOT BUILT".
    """
    lab = LABS[lab_id]
    if not await docker_running():
        return {"status": "error", "error": "Docker daemon is not running"}

    images_removed: list[str] = []
    bytes_freed = 0

    if lab.kind == "compose":
        # Measure the stack's images before tearing down so we can report the
        # space reclaimed. `down --rmi all` removes every image the services
        # reference (built + pulled), `-v` drops named volumes.
        rc, out, _ = await _run(
            ["docker", "compose", "-p", lab.compose_project,
             "-f", str(lab.compose_file), "config", "--images"], timeout=10,
        )
        imgs = [ln.strip() for ln in (out or "").splitlines() if ln.strip()] if rc == 0 else []
        if purge_image:
            for img in imgs:
                sz = await _image_size(img)
                if sz:
                    bytes_freed += sz
                    images_removed.append(img)
        down = ["docker", "compose", "-p", lab.compose_project,
                "-f", str(lab.compose_file), "down", "-v", "--remove-orphans"]
        if purge_image:
            down += ["--rmi", "all"]
        rc, _, err = await _run(down, timeout=180)
        if rc != 0:
            return {"status": "error", "error": err.strip()[:500]}
        _compose_status_cache.pop(lab.id, None)
    else:
        # Remove the container (ignore "no such container").
        await _run(["docker", "rm", "-f", lab.container_name], timeout=30)
        if purge_image and await image_exists(lab.image_tag):
            sz = await _image_size(lab.image_tag)
            rc, _, err = await _run(["docker", "rmi", "-f", lab.image_tag], timeout=60)
            if rc != 0:
                return {"status": "error", "error": err.strip()[:500]}
            bytes_freed += sz
            images_removed.append(lab.image_tag)

    # Reset build state so the card stops claiming the image is built.
    bs = _build_state(lab_id)
    bs.status = "idle"
    bs.error = None
    bs.started_at = bs.finished_at = None
    bs.log.clear()

    return {
        "status":         "removed",
        "purged":         purge_image,
        "bytes_freed":    bytes_freed,
        "images_removed": images_removed,
    }


# ── Sidecar exec ─────────────────────────────────────────────────────────────
async def sidecar_exec(
    lab_id: str,
    cmd: str,
    args: list[str],
    timeout: float = 120,
) -> dict[str, Any]:
    """Run a whitelisted command inside the lab's scanner sidecar.

    The sidecar is a container on the same docker bridge as the vulnerable
    hosts, so it can scan internal IPs (10.20.0.x) that aren't reachable
    from macOS. Returns ``{rc, stdout, stderr}``.

    Validation:
      * Lab exists and declares a ``sidecar_container``.
      * ``cmd`` is in ``sidecar_allowed_cmds``.
      * Each arg passes a permissive shell-metacharacter check — the call
        uses ``docker exec ... <cmd> <args...>`` with an argv list, so no
        shell is invoked, but we still reject obvious injection attempts.
    """
    lab = LABS.get(lab_id)
    if lab is None:
        return {"rc": -1, "stdout": "", "stderr": "unknown lab"}
    if not lab.sidecar_container or not lab.sidecar_allowed_cmds:
        return {"rc": -1, "stdout": "", "stderr": "lab has no sidecar"}
    if cmd not in lab.sidecar_allowed_cmds:
        return {"rc": -1, "stdout": "",
                "stderr": f"command not allowed: {cmd}"}

    BAD = set(";|&`$\n\r\0")
    for a in args:
        if not isinstance(a, str) or len(a) > 256 or any(c in BAD for c in a):
            return {"rc": -1, "stdout": "", "stderr": f"invalid arg: {a!r}"}
        # Reject `-`-prefixed args. The whitelisted commands (nmap, curl, ...)
        # accept option flags like `--script` / `-K` that can pivot to code
        # execution inside the sidecar; the sidecar API is meant for plain
        # positional targets only.
        if a.startswith("-"):
            return {"rc": -1, "stdout": "",
                    "stderr": f"arg may not start with '-': {a!r}"}

    if not await docker_running():
        return {"rc": -1, "stdout": "", "stderr": "docker daemon is not running"}

    rc, out, err = await _run(
        ["docker", "exec", lab.sidecar_container, cmd, *args],
        timeout=timeout,
    )
    return {"rc": rc, "stdout": out, "stderr": err}


# ── Internals ────────────────────────────────────────────────────────────────
def _lab_summary(lab: LabDef) -> dict[str, Any]:
    return {
        "id":              lab.id,
        "name":            lab.name,
        "summary":         lab.summary,
        "kind":            lab.kind,
        "category":        lab.category,
        "image_tag":       lab.image_tag,
        "container_name":  lab.container_name,
        "port_map":        {str(k): v for k, v in lab.port_map.items()},
        "primary_url":     lab.primary_url,
        "default_creds":   lab.default_creds,
        "compose_services": list(lab.compose_services),
        "has_sidecar":     bool(lab.sidecar_container and lab.sidecar_allowed_cmds),
        "sidecar_cmds":    list(lab.sidecar_allowed_cmds),
        "suggested_steps": [
            {"label": s.label, "route": s.route, "query": s.query, "description": s.description}
            for s in lab.suggested_steps
        ],
    }


async def _run(cmd: list[str], timeout: float = 30) -> tuple[int, str, str]:
    """Run a command, capture stdout+stderr separately, return (rc, out, err)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return -1, "", f"command timed out after {timeout}s"
    return (proc.returncode or 0,
            out.decode("utf-8", "replace"),
            err.decode("utf-8", "replace"))


async def _run_build(lab_id: str) -> None:
    """Stream ``docker build`` (single) or ``docker compose build`` (compose)
    into the lab's in-memory log."""
    lab = LABS[lab_id]
    bs = _build_state(lab_id)
    build_path = LABS_DIR / lab.build_dir
    if not build_path.exists():
        bs.status = "error"
        bs.error = f"build directory missing: {build_path}"
        bs.finished_at = time.time()
        bs.log.append(bs.error)
        return

    if lab.kind == "compose":
        # Two passes: `build` materializes any service with a `build:` section
        # (vulhub-net); `pull --ignore-buildable` fetches upstream `image:`
        # services (webgoat, crapi) while skipping the ones we just built — so
        # it never errors trying to pull a local-only tag off a registry.
        base_cmd = ["docker", "compose", "-p", lab.compose_project,
                    "-f", str(lab.compose_file)]
        cmds = [base_cmd + ["build"], base_cmd + ["pull", "--ignore-buildable"]]
    else:
        cmds = [["docker", "build", "-t", lab.image_tag, str(build_path)]]

    rc = 0
    try:
        for cmd in cmds:
            bs.log.append(f"$ {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip()
                if text:
                    bs.log.append(text)
            rc = await proc.wait()
            if rc != 0:
                break
    except Exception as e:
        bs.status = "error"
        bs.error = f"build failed: {e}"
        bs.finished_at = time.time()
        bs.log.append(bs.error)
        return

    bs.finished_at = time.time()
    if rc == 0:
        bs.status = "built"
        bs.log.append("✓ build succeeded")
    else:
        bs.status = "error"
        bs.error = f"docker build exited {rc}"
        bs.log.append(f"✗ build failed (exit {rc})")
