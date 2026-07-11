"""CI smoke tests for the FastAPI backend.

These are the floor — every endpoint listed here must return a clean 2xx
on a fresh install with no API keys, no engagements, and no external
tooling installed. If a probe regresses to 500, that is a real bug the
smoke test just caught; do not delete the test to make CI green.

REST probes use httpx.AsyncClient against the ASGI app in-process — no
live uvicorn needed. WebSocket probes use Starlette's TestClient (httpx
itself doesn't speak the WS protocol against ASGI), and only exercise
the handshake → first server event handshake step for safe, non-routable
targets. We deliberately never run a destructive or exploit WS route here.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient


AUTH = {"X-MHP-Token": "smoke-token"}


@pytest.fixture
def _patched_app(temp_db, monkeypatch):
    """Boot the real ASGI app with a known auth token + temp DB.

    Mirrors how the Electron preload bootstraps: fetch the per-launch token
    once, then attach it via X-MHP-Token. We bypass /auth/token by pinning
    the module global to a fixed value so every test uses the same header.
    """
    from lib import auth as auth_mod
    monkeypatch.setattr(auth_mod, "AUTH_TOKEN", "smoke-token")
    # httpx and TestClient both report client.host as "testclient" — accept
    # it as loopback so the auth dep doesn't reject the in-process call.
    monkeypatch.setattr(
        auth_mod, "_LOOPBACK_HOSTS",
        auth_mod._LOOPBACK_HOSTS | {"testclient"},
    )
    from main import app
    return app


@pytest_asyncio.fixture
async def client(_patched_app):
    transport = ASGITransport(app=_patched_app)
    async with AsyncClient(transport=transport, base_url="http://testclient") as c:
        yield c


# ── REST probes ─────────────────────────────────────────────────────────────
#
# Every endpoint here must respond cleanly. The set is the intersection of
# "always available on a fresh install" and "load-bearing for app startup or
# the Electron renderer's first render".

@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body.get("version")


@pytest.mark.asyncio
async def test_version(client):
    r = await client.get("/version")
    assert r.status_code == 200
    assert r.json().get("version")


@pytest.mark.asyncio
async def test_system_info(client):
    # /system/info is auth-gated since the security tightening — the
    # Electron renderer fetches the token before any /system/info call.
    r = await client.get("/system/info", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    # Renderer hides platform-locked tools off these flags — keep them stable.
    assert "platform" in body
    assert {"is_mac", "is_linux", "is_windows"}.issubset(body)


@pytest.mark.asyncio
async def test_settings_api_key_status(client):
    r = await client.get("/settings/api-key/status", headers=AUTH)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_settings_keys(client):
    r = await client.get("/settings/keys", headers=AUTH)
    assert r.status_code == 200
    # Named-key listing is the source of truth for the Settings page's
    # "configured providers" badges — must always be a list.
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_chat_config(client):
    # /chat/config is loopback-only but not token-gated — the renderer calls
    # it before /auth/token has finished bootstrapping. Sending the token
    # anyway is harmless and matches Electron's behaviour on subsequent calls.
    r = await client.get("/chat/config", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert "provider" in body
    assert "usable" in body


@pytest.mark.asyncio
async def test_tcpdump_status(client):
    # tcpdump/status is Unix-only — on macOS/Linux CI it 200s with the
    # passwordless-sudo flag; on Windows the platform guard returns 501.
    # Either is fine; 500 is not. The router is Tier-2 (raw-socket capture)
    # and is not in the exposed set by default, so its route 404s — accept
    # that when unexposed, and skip the liveness contract entirely.
    from lib import exposure
    r = await client.get("/tcpdump/status", headers=AUTH)
    if not exposure.is_exposed("tcpdump"):
        assert r.status_code == 404
        return
    assert r.status_code in (200, 501)


@pytest.mark.asyncio
async def test_nmap_status(client):
    # Returns available:false when the binary isn't installed (CI runners
    # don't have nmap) — that's the contract, not an error.
    r = await client.get("/nmap/status", headers=AUTH)
    assert r.status_code == 200
    assert "available" in r.json()


@pytest.mark.asyncio
async def test_cvss_calculate(client):
    # CVSS v3.1 reference vector — Critical 9.8. Keeps the scoring formula
    # honest in CI; if the math drifts, this assertion catches it before
    # any finding gets a wrong band.
    r = await client.get(
        "/cvss/calculate?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        headers=AUTH,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["base_score"] == 9.8
    assert body["severity"] == "Critical"
    assert body["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.asyncio
async def test_labs(client):
    r = await client.get("/labs", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert "labs" in body
    assert "docker_available" in body


@pytest.mark.asyncio
async def test_labs_preflight(client):
    # State will vary by host (CI runners don't have colima), but the
    # endpoint must always respond with the documented contract so the
    # Labs popup can switch on it.
    r = await client.get("/labs/preflight", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body.get("state") in {
        "ok", "binary_missing", "daemon_stopped", "socket_unreachable",
    }
    for key in ("colima_path", "docker_path", "hint", "command"):
        assert key in body


@pytest.mark.asyncio
async def test_labs_runtime_status(client):
    # The slim alias the app-shell banner polls. Same underlying state
    # machine as /labs/preflight, but with the two booleans the banner
    # switches on already computed so the renderer never has to map states.
    r = await client.get("/labs/runtime/status", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body.get("state") in {
        "ok", "binary_missing", "daemon_stopped", "socket_unreachable",
    }
    assert isinstance(body.get("needs_install"), bool)
    assert isinstance(body.get("needs_start"), bool)
    # Booleans must be derived consistently from state.
    assert body["needs_install"] == (body["state"] == "binary_missing")
    assert body["needs_start"] == (
        body["state"] in {"daemon_stopped", "socket_unreachable"}
    )
    for key in ("colima_path", "docker_path"):
        assert key in body


@pytest.mark.asyncio
async def test_engagements(client):
    r = await client.get("/engagements", headers=AUTH)
    assert r.status_code == 200
    assert "engagements" in r.json()


@pytest.mark.asyncio
async def test_findings_happy_path(client):
    # /findings is the evidence layer: it must accept an engagement_id,
    # list cleanly when empty, create a promoted finding, and surface it
    # back via the standalone endpoint and the per-engagement list.
    create = await client.post(
        "/engagements", headers=AUTH,
        json={"name": "smoke", "scope": [], "exclusions": [], "notes": ""},
    )
    assert create.status_code == 200, create.text
    eid = create.json()["id"]

    listed = await client.get(f"/findings?engagement_id={eid}", headers=AUTH)
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body == {"count": 0, "findings": []}

    posted = await client.post(
        "/findings", headers=AUTH,
        json={
            "engagement_id": eid,
            "title": "Open SSH on 22",
            "severity": "medium",
            "tool": "port-scanner",
            "target": "127.0.0.1",
            "evidence": "22/tcp open ssh OpenSSH 9.6",
            "description": "Default SSH banner exposed.",
        },
    )
    assert posted.status_code == 200, posted.text
    fid = posted.json()["id"]
    assert posted.json()["status"] == "open"
    assert posted.json()["tool"] == "port-scanner"

    # Single-finding read goes through the standalone endpoint.
    single = await client.get(f"/findings/{fid}", headers=AUTH)
    assert single.status_code == 200
    assert single.json()["title"] == "Open SSH on 22"

    # Patching status to a canonical value bumps updated_at and is audited.
    patched = await client.patch(
        f"/findings/{fid}", headers=AUTH,
        json={"status": "confirmed"},
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "confirmed"

    # Audit log records the create + patch as finding-* actions.
    audit = await client.get(
        f"/audit-log?engagement_id={eid}&tool=finding-create", headers=AUTH,
    )
    assert audit.status_code == 200
    assert audit.json()["count"] >= 1

    # Evidence timeline: promoting the finding above auto-captured one
    # scan_output item from the seeded `evidence` field. Listing returns it
    # under the multi-item contract, and a manual add lands a second item.
    evlist = await client.get(f"/findings/{fid}/evidence", headers=AUTH)
    assert evlist.status_code == 200, evlist.text
    evbody = evlist.json()
    assert evbody["count"] == 1
    first = evbody["items"][0]
    assert first["type"] == "scan_output"
    assert first["source_tool"] == "port-scanner"
    assert "OpenSSH" in first["content"]

    added = await client.post(
        f"/findings/{fid}/evidence", headers=AUTH,
        json={"type": "note", "content": "Reproduced from a separate host."},
    )
    assert added.status_code == 200, added.text
    eid_added = added.json()["id"]
    assert added.json()["type"] == "note"

    after = await client.get(f"/findings/{fid}/evidence", headers=AUTH)
    assert after.json()["count"] == 2

    # Evidence mutations leave audit-log breadcrumbs.
    ev_audit = await client.get(
        f"/audit-log?engagement_id={eid}&tool=evidence-add", headers=AUTH,
    )
    assert ev_audit.status_code == 200
    assert ev_audit.json()["count"] >= 1

    removed = await client.delete(
        f"/findings/{fid}/evidence/{eid_added}", headers=AUTH,
    )
    assert removed.status_code == 200
    assert removed.json()["deleted"] is True

    # Report preview: structured payload that the frontend renders. Must
    # carry header (engagement_name), exec_summary (counts + summary),
    # the findings list with evidence timeline, methodology and disclaimer.
    preview = await client.get(
        f"/reports/engagement/{eid}/preview", headers=AUTH,
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["header"]["engagement_name"] == "smoke"
    assert body["exec_summary"]["total"] == 1
    assert body["exec_summary"]["summary"]  # non-empty template summary
    assert len(body["findings"]) == 1
    assert body["findings"][0]["title"] == "Open SSH on 22"
    assert body["findings"][0]["evidence"]  # auto-captured item
    assert body["disclaimer"]
    assert body["methodology"]

    deleted = await client.delete(f"/findings/{fid}", headers=AUTH)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


# ── WebSocket handshake smoke tests ─────────────────────────────────────────
#
# Each canonical streaming router gets one probe that confirms the upgrade
# handshake works and the server emits its first event. We pick safe,
# non-routable targets — 127.0.0.1 (own loopback) for the probes that need
# a host — so nothing leaves the runner. Destructive / exploit WS routes
# (sqli, xss, cmdi, kerberos_roast, etc.) are intentionally out of scope.

def _ws_url(path: str) -> str:
    # require_local_auth's WS path reads the token from ?token=.
    return f"{path}?token=smoke-token"


def test_ws_port_scan_handshake(_patched_app):
    """Port-scan WS: handshake → 'scope' verdict → connection survives."""
    with TestClient(_patched_app) as tc:
        with tc.websocket_connect(_ws_url("/ws/port-scan")) as ws:
            # ports="22" keeps the synthetic scan trivially small in case the
            # server starts it before we get the chance to send "stop".
            ws.send_json({
                "target": "127.0.0.1", "ports": "22",
                "timeout": 0.1, "threads": 1, "mode": "lab",
            })
            first = ws.receive_json()
            assert first["type"] in ("scope", "started", "error"), first
            ws.send_json({"action": "stop"})


def test_ws_lan_scan_handshake(_patched_app):
    """LAN-scan WS: handshake → 'started' or 'error' (no live subnet on CI)."""
    with TestClient(_patched_app) as tc:
        with tc.websocket_connect(_ws_url("/ws/lan-scan")) as ws:
            # Tiny CIDR — /30 leaves 2 host addresses. Doesn't matter if the
            # scan returns nothing; we only assert the handshake completed.
            ws.send_json({"network": "127.0.0.0/30", "mode": "lab"})
            first = ws.receive_json()
            assert first["type"] in ("scope", "started", "error"), first
            ws.send_json({"action": "stop"})


def test_ws_ping_handshake(_patched_app):
    """Ping WS: handshake → 'scope' or 'started' on loopback target."""
    with TestClient(_patched_app) as tc:
        with tc.websocket_connect(_ws_url("/ws/ping")) as ws:
            # count=1 so the underlying `ping` process exits on its own even
            # if our stop signal races with cleanup.
            ws.send_json({
                "target": "127.0.0.1", "count": 1,
                "interval": 1.0, "mode": "lab",
            })
            first = ws.receive_json()
            assert first["type"] in ("scope", "started", "error"), first
            ws.send_json({"action": "stop"})
