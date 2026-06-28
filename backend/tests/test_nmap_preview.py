"""Tests for POST /nmap/preview — the dry-run that shows the exact argv a
scan would spawn, without spawning.

The point of the endpoint is fidelity and safety: the previewed command must
be what a real run executes (built through the same options_from_dict +
build_argv path), and the same validation that guards a run must reject unsafe
input here too — before the user commits.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


AUTH = {"X-MHP-Token": "testing-token"}


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setenv("MHP_BACKEND_HOST", "127.0.0.1")
    from lib import auth as auth_mod
    monkeypatch.setattr(auth_mod, "AUTH_TOKEN", "testing-token")
    monkeypatch.setattr(
        auth_mod, "_LOOPBACK_HOSTS",
        auth_mod._LOOPBACK_HOSTS | {"testclient"},
    )
    from main import app
    return TestClient(app)


def _preview(client, opts: dict):
    return client.post("/nmap/preview", headers=AUTH, json={"opts": opts})


def test_preview_renders_exact_command(client):
    r = _preview(client, {
        "targets": ["example.com"], "scan_type": "syn",
        "service_version": True, "no_dns": True,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    # argv is a list and command is its shell-quoted join.
    assert body["argv"][-1] == "example.com"
    assert "-sS" in body["argv"] and "-sV" in body["argv"]
    assert "nmap" in body["command"]
    assert "-oX" in body["command"]
    # SYN scan is privileged.
    assert body["needs_privileged"] is True
    assert "nmap_found" in body


def test_preview_reflects_sudo_prefix(client):
    r = _preview(client, {"targets": ["10.0.0.1"], "scan_type": "connect",
                          "use_sudo": True})
    assert r.status_code == 200, r.text
    assert r.json()["command"].startswith("sudo -n ")
    # A TCP connect scan is not privileged.
    assert r.json()["needs_privileged"] is False


def test_preview_requires_a_target(client):
    r = _preview(client, {"scan_type": "syn"})
    assert r.status_code == 400, r.text
    assert r.json()["code"] == "INVALID_TARGET"


def test_preview_rejects_unsafe_extra_args_with_reason(client):
    # The dry-run must surface *why* a run would be rejected, before running.
    r = _preview(client, {"targets": ["example.com"],
                          "extra_args": "--script /tmp/evil.nse"})
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["code"] == "VALIDATION_ERROR"
    assert "script" in body["error"].lower()


def test_preview_rejects_shell_metacharacters(client):
    r = _preview(client, {"targets": ["example.com"],
                          "extra_args": "; rm -rf /"})
    assert r.status_code == 400, r.text
    assert r.json()["code"] == "VALIDATION_ERROR"
