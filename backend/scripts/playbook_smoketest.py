#!/usr/bin/env python3
"""Smoketest for the playbook subsystems against the live backend.

Two surfaces:

  1. /playbooks   — the declarative CRUD the s-ide UI steps through
                    (create -> get -> update -> coverage -> list -> delete-skip).
  2. /ws/preset-run — the executable preset engine: actually runs a built-in
                    playbook's tool steps against a target and streams
                    step/finding events. We point it at a running lab.

Run with the dev backend on 8799:  SIDE_BASE=http://127.0.0.1:8799 python3 scripts/playbook_smoketest.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.request

BASE = os.environ.get("SIDE_BASE", "http://127.0.0.1:8765")
WS_BASE = BASE.replace("http://", "ws://").replace("https://", "wss://")


def _token() -> str:
    with urllib.request.urlopen(f"{BASE}/auth/token", timeout=5) as r:
        return json.load(r)["token"]


TOKEN = _token()


def call(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    req.add_header("X-MHP-Token", TOKEN)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:  # type: ignore[name-defined]
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}


PASS, FAIL = "✓", "✗"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"   {PASS if ok else FAIL} {name:32} {detail}")
    return ok


def test_crud():
    print("── /playbooks CRUD ───────────────────")
    # create
    sc, pb = call("POST", "/playbooks", {
        "name": "Smoketest recon",
        "steps": [
            {"tool_id": "http_probe", "expected": "200/redirect",
             "methodology_ids": ["WSTG-INFO-02"]},
            {"tool_id": "fingerprint", "expected": "server banner",
             "methodology_ids": ["WSTG-INFO-08", "PTES-RECON"]},
        ],
    })
    pid = pb.get("id", "")
    if not check("create", sc == 200 and bool(pid), f"id={pid[:8]}"):
        return
    # get
    sc, got = call("GET", f"/playbooks/{pid}")
    check("get", sc == 200 and got.get("id") == pid and len(got.get("steps", [])) == 2,
          f"{len(got.get('steps', []))} steps")
    # step tool_ids are non-empty
    tids = [s.get("tool_id") for s in got.get("steps", [])]
    check("steps carry tool ids", all(tids), ", ".join(tids))
    # update (add a lab binding + a step)
    sc, upd = call("PUT", f"/playbooks/{pid}", {
        "name": "Smoketest recon v2",
        "lab_id": "juice-shop",
        "steps": got["steps"] + [{"tool_id": "sqli", "expected": "sql error",
                                  "methodology_ids": ["WSTG-INPV-05"]}],
    })
    check("update", sc == 200 and upd.get("lab_id") == "juice-shop" and len(upd.get("steps", [])) == 3,
          f"lab={upd.get('lab_id')} steps={len(upd.get('steps', []))}")
    # coverage
    sc, cov = call("POST", f"/playbooks/{pid}/coverage")
    check("coverage", sc == 200 and "required" in cov and "pct" in cov,
          f"{len(cov.get('required', []))} methodology ids, {cov.get('pct')}% covered")
    # list contains it
    sc, lst = call("GET", "/playbooks")
    check("list", sc == 200 and any(p["id"] == pid for p in lst.get("playbooks", [])),
          f"{len(lst.get('playbooks', []))} total")
    return pid


async def test_preset_run(target_url: str):
    print("\n── /ws/preset-run (executable) ───────")
    import websockets

    # Pick a built-in preset that actually runs against our lab: a low-risk,
    # no-auth, host/url preset with the fewest steps. The list payload carries
    # `step_count` (not the steps themselves), so filter on that.
    sc, data = call("GET", "/presets")
    presets = data.get("presets", [])
    check("presets listed", sc == 200 and len(presets) > 0,
          f"{len(presets)} presets, {len(data.get('tools', []))} tools")
    runnable = [p for p in presets
                if p.get("target_type") in ("host", "url", "domain")
                and (p.get("step_count") or 0) > 0
                and not p.get("requires_auth")]
    runnable.sort(key=lambda p: p.get("step_count") or 0)
    cand = runnable[0] if runnable else None
    if not cand:
        check("runnable preset found", False, "no no-auth host/url preset with steps")
        return
    pid = cand["id"]
    tt = cand.get("target_type")
    # host-type presets want a bare host/IP; url-type want the full URL.
    target = "127.0.0.1" if tt in ("host", "domain") else target_url
    print(f"   running preset '{pid}' ({cand.get('name')}, {cand.get('step_count')} steps) "
          f"against {target}")

    uri = f"{WS_BASE}/ws/preset-run?token={TOKEN}"
    steps_seen, findings_seen, errors = 0, 0, []
    final = None
    try:
        async with websockets.connect(uri, max_size=8_000_000) as ws:
            await ws.send(json.dumps({
                "preset": pid,
                "target": target,
                "authorized": True,
                "confirm": True,
                "mode": "lab",
            }))
            while True:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=90)
                except asyncio.TimeoutError:
                    errors.append("timeout waiting for events")
                    break
                ev = json.loads(raw)
                t = ev.get("type")
                if t in ("step", "step_start", "step_result"):
                    steps_seen += 1
                elif t == "finding":
                    findings_seen += 1
                elif t in ("error",):
                    errors.append(ev.get("message") or ev.get("code") or "error")
                elif t in ("done", "complete", "preset_done"):
                    final = ev
                    break
    except Exception as e:
        errors.append(f"{type(e).__name__}: {e}")

    check("preset stream ran", steps_seen > 0 or final is not None,
          f"{steps_seen} step events, {findings_seen} findings")
    check("no fatal errors", not errors, "; ".join(errors[:2]) if errors else "clean")


def main() -> int:
    test_crud()
    # Use a running lab as the executable target (juice-shop on 8083).
    target = os.environ.get("PLAYBOOK_TARGET", "http://127.0.0.1:8083")
    try:
        asyncio.run(test_preset_run(target))
    except Exception as e:
        check("preset-run harness", False, f"{type(e).__name__}: {e}")

    print("\n" + "=" * 46)
    npass = sum(1 for _, ok, _ in results if ok)
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{npass}/{len(results)} checks PASS")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
