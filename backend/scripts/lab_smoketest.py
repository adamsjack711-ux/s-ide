#!/usr/bin/env python3
"""End-to-end smoketest for the Labs lifecycle against the live backend.

For every lab in the catalog it exercises the operator path:

    enable (add)  ->  build (if image missing)  ->  start  ->  verify running

and prints a per-lab PASS/FAIL table. Use ``--start-only`` to skip building
labs whose image is already present, ``--only id,id`` to scope to a subset,
and ``--no-build`` to fail (rather than build) when an image is missing.

It talks to the same loopback API the UI uses, so a green run here means the
UI's Add/Build/Start buttons will work too.
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.request
import json
import os

BASE = os.environ.get("SIDE_BASE", "http://127.0.0.1:8765")


def _token() -> str:
    with urllib.request.urlopen(f"{BASE}/auth/token", timeout=5) as r:
        return json.load(r)["token"]


TOKEN = _token()


def call(method: str, path: str, body: dict | None = None, timeout: float = 180) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    req.add_header("X-MHP-Token", TOKEN)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {"error": e.read().decode("utf-8", "replace")[:300]}
    except Exception as e:
        return -1, {"error": f"{type(e).__name__}: {e}"}


def lab_running(status: dict, kind: str) -> bool:
    if kind == "compose":
        st = (status.get("compose") or {}).get("state")
        return st in ("running", "partial")
    return (status.get("container") or {}).get("state") == "running"


def smoketest_lab(lab: dict, *, build: bool, build_timeout: float) -> dict:
    lid, kind = lab["id"], lab["kind"]
    result = {"id": lid, "kind": kind, "steps": [], "ok": True, "note": ""}

    def step(name: str, ok: bool, detail: str = "") -> bool:
        result["steps"].append((name, ok, detail))
        if not ok:
            result["ok"] = False
        return ok

    # 1. ENABLE (add to grid)
    sc, r = call("POST", f"/labs/{lid}/enable")
    if not step("enable", sc == 200 and r.get("enabled") is True, f"HTTP {sc} {r}"):
        return result

    # 2. STATUS — decide whether a build is needed
    sc, st = call("GET", f"/labs/{lid}/status", timeout=30)
    if not step("status", sc == 200, f"HTTP {sc} {r}"):
        return result
    have_image = bool(st.get("image_exists"))
    already_running = lab_running(st, kind)

    # 3. BUILD (only if image missing)
    if not have_image:
        if not build:
            return result if step("build", False, "image missing and --no-build set") else result
        sc, r = call("POST", f"/labs/{lid}/build")
        if not step("build:start", sc == 200 and r.get("status") in ("building", "already_building"),
                    f"HTTP {sc} {r}"):
            return result
        # Poll until build finishes
        deadline = time.time() + build_timeout
        last = ""
        while time.time() < deadline:
            sc, st = call("GET", f"/labs/{lid}/status", timeout=30)
            bstat = st.get("build_status")
            if bstat == "built":
                break
            if bstat == "error":
                tail = " | ".join((st.get("build_log_tail") or [])[-3:])
                return result if step("build", False, f"{st.get('build_error')}: {tail}") else result
            last = bstat or ""
            time.sleep(5)
        else:
            return result if step("build", False, f"timed out after {build_timeout}s (state={last})") else result
        step("build", True, f"{time.time() - (st.get('build_started_at') or time.time()):.0f}s")
    else:
        step("build", True, "image already present (skipped)")

    # 4. START
    sc, r = call("POST", f"/labs/{lid}/start", timeout=180)
    if not step("start", sc == 200 and r.get("status") == "running",
                f"HTTP {sc} {r}"):
        return result

    # 5. VERIFY running (give compose stacks a moment)
    running = False
    for _ in range(12):
        sc, st = call("GET", f"/labs/{lid}/status", timeout=30)
        if lab_running(st, kind):
            running = True
            break
        time.sleep(3)
    detail = ""
    if kind == "compose":
        comp = st.get("compose") or {}
        detail = f"{comp.get('running_count')}/{comp.get('total')} services {comp.get('state')}"
    else:
        detail = (st.get("container") or {}).get("state", "?")
    step("verify-running", running, detail)
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated lab ids")
    ap.add_argument("--no-build", action="store_true", help="fail instead of building missing images")
    ap.add_argument("--build-timeout", type=float, default=900.0)
    args = ap.parse_args()

    sc, cat = call("GET", "/labs/catalog", timeout=30)
    if sc != 200:
        print(f"FATAL: /labs/catalog -> HTTP {sc} {cat}")
        return 2
    labs = cat["labs"]
    if args.only:
        want = {x.strip() for x in args.only.split(",")}
        labs = [l for l in labs if l["id"] in want]

    print(f"Smoketesting {len(labs)} lab(s): {', '.join(l['id'] for l in labs)}\n")
    results = []
    for lab in labs:
        print(f"── {lab['id']} ({lab['kind']}) ─────────────────────")
        res = smoketest_lab(lab, build=not args.no_build, build_timeout=args.build_timeout)
        for name, ok, detail in res["steps"]:
            mark = "✓" if ok else "✗"
            print(f"   {mark} {name:16} {detail}")
        print(f"   => {'PASS' if res['ok'] else 'FAIL'}\n")
        results.append(res)

    print("=" * 50)
    print("SUMMARY")
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        failed = [s[0] for s in r["steps"] if not s[1]]
        print(f"  {mark:4}  {r['id']:16} {'(' + ', '.join(failed) + ' failed)' if failed else ''}")
    npass = sum(1 for r in results if r["ok"])
    print(f"\n{npass}/{len(results)} labs PASS")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
