# Backend provenance

This `backend/` is **vendored wholesale** from the HackingPal project — a plain
copy, not a submodule. s-ide reuses HackingPal's proven FastAPI + WebSocket
backend and its SQLite engagement/findings/CVSS/evidence/report spine.

| | |
|---|---|
| Upstream repo | `github.com/hackingpal/hackingpal` |
| Vendored from commit | **`60a38c456d69336509a628714a426e33506b1792`** |
| Date | 2026-06-27 |
| Branch | `fix/backend-tests-and-tool-catalog` |

## What changed on the way in

- Added `lib/exposure.py` — the **capability gate**. s-ide exposes only the
  zero-setup (Tier 1) toolset; Tier 2 (privilege/root) and Tier 3 (keys / Docker
  / cloud SDKs / hardware) routers ship in the tree but are **not registered**
  (their routes 404) unless `RAMPART_EXPOSE_ALL=1`.
- `main.py` router registration was rewritten to route every
  `app.include_router(...)` through `_inc(key, router, deps)`, which consults
  `exposure.is_exposed(key)`. Nothing else in the backend was modified.

## Re-syncing with upstream

`scripts/sync-upstream.sh` diffs this tree against a fresh HackingPal checkout so
new Tier-1 work can be cherry-picked manually. Re-exposing a gated tool is a
one-line change in `lib/exposure.py`.
