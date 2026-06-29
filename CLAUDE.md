# CLAUDE.md — s-ide

s-ide (working name) is an **IDE for security engagements**.
Full plan: `~/security-engagement-ide-PLAN.md`.

## Architecture

- **backend/** — FastAPI + SQLite. Treat the routers as a vendored snapshot:
  prefer adding new local modules over hand-editing them. The capability gate
  lives in `lib/exposure.py` + the `_inc()` gate in `main.py`.
- **Capability gate** (`backend/lib/exposure.py`): only Tier-1 (zero-setup) routers are
  registered. Tier 2/3 ship but 404 unless `RAMPART_EXPOSE_ALL=1`. To expose a tool,
  add its module key to `TIER1`. Web-exploit fuzzers are in `DEFERRED_TIER1` (held from v1).
- **frontend/** — new IDE shell. Key seams:
  - `src/shell/tools.ts` — the tool registry. Add a `ToolDescriptor` (ws or http) to wire a tool.
  - `src/shell/bus.ts` — in-process pub/sub (openTool / output / promote / findingsChanged).
  - `src/panels/ToolPanel.tsx` — the ONE generic tool surface (replaces per-tool pages).
  - `src/lib/*` — keeps the `X-MHP-*` token/header contract in sync with the
    backend. Don't rename headers without changing the backend.

## Conventions

- Tool contracts (WS init/event shapes, HTTP response types) are already encoded in
  `frontend/src/api.ts` — harvest them there rather than guessing.
- Engagement is the project spine; every backend write carries the active engagement via
  `X-MHP-Engagement-Id` (per-window pin via `?engagement=` query param).
- Scope is enforced server-side (`target_policy` default-deny external + engagement scope).
  Don't weaken `backend/config.json`.

## Verify

```bash
cd frontend && npx tsc --noEmit          # type-check
cd backend && python3 -c "import main"   # backend imports + gate
```
