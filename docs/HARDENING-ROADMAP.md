# s-ide — hardening & quality roadmap

Concrete, prioritized follow-up work that came out of the shell-foundation-lane
review. The first block is **already in flight** as a stacked set of PRs; the rest
is **specified but not yet built** — each item is scoped enough to pick up as its
own PR. Ordered by leverage.

## Shipped / in review (the review-fix stack)

These landed as PRs stacked on `shell-foundation-lane`:

| # | Change | Class |
|---|---|---|
| PR#19 | CSP `app.isPackaged` gate, `FILE_LINE_RE` tightening, FixDiff stale-async guard, template-validator narrowing, dead/stale bus events (`selectAsset`, `modelChanged{run}`), `nodeAnchor` null-for-module, `KnownViewId` trim + registry-miss warn | correctness |
| PR#20 | One shared `lib/redact` (union of 6 diverged copies) | security dedup |
| PR#21 | One shared `lib/severity` (order/rank/colour) | dedup |
| PR#22 | Demo/acceptance panels out of the shipped registry | cleanup |
| PR#23 | Bus producer/consumer contract test + `modelChanged` entity narrowing | structural |
| PR#24 | `useBus` stable subscription (no per-render churn) | efficiency |
| PR#25 | Feature reads routed through the model seam (CONTRACT rule 1) | architecture |
| PR#26 | Collapse 6 duplicate fake-Request shims in `preset_engine` | dedup |

## Specified next (each a standalone PR)

### 1. Close the remaining efficiency gaps in the model read-path
The `useBus` churn is fixed (PR#24); two bigger items remain and were deferred
because they need careful cache-invalidation design, not a quick edit:

- **SearchPanel re-runs the 4000-file `scanSource` on every `modelChanged`.**
  Source files don't change when a finding/asset/run mutates — only on an
  engagement or `source_root` change. Cache the scan result keyed by
  `(engagementId, source_root)` and only re-run on those (or an explicit rescan).
  `scanSource` already lives behind the model seam (PR#25), so the cache belongs
  there. Gate SearchPanel's corpus refetch on `modelChanged.entity` too (it
  currently ignores it).
- **`model.ts` getters re-fetch + linear-scan per call.** `getFinding`/`getEngagement`
  each pull a full list and `.find()` on every call, so resolving N ids is N
  round-trips. Back them with a memoized snapshot indexed by `Map<id, record>`.
  **Invalidation is the hard part:** findings invalidate on `modelChanged{finding}`
  (safe), but the **engagement list has no `modelChanged` signal** (create/rename
  don't emit one), so an engagement-list cache would go stale. Either add an
  engagement-list mutation signal first, or scope the memo to findings only.

### 2. Adversarially test the scope + attestation gates
`tests/test_spine.py` covers the happy path (arm → run → finding). The security
value is in the *negative* paths, which are currently unproven:
- a run against an **un-attested** engagement is rejected;
- a run whose target is **out of scope** is rejected even if the sub-target is armed;
- the per-step `_InternalRequest` lab-mode stand-in **cannot** be reached on a
  non-lab path (prove the run-level gate is the real barrier);
- an attestation cannot be forged or replayed across engagements.
Write these as `pytest` cases asserting the 403 / rejection, not just the success.

### 3. Grow the cross-panel interaction test layer
The unit tests are broad but missed every wiring bug the review found — the bugs
live *between* panels. The phase-0 contract test is the right shape; extend it:
- one "click X → panel Y reacts" acceptance test per selection event
  (`selectFinding`, `selectAnchor`, `selectStep`, `selectSubTarget`);
- a stale-async race test per async panel (FixDiff got one in PR#19; Pivot and
  the debugger have the guard but no test);
- keep the bus-contract audit (PR#23) green as the cheap static backstop.

### 4. Audit the rest of the packaged-build posture
The CSP gate is fixed; sweep for the same class of "dev signal leaks into prod":
- every `process.env.*` read in `electron/main.cjs` that changes security posture
  → gate on `app.isPackaged`;
- confirm `RAMPART_EXPOSE_ALL` / Tier-2/3 routers cannot be enabled in a packaged
  build by environment alone;
- confirm node integration / context isolation settings on the `BrowserWindow`.

### 5. Supply-chain gate in CI
Add a lockfile audit (npm + the pip/PyInstaller set) to CI — fail on a known-bad
advisory or an install-script/typosquat signal. `pkgxray` already exists in this
author's toolbelt and fits here.

### 6. Plan the router-snapshot exit
`CLAUDE.md` treats `backend/routers/` as a vendored snapshot ("prefer adding local
modules over hand-editing them"). That's pragmatic but caps how deep the spine can
go. Pick the handful of routers that actually carry engagement/spine state, fork-
and-own those (with tests), and keep the rest vendored. Track which is which.

## Scope discipline (not a PR — a standing principle)

s-ide spans a VS Code shell, ~38 tools, 10 training labs, the engagement spine,
findings, reporting, copilot, graph, timeline, evidence debugger, pivot,
templates, and suggestions. That breadth is why several features shipped ~80%
wired. The core loop that defines the product is **engagement → scoped tool run →
finding → report**; that path should be flawless and obviously solid. Everything
else should be labelled experimental in the UI until it is, and a new feature is
worth less than finishing the wiring on an existing one. The bus-contract test
(PR#23) is one enforcement lever for "wired, not almost-wired"; keep adding them.
