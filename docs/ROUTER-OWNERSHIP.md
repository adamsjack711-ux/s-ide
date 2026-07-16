# Router ownership & the vendored-snapshot exit

`CLAUDE.md` treats `backend/routers/` as a vendored snapshot ("prefer adding local
modules over hand-editing them"). That's the right default for the ~90 tool
routers inherited from HackingPal, but it needs a boundary: which routers actually
carry engagement/spine state (and so must be **owned** — changed freely, with
tests) versus which are pure tool endpoints that stay vendored?

This document is the answer (roadmap item 6). The headline finding is that the
exit is **smaller than it looks**: the engagement model couples to the tool
routers through an s-ide-owned **lib seam**, not through hand-edits to the vendored
routers themselves.

## The three tiers

### Tier A — owned (engagement/spine state + the safety gate)
These carry or manage engagement-spine state and the authorization gate. They are
s-ide's core and must be freely editable, each backed by tests. Change them without
the vendored-snapshot caution.

| Module | Role |
|---|---|
| `lib/spine.py` + `routers/spine.py` | Target / sub-target / engagement / pairing model; the run gate (`require_armed` → scope + attestation). |
| `lib/safety.py` + `routers/safety.py` | Authorization attestations + the `require_active_allowed` hard gate. |
| `lib/scope.py` + `routers/scope.py` | Scope enforcement (`enforce_rest`, `check_combined`, default-deny). |
| `lib/preset_engine.py` + `routers/presets.py` | The preset/playbook engine that drives tool routers in-process. |
| `lib/engagements.py` | Engagement + audit-ledger storage. |
| `routers/summarize.py` | Persists per-engagement `tool_summaries` for the report. |
| `lib/exposure.py` | The capability gate (Tier-1 allowlist; `RAMPART_EXPOSE_ALL`). |

Test coverage today: `tests/test_spine.py` (arm/run/finding + scope boundary) and
`tests/test_safety_gate.py` (the attestation negative paths). **Owning a module
means it should have tests** — extend this set as Tier-A changes.

### Tier B — the seam (the stable contract between vendored routers and owned libs)
The tool routers reach the engagement model **only** through these calls. Keep
their signatures stable and a vendored router never needs a hand-edit:

- `lib.scope.enforce_rest(target, engagement_id, mode, *, active=, action=)` — scope + (for active runs) the attestation gate.
- `lib.safety.require_active_allowed(target, engagement_id)` — the non-bypassable attestation hard gate.
- `lib.mode.get_engagement_id(request)` / `get_mode(request)` — where the engagement id / mode come from (the `X-MHP-Engagement-Id` header + `?engagement=`), so routers don't parse it themselves.

~50 of the ~90 tool routers import `lib.scope`/`lib.safety`; that call is the
*entire* coupling. Because the engagement id arrives via a header read by
`lib.mode` (not baked into router logic), the vendored routers were **not**
hand-edited to carry engagement state — they just call the seam.

### Tier C — vendored tool routers (the rest, ~90)
`nmap`, `tcpdump`, `dns_recon`, `tls_audit`, … Pure tool endpoints. Keep them as a
snapshot; add new tools as new local modules. They consume Tier B and carry no
engagement/spine state.

## The exit plan

The exit is mostly **already achieved** by the lib-seam architecture. What remains
is to make it explicit and keep it from eroding:

1. **Freeze the seam (Tier B).** Treat the three seam signatures as a contract; if
   one must change, change it in one place and let every vendored router pick it up
   unchanged. A seam change is an owned-code change (with tests), not a router edit.
2. **Own Tier A with tests.** Every change to a Tier-A module lands with a test.
   The adversarial gate tests (roadmap item 2) are the model; grow them as the
   spine deepens (e.g. attestation lifecycle, run auditing, report roll-up).
3. **Watch for a Tier-C router that starts carrying state.** The moment a tool
   router needs to *store* engagement/finding state (rather than call the seam),
   it has crossed into Tier A — fork-and-own it then, with tests, instead of
   hand-editing the snapshot. A cheap guard: a CI grep that flags a new
   `routers/*.py` importing `lib.spine`/`lib.engagements`/`create_pairing_finding`
   (today only `spine.py` + `summarize.py` do) so the boundary is enforced, not
   just documented.
4. **Don't fork the whole snapshot.** The value of the vendored ~90 is that they
   track upstream cheaply. Only Tier A is worth owning; resist the urge to
   fork-and-own tool routers that only call the seam.

## One-line summary

Own the libs (`spine`/`safety`/`scope`/`engagements`/`preset_engine`) + the spine
router, keep the three-call lib seam stable, and leave the ~90 tool routers
vendored — they couple to the engagement model only through that seam, so the
"exit" is a boundary to maintain, not a big migration to run.
