# s-ide — Learning Sandbox: design & build (2026-06-28)

Extends the existing seams (bus.ts · tools registry · engagement/lab spine · sessionLog · generic ToolPanel). Does **not** refactor them. Builds the data model below as the single source of truth; the human report, agent export, and retest are all **views** over it (none authored by hand).

## Locked decisions
1. **Data model → backend SQLite**, extending the engagement spine (new tables + router; durable; hash-chainable).
2. **Fix-in-place → Monaco** editor panel, editing the **lab-container** source via the existing `/labs/{id}/sidecar/exec` seam. Fix→retest stays in the sandbox.
3. **Asset parsers → Discovery/Recon/Web subset first** (dns, ip, port_scan, http_probe, tls, fingerprint, cms, subdomain, takeover).
4. **Isolation self-check → gates lab-arming only** (real-target engagements may reach the internet). Fail closed for labs.
5. **Methodology → WSTG + PTES** (steps tagged with both; coverage ticks per id).
6. **Lab authoring → in-app authoring UI** (author learner_view/hints/solution/snapshot; solution stays server-side).
7. **Copilot confirm 'why' → both** (default deferred to promotion review; opt-in "ask me live" toggle).
8. **Progress → backend, global per-machine** (labs solved, vuln classes, methodology steps).

## Data model (backend, new tables alongside engagements/findings)
- **finding_method**(finding_id PK→findings, state `open|fixed|verified`, root_cause json `{anchor, explanation}`, remediation json `{change, why}`). *Separate table — does not touch the vendored findings.status.*
- **steps**(id, finding_id, ordinal, action json `{tool_id, params}`, evidence json `{raw_output, hash, timestamp}` = FACT, interpretation text = INFERENCE, links_from `step_id|null`, anchored bool, prev_hash, row_hash). *Append-only, hash-chained like audit_log.*
- **assets**(id, scope_key `lab:<id>|eng:<id>`, kind `host|service|cert|endpoint|tech`, key, props json, first_seen, source_tool). Asset graph per lab.
- **labs_meta**(lab_id PK, armed_snapshot json, solution json **[private]**, learner_view json `{description, objective, hints[]}`, source_anchor json). *solution NEVER serialized into any learner/report response — enforced by a dedicated serializer that whitelists learner_view only.*
- **progress**(singleton/global: labs_solved json, vuln_classes json, methodology_steps json).
- **playbooks**(id, name, steps json `[{tool_id, in_map, expected, methodology_ids[]}]`).

New router `routers/method.py` (gated via exposure.py). Evidence/steps hashing mirrors `lib/audit_log.py` (prev_hash/row_hash). A `learner_serialize()` helper is the only path the learner UI/report read — it cannot emit `solution`.

## Active-vs-passive
Add `mode: "passive" | "active"` to every `ToolDescriptor` (default by tier/intrusive). Show the label on active tools; active playbooks gated behind the isolation check.

## Build stages (in order; each verified `tsc` + `import main`)
1. **Data model + asset graph** — ✅ DONE 2026-06-28. Backend `lib/method.py` + `routers/method.py` (finding_method/steps[hash-chained]/assets/labs_meta/progress/playbooks; `learner_serialize` solution-safe), gated + registered. Frontend: `types.ts` +mode +parseAssets +AssetRecord, `assetDiscovered` bus event, ToolPanel emits+persists, parsers on dns/ip/port_scan/http/tls, `AssetsTree` in Explorer, active/passive label. Verified: import main OK · solution-leak PASS · step hash-chain OK · asset bulk POST/GET + progress live. tsc 0. (Not yet in the Desktop .app — needs rebuild.)
2. **Evidence chain** — sessionLog append-only + SHA-256 per entry; "Promote to finding" sends the selected subsequence → backend `steps` (ordered, hash-chained).
3. **Lab lifecycle + isolation** — arm / reset(→armed_snapshot) / solve(gated reveal); backend egress probe; StatusBar pass/fail; refuse to arm if egress reachable.
4. **Copilot method reconstruction** — link each Step to the prior step its output justifies (anchored); render FACT spine vs INFERENCE layer, visibly separate; label inference; unanchored → flagged guess only; surface gaps; deferred/live confirm toggle.
5. **Root-cause anchor + fix-in-place + retest** — chain terminates at file:line/route/config; Monaco opens lab-container source; retest replays the Step chain; previously-passing step now failing = verification → auto-advance state.
6. **Learning surface + playbooks** — no-spoiler progressive hints; guided empty state; backend progress; declarative playbooks with in_map/expected + WSTG/PTES ids + coverage.

## Stages 2–6 — ✅ DONE 2026-06-28 (5 parallel agents + inline integration)
- **2 Evidence chain:** `sessionLog.ts` append-only + SHA-256 chain + `verifyLog()`; `MethodPromote` (bus `promoteSteps`, "Promote → steps" button in Output dock) → ordered Step chain via `/method/findings/{id}/steps`.
- **3 Lab lifecycle + isolation:** `lib/isolation.py` egress probe; `/isolation/labs/{id}/arm|reset|solve` (arm **409 fail-closed** when egress reachable; solve = privileged `get_solution`, not learner); `IsolationStatus` in StatusBar; `LabsView` in the Labs activity surface.
- **4 Copilot reconstruction:** `lib/methodAnalysis.ts` (anchored + gap detection) + `MethodReconstruction` (FACT spine vs INFERENCE layer; unanchored+no-interpretation → flagged "unverified", **never fabricates**); mounted in CopilotRail on `focusFinding` (click a finding).
- **5 Fix-in-place + retest:** `routers/labfs.py` (read/write lab source via `sidecar_exec`, path-traversal rejected; `retest` replay → state→verified); Monaco `EditorPanel` dockview component (`openEditor` bus event); `retest.ts`. *Open item: lab `sidecar_allowed_cmds` whitelist + stdin must be extended for live write.*
- **6 Learning + playbooks:** `routers/playbook_run.py` (CRUD + WSTG/PTES coverage); `methodology.ts`; `LearningView` (no-spoiler progressive hints + progress), `PlaybooksView` (isolation-gated Run), `LabAuthoring` (solution stays server-side).

**Acceptance (all PASS):** `tsc --noEmit` 0 · `vite build` green · `import main` OK · unanchored step = labeled inference, no fabrication · isolation arm refused 409 when egress reachable · learner serializer emits only `{lab_id, learner_view, source_anchor}`.

## Constraints (hard)
- Don't weaken `backend/config.json` target_policy (default-deny stays).
- Don't rename `X-MHP-*` headers.
- `solution` never reaches learner UI or report (enforced by `learner_serialize`).

## Acceptance
- `npx tsc --noEmit` and `python3 -c "import main"` clean.
- An unanchored step renders labeled **inference** with NO fabricated rationale.
- Isolation check **fails closed** when egress is reachable (labs refuse to arm).
- Report/learner serializer **never** emits `solution` (unit-tested).
