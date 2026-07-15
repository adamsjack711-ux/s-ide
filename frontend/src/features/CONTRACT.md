# Feature-suite contract (FROZEN — Phase 0)

Every feature under `frontend/src/features/<yourDir>/` builds against this. It is
frozen: do not change it. If something is missing, add a **private** helper in
your own dir — never edit a shared file.

## The one rule

A feature is a **self-contained module** that:
1. **reads** shared state only through the model API (`../../shell/model`),
2. **refreshes** on the `modelChanged` bus event (no private cache of shared state),
3. **cross-links** by *publishing* selection events on the bus and *subscribing*
   to them — **never** a direct import of or call into another feature/panel,
4. **registers** its own view(s) + command(s) at import time,
5. has **loading / empty / error** states (no blank panel, no silent failure).

## Files you MAY create

Only files under **`frontend/src/features/<yourDir>/`**. Nothing else.

## Files you MUST NOT edit

`shell/bus.ts`, `shell/refs.ts`, `shell/model.ts`, `shell/views.ts`,
`shell/views.builtin.tsx`, `shell/commands.ts`, `features/index.ts`, `features/CONTRACT.md`,
any existing panel, any `lib/*`, any backend file. The orchestrator owns the
single manifest import line that activates your module. Do NOT add it yourself.

## Canonical references — `import type { ... } from "../../shell/refs"`

```ts
type EngagementId = string
type TargetRef    = { targetId: string }
type SubTargetRef = { targetId: string; subTargetId: string }
type AssetKind    = "host" | "service" | "cert" | "endpoint" | "tech"
type AssetRef     = { subTargetId: string; assetId: string; kind: AssetKind }
type FindingRef   = { findingId: string; subTargetId: string; targetId: string }
type StepRef      = { findingId: string; stepId: string }
type Anchor       = { kind: "file"|"route"|"config"; file?: string; line?: number; route?: string; key?: string; labId?: string }
type ConfLevel    = "confirmed" | "suspected"
```
Never redefine these locally (Phase-2 test T2 greps for divergent copies). Import them.

## Bus — `import { emit, on, useBus } from "../../shell/bus"`

Selection/navigation events (publish to broadcast; subscribe to react). `source`
is your feature id so you can ignore your own echo:
```ts
selectFinding    { ref: FindingRef; source: string }
selectAsset      { ref: AssetRef; source: string }
selectAnchor     { ref: Anchor; findingId?: string; source: string }
selectStep       { ref: StepRef; source: string }
selectSubTarget  { ref: SubTargetRef; source: string }
modelChanged     { entity: "finding"|"asset"|"engagement"|"subtarget"|"run"; id: string; op: "create"|"update"|"delete" }
activeEngagementChanged { engagementId: EngagementId | null }
openView         { view: string; params?: Record<string, unknown> }   // navigate to a registered view
openTool         { toolId: string }                                   // open a tool panel
openEditor       { labId: string; path: string }                      // open Monaco at a file
```
`useBus(event, handler)` subscribes for a component's lifetime. Use it to refresh
on `modelChanged` and `activeEngagementChanged`.

## Model API — `import { ... } from "../../shell/model"` (READ ONLY)

```ts
getEngagement(id): Promise<Engagement | null>
listFindings(engagementId, filter?): Promise<PairingFinding[]>   // filter: {severity?,status?,confidence?,subTargetId?}
getFinding(ref | id): Promise<PairingFinding | null>
listAssets(subTargetRef?): Promise<Asset[]>                       // Asset: {subTargetId,assetId,kind,key,props,tool}
getEvidenceChain(findingId): Promise<EvidenceChain>              // {findingId, method, steps: Step[], gaps}
getCoverage(engagementId): Promise<EngagementCoverage>          // {areas[],covered_count,total}
listRuns(engagementId, subTargetRef?): Promise<PairingRun[]>
getRun(runId, {engagementId, subTargetId?}): Promise<PairingRun | null>
listAudit(engagementId, filter?): Promise<AuditEntry[]>         // newest-first ledger; filter {tool?,status?,limit?}
resolveAnchor(ref | findingId): Promise<Anchor | null>          // best-effort root cause; null when nothing anchors
confLevel(finding): ConfLevel                                   // status==="confirmed" ? confirmed : suspected
toFindingRef(f): FindingRef ; toAssetRef(a): AssetRef
```
The active engagement id: `import { getActiveEngagementId, useActiveEngagementId } from "../../lib/engagement"`.
Types `PairingFinding`, `PairingRun`, `Step`, `EvidenceChain`, `Asset`,
`EngagementCoverage`, `AuditEntry`, `Finding`, `FindingSeverity`, `FindingStatus`
are all re-exported from `../../shell/model`.

`PairingFinding` fields: `id, engagement_id, title, severity, status, cvss, cvss_vector, tool, target, description, evidence, ai_summary, sub_target_id, target_id, ts, updated_at`.
`PairingRun` fields: `id, sub_target_id, engagement_id, target_id, tool, status ("started"|"completed"|"error"|"refused"), started_at, ended_at, output, summary`.
`Step` (AnalyzedStep) fields: `id, finding_id, ordinal, action{tool_id?,params?}, evidence{raw_output?,hash?,timestamp?}, interpretation (string|null), links_from, anchored (bool), role ("fact"), hasInterpretation (bool)`.

## Writes

The model API is read-only. To create/mutate, use the existing audited lib paths
(they now emit `modelChanged`, so every view refreshes):
`import { promoteToFinding, patchTrackedFinding } from "../../lib/engagement"`.
F8 (templates) instantiates via `promoteToFinding` so `modelChanged` fires.

## Registration pattern (copy this shape)

```tsx
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";

function MyPanel(_props: { params: ViewParams }) { /* reads model, subscribes bus */ }

registerView({ id: "my-feature", component: MyPanel });
registerCommand({
  id: "my-feature.open",
  title: "Open My Feature",
  keywords: ["..."],
  context: "View",
  run: () => emit("openView", { view: "my-feature" }),
});
```
`registerView({ subTab: true })` routes into the active engagement tab instead of
replacing the main area — use it if your surface belongs inside an engagement.
Reference examples: `../demo/ActiveEngagementPanel.tsx` and `./echo/EchoPanel.tsx`.

## Security invariants (Phase-2 test T5 attacks these)

- **Arm gate**: never trigger a run against an un-armed sub-target. The backend
  refuses with 403 `SUBTARGET_UNARMED`/`TARGET_DENIED`; surface the refusal, don't
  work around it. Read-only features never run tools at all.
- **Secrets**: never render stored auth/session secrets. Engagement auth reads
  come back redacted (`EngagementAuthMeta`) — never request or display raw secrets.
  If tool output/evidence may contain secrets, redact before display (mask tokens,
  cookies, `Authorization:` headers, API keys).
- **Confidence**: never render a `suspected` finding as `confirmed`. Derive via
  `confLevel()`. Make `suspected` visually distinct.
- **Scope**: never suggest or act on a target outside the engagement scope.
- Do not rename `X-MHP-*` headers, weaken `target_policy`, or remove tabs.

## Styling

Tailwind with CSS-variable tokens. Use: `bg-bg-base bg-bg-card border-divider
text-ink-primary text-ink-muted text-ink-dim bg-accent`. Severity/semantic colors:
`text-critical text-high text-medium text-low text-success` (and `bg-*`/`border-*`).
Font sizes use the pattern `text-[calc(12px_*_var(--text-scale))]`. Match the look
of `demo/ActiveEngagementPanel.tsx`.

## Verify your module

`cd frontend && npx tsc --noEmit`. Other `features/*` dirs may be under concurrent
construction — only errors pointing at files in YOUR dir are yours to fix.
