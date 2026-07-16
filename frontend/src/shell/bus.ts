/**
 * Tiny in-process pub/sub that decouples the shell's panels.
 *
 * The Explorer / command palette emit `openTool`; the dockview Workspace
 * subscribes and adds a panel. Tool panels emit `output` lines; the Output
 * dock subscribes and renders them. Keeping this out of React context avoids
 * prop-drilling across the dockview boundary (panels are mounted by dockview,
 * not by our tree).
 */
import { useEffect } from "react";
import type {
  FindingRef, AssetRef, StepRef, SubTargetRef, Anchor, EngagementId,
} from "./refs";

export type OutputLine = {
  ts: number;
  tool: string;
  level: "info" | "hit" | "error" | "done";
  text: string;
};

/**
 * Built-in view ids, for editor autocomplete on `openView`. This is NOT a
 * closed set — views register at runtime (shell/views.ts) and `ViewId` accepts
 * any string, so a contributed panel uses its own id without editing this file.
 *
 * Keep this list to ids that are actually registered (see views.builtin.tsx) —
 * an id here that nothing registers silently routes to Home (MainArea's
 * fallback), so advertising a destination that doesn't exist is worse than
 * omitting it. Contributed feature panels register their own ids at runtime and
 * needn't be listed.
 */
export type KnownViewId =
  | "home" | "spine" | "learn" | "settings" | "playbook" | "tool"
  | "engagement" | "build" | "graph" | "findings" | "reports" | "terminal"
  | "labs";
export type ViewId = KnownViewId | (string & {});

type Events = {
  openTool: { toolId: string };
  output: OutputLine;
  focusFinding: { findingId: string };
  promote: { tool: string; target: string; title: string; description: string; evidence: string };
  findingsChanged: Record<string, never>;
  assetDiscovered: { scopeKey: string | null; tool: string; assets: { kind: string; key: string; props?: Record<string, unknown> }[] };
  promoteSteps: Record<string, never>;
  openEditor: { labId: string; path: string };
  openAttestation: Record<string, never>;
  attestationsChanged: Record<string, never>;
  /** Open a non-tool view as a tab in the center editor area. The activity bar
   *  (home / spine / learn / settings), the Explorer links (findings / reports),
   *  and the engagement sub-tabs (build / graph / findings / reports / terminal)
   *  all route through here.
   *
   *  `view` is an open string: views self-register in shell/views.ts, so the
   *  set is not closed at compile time. The `KnownViewId` union below is a
   *  convenience for autocomplete on the built-ins, not an allow-list —
   *  contributed panels use their own ids without editing this file. */
  openView: { view: ViewId; params?: Record<string, unknown> };
  /**
   * Engagement-spine domain events. The four spine tabs (Targets / Engagements /
   * Workbench / Findings) cross-link through these: arming a sub-target in
   * Targets reflects immediately in Engagements and unlocks it in Workbench.
   *
   *  - `subTargetArmed` / `subTargetDisarmed` — an engagement was attached /
   *    detached from a sub-target. Carries both ids so every tab can refresh.
   *  - `pairingRunStarted` / `pairingRunOutput` — a pairing (engagement ×
   *    sub-target) began executing / produced output in the Workbench.
   *  - `findingCreated` — a finding was born from a pairing; carries its
   *    provenance triple so Findings + the Target roll-up can update.
   */
  subTargetArmed: { subTargetId: string; engagementId: string; targetId: string };
  subTargetDisarmed: { subTargetId: string; targetId: string };
  pairingRunStarted: { subTargetId: string; engagementId: string; tool: string };
  pairingRunOutput: { subTargetId: string; engagementId: string; runId: string; status: string; output: string };
  findingCreated: { findingId: string; engagementId: string; subTargetId: string; targetId: string };
  /** Lab MDI — a lab opened/closed/activated as a working tab. */
  labTabOpened: { labId: string };
  labTabClosed: { labId: string };
  labTabActivated: { labId: string };
  /** Engagement MDI — an engagement opened/closed/activated as a primary tab.
   *  Activating a tab swaps the main area to that engagement's workspace
   *  (Workbench / Map / Findings / Terminal sub-surfaces). */
  engagementTabOpened: { engagementId: string };
  engagementTabClosed: { engagementId: string };
  engagementTabActivated: { engagementId: string };
  /**
   * The window's ACTIVE engagement changed (via the persistent selector or any
   * setActiveEngagementId caller). Every workspace surface — Targets, Workbench,
   * Findings, Reporting — listens and re-scopes to the new engagement. The
   * selector itself stays visible in every view; this is the re-scope signal.
   * `engagementId` is null when no engagement is active.
   */
  activeEngagementChanged: { engagementId: EngagementId | null };
  /**
   * ── SELECTION / NAVIGATION EVENTS (Foundation lane; payloads in shell/refs.ts) ──
   *
   * The connective tissue between feature panels. A feature that focuses an
   * object BROADCASTS the matching event carrying a canonical ref; it NEVER
   * targets a specific panel. Any panel that cares subscribes and reacts by
   * reading the model — no panel imports or calls another. `source` is the
   * publishing feature's id so a panel can ignore its own echo (avoids feedback
   * loops when a panel both publishes and subscribes to the same event).
   *
   *  - `selectFinding`   — a finding was focused. Problems/search/graph/timeline
   *    publish it; the pivot lane resolves its root-cause Anchor and re-broadcasts
   *    `selectAnchor`; the debugger loads its chain.
   *  - `selectAsset`     — an asset was focused. No panel consumes this yet (an
   *    asset-tree / graph highlight is the intended reactor); until one does,
   *    clicking an asset search result publishes into the void. Kept as the
   *    canonical event so the consumer can land without touching publishers.
   *  - `selectAnchor`    — jump the editor to a code/route/config location. Carries
   *    the originating `findingId` when the anchor came from a finding pivot.
   *  - `selectStep`      — a step in an evidence chain was focused. The evidence/
   *    request-response view reacts; if the step has an anchor the pivot follows
   *    it with `selectAnchor`.
   *  - `selectSubTarget` — a sub-target was focused (scopes Workbench/coverage).
   */
  selectFinding: { ref: FindingRef; source: string };
  selectAsset: { ref: AssetRef; source: string };
  selectAnchor: { ref: Anchor; findingId?: string; source: string };
  selectStep: { ref: StepRef; source: string };
  selectSubTarget: { ref: SubTargetRef; source: string };
  /**
   * The model changed underneath every view. This is how a view knows to
   * re-read WITHOUT caching shared state: no view holds a private copy, so on
   * `modelChanged` it re-fetches through the model API. `entity` narrows what
   * changed so a listener can skip irrelevant refreshes; `id` is that entity's
   * id; `op` is the mutation kind. The existing findingsChanged / findingCreated
   * events stay for back-compat, but new features listen on this unified signal.
   */
  modelChanged: {
    // Only the entities that a mutation path actually emits belong here — a
    // listener that gates on an entity nobody publishes is dead code (a bus-
    // contract test enforces this). Widen this union the moment a new emitter
    // lands, not before.
    entity: "finding" | "subtarget" | "run";
    id: string;
    op: "create" | "update" | "delete";
  };
  /**
   * Command-system events (owned by the Foundation lane; see shell/commands.ts
   * + shell/keymap.ts). Feature lanes LISTEN for these to react to global
   * commands they don't own the wiring for:
   *
   *  - `command:focus-create`   — "New Engagement" was invoked. The Home lane
   *    navigates to the home view itself (via openView) then focuses/opens its
   *    create-engagement affordance.
   *  - `command:show-onboarding` — "Show Getting Started" was invoked. The Home
   *    lane surfaces its onboarding / getting-started panel.
   *  - `command:run` — a generic contextual command fired by id (e.g. a feature
   *    lane registered `promote-to-finding` / `retest` with a keybinding and
   *    wants a single bus hook to listen on instead of a direct closure). The
   *    payload carries the commandId so multiple listeners can disambiguate.
   */
  "command:focus-create": Record<string, never>;
  "command:show-onboarding": Record<string, never>;
  "command:run": { commandId: string; params?: Record<string, unknown> };
};

type Handler<K extends keyof Events> = (payload: Events[K]) => void;

const listeners: { [K in keyof Events]?: Set<Handler<K>> } = {};

export function emit<K extends keyof Events>(event: K, payload: Events[K]): void {
  listeners[event]?.forEach((h) => h(payload));
}

export function on<K extends keyof Events>(event: K, handler: Handler<K>): () => void {
  (listeners[event] ??= new Set() as any).add(handler);
  return () => listeners[event]?.delete(handler);
}

/** React convenience: subscribe for the lifetime of a component. */
export function useBus<K extends keyof Events>(event: K, handler: Handler<K>): void {
  useEffect(() => on(event, handler), [event, handler]);
}
