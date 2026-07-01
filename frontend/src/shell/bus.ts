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

export type OutputLine = {
  ts: number;
  tool: string;
  level: "info" | "hit" | "error" | "done";
  text: string;
};

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
  /** Open a non-tool view as a tab in the center editor area. The top-level bar
   *  modes — home / targets / workbench / findings / reporting — and the
   *  engagements switcher + audit log all route through here. */
  openView: { view: "home" | "targets" | "workbench" | "reporting" | "engagements" | "audit" | "findings" | "reports" | "learn" | "settings" | "playbook" | "graph" | "build" | "terminal" | "labs" | "lab" | "spine"; params?: Record<string, unknown> };
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
  activeEngagementChanged: { engagementId: string | null };
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
