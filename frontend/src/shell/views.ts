/**
 * View registry (Foundation lane) — the single source of truth for every
 * top-level destination the main area can render.
 *
 * This is the third leg of the shell's registry trio, alongside the command
 * registry (shell/commands.ts) and the tool registry (shell/tools/index.ts).
 * Before it existed, MainArea owned a hardcoded `switch(view.kind)` and every
 * new panel had to be wired into that switch AND into the closed `openView`
 * union in shell/bus.ts. That was coupling: a new panel could not be added
 * without editing existing shell files.
 *
 * ── CONTRACT FOR OTHER LANES ────────────────────────────────────────────────
 *
 *   import { registerView } from "../shell/views";
 *
 * Register a full-screen destination at module load (side effect), then reach
 * it from anywhere via the bus:
 *
 *   registerView({ id: "my-panel", component: MyPanel });
 *   // ...elsewhere: emit("openView", { view: "my-panel" })
 *
 * The panel component receives `{ params }` (whatever `openView` carried). It
 * reads shared state from the model and subscribes to the bus like any other
 * view — it never imports or is imported by another panel. The ONLY wiring
 * outside the panel file is one import line in the registration manifest
 * (shell/views.builtin.tsx), mirroring how a tool is added via tools/index.ts.
 * ────────────────────────────────────────────────────────────────────────────
 */
import type { ComponentType } from "react";

export type ViewParams = Record<string, any>;

export type ViewDescriptor = {
  /** Stable id — matches the `openView` event's `view` string. */
  id: string;
  /**
   * Full-screen component rendered in the main slot. Omit for sub-tab-only
   * routing markers (surfaces rendered by EngagementWorkspace, not the main
   * slot — see `subTab`).
   */
  component?: ComponentType<{ params: ViewParams }>;
  /**
   * When true, `openView(id)` routes into the ACTIVE engagement tab as a
   * sub-tab (via setEngagementSubTab) instead of replacing the whole main area.
   * Falls back to Home when no engagement tab is open.
   */
  subTab?: boolean;
};

const registry = new Map<string, ViewDescriptor>();
const listeners = new Set<() => void>();

function notify() {
  for (const l of listeners) l();
}

/**
 * Register a view. Returns an unregister fn. Re-registering the same id
 * replaces the previous entry (last writer wins — handy for HMR + remounts).
 */
export function registerView(v: ViewDescriptor): () => void {
  registry.set(v.id, v);
  notify();
  return () => {
    if (registry.get(v.id) === v) {
      registry.delete(v.id);
      notify();
    }
  };
}

export function getView(id: string): ViewDescriptor | undefined {
  return registry.get(id);
}

/** All registered views, in registration order. */
export function getViews(): ViewDescriptor[] {
  return [...registry.values()];
}

/** True if `openView(id)` should route into the active engagement's sub-tab. */
export function isSubTabView(id: string): boolean {
  return registry.get(id)?.subTab === true;
}

/** Subscribe to registry changes (parity with commands.ts; used for HMR). */
export function subscribeViews(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** Test/maintenance hook — clears the registry. */
export function _resetViewsForTest(): void {
  registry.clear();
  notify();
}
