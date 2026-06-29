// Open lab tabs — the MDI surface scoped to labs.
//
// A "lab tab" is a running lab the operator has opened to work against. The
// set of open tabs + which one is active is per-window state, persisted to
// localStorage and broadcast over the shell bus so MainArea's tab strip and
// any lab surface stay in sync. Activating a tab also makes that lab the
// active *target* (lib/targets.ts) so every tool/console auto-aims at it.

import { useEffect, useState } from "react";
import { emit } from "../shell/bus";
import { setActiveTarget } from "./targets";
import { writeLabIntent } from "./labIntent";

export type LabTab = {
  id: string; // lab id (e.g. "juice-shop")
  name: string;
  /** Browser-openable URL, e.g. http://127.0.0.1:3000 (may be empty). */
  primaryUrl: string;
  /** Bare host:port used to pre-fill tools / the active target. */
  address: string;
  hasSidecar: boolean;
};

const KEY = "s-ide:lab-tabs:v1";
const ACTIVE_KEY = "s-ide:lab-tab-active:v1";

let tabs: LabTab[] = [];
let activeId: string | null = null;
try {
  const raw = localStorage.getItem(KEY);
  if (raw) tabs = JSON.parse(raw) as LabTab[];
  activeId = localStorage.getItem(ACTIVE_KEY) || null;
} catch {
  /* ignore */
}

const listeners = new Set<() => void>();
function notify() {
  for (const l of listeners) l();
}
function persist() {
  try {
    localStorage.setItem(KEY, JSON.stringify(tabs));
    if (activeId) localStorage.setItem(ACTIVE_KEY, activeId);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch {
    /* quota */
  }
}

export function getLabTabs(): LabTab[] {
  return tabs;
}
export function getActiveLabTabId(): string | null {
  return activeId;
}

/** Make `id` the active lab tab: sets the active target + broadcasts. */
export function activateLabTab(id: string): void {
  const tab = tabs.find((t) => t.id === id);
  if (!tab) return;
  activeId = id;
  setActiveTarget({ id: `lab:${tab.id}`, address: tab.address, name: tab.name, kind: "lab" });
  persist();
  notify();
  emit("labTabActivated", { labId: id });
}

/** Open (or focus) a lab as a tab and activate it. */
export function openLabTab(tab: LabTab): void {
  if (!tabs.some((t) => t.id === tab.id)) {
    tabs = [...tabs, tab];
  } else {
    // Refresh the stored snapshot (ports/url may have changed since last open).
    tabs = tabs.map((t) => (t.id === tab.id ? { ...t, ...tab } : t));
  }
  persist();
  notify();
  emit("labTabOpened", { labId: tab.id });
  activateLabTab(tab.id);
}

export function closeLabTab(id: string): void {
  const idx = tabs.findIndex((t) => t.id === id);
  if (idx < 0) return;
  tabs = tabs.filter((t) => t.id !== id);
  if (activeId === id) {
    const next = tabs[idx] ?? tabs[idx - 1] ?? null;
    activeId = next?.id ?? null;
    if (next) setActiveTarget({ id: `lab:${next.id}`, address: next.address, name: next.name, kind: "lab" });
  }
  persist();
  notify();
  emit("labTabClosed", { labId: id });
}

// ── Arm & aim ────────────────────────────────────────────────────────────────
//
// The ONE consistent way a lab hands a target to a tool. Every "arm" path in
// the labs surface (the lab card, a suggested-step chip, the LabTabView "aim"
// buttons) funnels through here so the ToolPanel lane — which reads
// takeLabIntent(toolId) and the active-target snapshot — always sees the same
// shape regardless of which affordance the operator clicked.
//
// `armLabTarget` writes the persistent active-target snapshot (so EVERY tool
// auto-aims at this lab until the operator picks another), and `armAndAim`
// additionally writes a one-shot lab intent for the specific tool and opens it.

export type LabArmInfo = {
  /** Lab id, e.g. "juice-shop". */
  id: string;
  name: string;
  /** Browser-openable URL (may be empty). */
  primaryUrl: string;
  /** Bare host:port used to pre-fill tools / the active target. */
  address: string;
};

/** What we hand a tool as its target — the full URL when we have one, else the
 * bare host:port. Tools that want host-only normalize via `intentHost`. */
function armTarget(lab: LabArmInfo): string {
  return lab.primaryUrl || lab.address;
}

/**
 * Make `lab` the active target (persistent, per-window). Pre-fills the target
 * field on every tool page via the active-target snapshot. Returns the target
 * string written, for callers that want to surface it.
 */
export function armLabTarget(lab: LabArmInfo): string {
  setActiveTarget({ id: `lab:${lab.id}`, address: lab.address, name: lab.name, kind: "lab" });
  return armTarget(lab);
}

/**
 * Unified "Arm & aim": activate the lab as the active target, write the
 * one-shot lab intent for `toolId`, and open that tool. This is the single
 * code path the lab card chips, suggested-steps, and the LabTabView aim
 * buttons all call — guaranteeing the ToolPanel lane reads a consistent
 * intent + active-target snapshot no matter which arm affordance was used.
 */
export function armAndAim(lab: LabArmInfo, toolId: string): void {
  const target = armLabTarget(lab);
  writeLabIntent(toolId, { target });
  emit("openTool", { toolId });
}

/** Subscribe to the open-tabs set + active id. */
export function useLabTabs(): { tabs: LabTab[]; activeId: string | null } {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((n) => n + 1);
    listeners.add(fn);
    return () => {
      listeners.delete(fn);
    };
  }, []);
  return { tabs, activeId };
}
