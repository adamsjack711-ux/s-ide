// Open engagement tabs — the primary MDI surface of the shell.
//
// An engagement is the project spine, so opening one opens a *tab* (mirroring
// labTabs.ts). Each engagement tab is a workspace with four sub-surfaces —
// Workbench / Map / Findings / Terminal — one visible at a time. The set of
// open tabs, the active tab, and the active sub-tab per engagement are
// per-window state, persisted to localStorage and broadcast over the shell bus
// so MainArea's tab strip + the workspace stay in sync.
//
// Activating a tab also pins that engagement as the active engagement
// (lib/engagement.ts) so every backend write carries the right
// X-MHP-Engagement-Id — i.e. switching tabs switches engagement context.

import { useEffect, useState } from "react";
import { emit } from "../shell/bus";
import { setActiveEngagementId } from "./engagement";

/** The four sub-surfaces inside an engagement tab. Values reuse the existing
 *  view kinds so MainArea/EngagementWorkspace can render the existing views. */
export type EngagementSubTab = "build" | "graph" | "findings" | "reports" | "terminal";
export const ENGAGEMENT_SUB_TABS: EngagementSubTab[] = ["build", "graph", "findings", "reports", "terminal"];

export type EngagementTab = {
  id: string; // engagement id
  name: string;
};

const KEY = "s-ide:eng-tabs:v1";
const ACTIVE_KEY = "s-ide:eng-tab-active:v1";
const SUB_KEY = "s-ide:eng-tab-sub:v1";

let tabs: EngagementTab[] = [];
let activeId: string | null = null;
let subTabs: Record<string, EngagementSubTab> = {};
try {
  const raw = localStorage.getItem(KEY);
  if (raw) tabs = JSON.parse(raw) as EngagementTab[];
  activeId = localStorage.getItem(ACTIVE_KEY) || null;
  const subRaw = localStorage.getItem(SUB_KEY);
  if (subRaw) subTabs = JSON.parse(subRaw) as Record<string, EngagementSubTab>;
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
    localStorage.setItem(SUB_KEY, JSON.stringify(subTabs));
    if (activeId) localStorage.setItem(ACTIVE_KEY, activeId);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch {
    /* quota */
  }
}

export function getEngagementTabs(): EngagementTab[] {
  return tabs;
}
export function getActiveEngagementTabId(): string | null {
  return activeId;
}
export function getEngagementSubTab(id: string): EngagementSubTab {
  return subTabs[id] ?? "build";
}

/** Make `id` the active engagement tab: pins the engagement + broadcasts. */
export function activateEngagementTab(id: string): void {
  const tab = tabs.find((t) => t.id === id);
  if (!tab) return;
  activeId = id;
  setActiveEngagementId(id);
  persist();
  notify();
  emit("engagementTabActivated", { engagementId: id });
}

/** Open (or focus) an engagement as a tab and activate it. */
export function openEngagementTab(eng: EngagementTab): void {
  if (!tabs.some((t) => t.id === eng.id)) {
    tabs = [...tabs, eng];
  } else {
    // Refresh the stored snapshot (the name may have been edited since).
    tabs = tabs.map((t) => (t.id === eng.id ? { ...t, ...eng } : t));
  }
  persist();
  notify();
  emit("engagementTabOpened", { engagementId: eng.id });
  activateEngagementTab(eng.id);
}

export function closeEngagementTab(id: string): void {
  const idx = tabs.findIndex((t) => t.id === id);
  if (idx < 0) return;
  tabs = tabs.filter((t) => t.id !== id);
  delete subTabs[id];
  if (activeId === id) {
    const next = tabs[idx] ?? tabs[idx - 1] ?? null;
    activeId = next?.id ?? null;
    if (next) setActiveEngagementId(next.id);
  }
  persist();
  notify();
  emit("engagementTabClosed", { engagementId: id });
}

/** Pick the active sub-surface (Workbench / Map / Findings / Terminal) for a tab. */
export function setEngagementSubTab(id: string, sub: EngagementSubTab): void {
  subTabs = { ...subTabs, [id]: sub };
  persist();
  notify();
}

/** Subscribe to the open-tabs set + active id + active sub-tab. */
export function useEngagementTabs(): {
  tabs: EngagementTab[];
  activeId: string | null;
  subTab: EngagementSubTab;
} {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((n) => n + 1);
    listeners.add(fn);
    return () => {
      listeners.delete(fn);
    };
  }, []);
  return { tabs, activeId, subTab: activeId ? getEngagementSubTab(activeId) : "build" };
}
