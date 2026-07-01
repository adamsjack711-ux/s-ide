/**
 * Capability gating — the "open but secure" sandbox seam.
 *
 * Tier-1 tools are enabled by default. Tier-2 (privilege) and Tier-3 (external
 * setup), and anything `intrusive`, are OFF until the operator enables their
 * group in Settings → Capabilities. Enablement is persisted and, on the backend,
 * the scope/auth/audit gates remain the hard enforcement.
 */
import { useSyncExternalStore } from "react";
import { fetchCapabilities, setServerCapability } from "../../api";
import type { ToolDescriptor } from "./types";

const KEY = "s-ide:enabled-caps:v1";
const listeners = new Set<() => void>();

function load(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(KEY) || "[]"));
  } catch {
    return new Set();
  }
}
let enabled = load();

/** Persist to localStorage + notify subscribers (no server round-trip). */
function writeLocal(next: Set<string>): void {
  enabled = next;
  try {
    localStorage.setItem(KEY, JSON.stringify([...enabled]));
  } catch {
    /* quota */
  }
  listeners.forEach((l) => l());
}

/** A capability key is the tool's group (we enable/disable by group). */
export function capabilityKey(t: ToolDescriptor): string {
  return t.group;
}

/** Tier-1 non-intrusive tools are always on; everything else needs enabling. */
export function isToolEnabled(t: ToolDescriptor): boolean {
  if (t.tier === 1 && !t.intrusive) return true;
  return enabled.has(capabilityKey(t));
}

export function isCapabilityEnabled(group: string): boolean {
  return enabled.has(group);
}

export function setCapabilityEnabled(group: string, on: boolean): void {
  const next = new Set(enabled);
  if (on) next.add(group);
  else next.delete(group);
  writeLocal(next); // optimistic — reflect immediately

  // The backend is authoritative: gated routers 403 until the group is enabled
  // server-side. Push the change; revert the optimistic update if it fails so
  // the UI never claims a capability the server hasn't actually granted.
  void setServerCapability(group, on).catch((e) => {
    const reverted = new Set(enabled);
    if (on) reverted.delete(group);
    else reverted.add(group);
    writeLocal(reverted);
    console.error(`capability "${group}" ${on ? "enable" : "disable"} failed`, e);
  });
}

/**
 * Reconcile local state with the server (the source of truth). Call once at
 * app boot so tool availability matches what the backend will actually allow —
 * otherwise a localStorage-"enabled" group whose server state was reset would
 * show tools as runnable that then 403.
 */
export async function hydrateCapabilities(): Promise<void> {
  try {
    const states = await fetchCapabilities();
    const server = new Set(states.filter((s) => s.enabled).map((s) => s.group));
    // Preserve any locally-enabled groups the backend doesn't gate (none today,
    // but keeps this forward-safe); authoritative for every gated group.
    const gated = new Set(states.map((s) => s.group));
    const merged = new Set([...enabled].filter((g) => !gated.has(g)));
    server.forEach((g) => merged.add(g));
    writeLocal(merged);
  } catch (e) {
    console.error("capability hydrate failed", e);
  }
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/** Re-render when capability enablement changes. */
export function useCapabilities(): Set<string> {
  return useSyncExternalStore(subscribe, () => enabled);
}
