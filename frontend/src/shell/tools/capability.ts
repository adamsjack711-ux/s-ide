/**
 * Capability gating — the "open but secure" sandbox seam.
 *
 * Tier-1 tools are enabled by default. Tier-2 (privilege) and Tier-3 (external
 * setup), and anything `intrusive`, are OFF until the operator enables their
 * group in Settings → Capabilities. Enablement is persisted and, on the backend,
 * the scope/auth/audit gates remain the hard enforcement.
 */
import { useSyncExternalStore } from "react";
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
  enabled = new Set(enabled);
  if (on) enabled.add(group);
  else enabled.delete(group);
  try {
    localStorage.setItem(KEY, JSON.stringify([...enabled]));
  } catch {
    /* quota */
  }
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/** Re-render when capability enablement changes. */
export function useCapabilities(): Set<string> {
  return useSyncExternalStore(subscribe, () => enabled);
}
