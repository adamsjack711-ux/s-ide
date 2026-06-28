// Active-target state + Targets CRUD wrappers.
//
// "Active target" is a per-window choice (localStorage) that pre-fills the
// target field on every tool page. Distinct from the active *engagement*:
// an engagement is a container; a target is a single host/URL inside it
// (or a global lab/scratch target with no engagement binding).
//
// Pages opt in via `useActiveTarget()`. Lab-intent (one-shot, from a
// suggested-step button) still takes precedence so clicking "Try SQLi on
// DVWA" doesn't get hijacked by whatever was the active target before.

import { useEffect, useState } from "react";
import { authFetch } from "../api";

export type TargetKind = "lab" | "manual" | "tailscale" | "ssh" | "lan";
export type ScopeTag = "lab" | "owned" | "authorized" | "manual";

export type Target = {
  id: string;
  engagement_id: string | null;
  name: string;
  address: string;
  kind: TargetKind;
  source_meta: Record<string, unknown>;
  scope_tag: ScopeTag;
  added_at: string;
  last_seen_at: string | null;
  hidden: boolean;
};

// ── Active target state ─────────────────────────────────────────────────────
//
// Stored as a compact snapshot ({id, address, name, kind}) so consumers
// like `useLabIntent` can synchronously read the active address at mount
// without an API round-trip. The full Target object is refetched via
// `useActiveTarget()` when callers need the rest of the fields.

export type ActiveTargetSnapshot = {
  id: string;
  address: string;
  name: string;
  kind: TargetKind;
};

const ACTIVE_KEY = "mhp:active-target:v2";

let activeSnap: ActiveTargetSnapshot | null = null;
try {
  const raw = localStorage.getItem(ACTIVE_KEY);
  if (raw) activeSnap = JSON.parse(raw) as ActiveTargetSnapshot;
} catch { /* ignore */ }

const listeners = new Set<() => void>();
function notify() { for (const l of listeners) l(); }

export function getActiveTargetSnapshot(): ActiveTargetSnapshot | null {
  return activeSnap;
}

export function getActiveTargetId(): string | null {
  return activeSnap?.id ?? null;
}

export function setActiveTarget(t: Target | ActiveTargetSnapshot | null): void {
  activeSnap = t
    ? { id: t.id, address: t.address, name: t.name, kind: t.kind }
    : null;
  try {
    if (activeSnap) localStorage.setItem(ACTIVE_KEY, JSON.stringify(activeSnap));
    else localStorage.removeItem(ACTIVE_KEY);
  } catch { /* quota */ }
  notify();
}

export function useActiveTargetId(): string | null {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((n) => n + 1);
    listeners.add(fn);
    return () => { listeners.delete(fn); };
  }, []);
  return activeSnap?.id ?? null;
}

/** Resolved active target object — refetched if the active id changes
 * or the targets list is mutated elsewhere. Returns `null` when no target
 * is active, `undefined` while loading. */
export function useActiveTarget(): Target | null | undefined {
  const id = useActiveTargetId();
  const [t, setT] = useState<Target | null | undefined>(undefined);
  useEffect(() => {
    let cancelled = false;
    if (!id) { setT(null); return; }
    (async () => {
      try {
        const got = await getTarget(id);
        if (!cancelled) setT(got);
      } catch {
        if (!cancelled) setT(null);
      }
    })();
    return () => { cancelled = true; };
  }, [id]);
  return t;
}

// ── CRUD wrappers ───────────────────────────────────────────────────────────

export async function listTargets(opts: {
  engagementId?: string | null;
  kind?: TargetKind;
  includeHidden?: boolean;
} = {}): Promise<Target[]> {
  const params = new URLSearchParams();
  if (opts.engagementId) params.set("engagement_id", opts.engagementId);
  if (opts.kind) params.set("kind", opts.kind);
  if (opts.includeHidden) params.set("include_hidden", "true");
  const qs = params.toString();
  const r = await authFetch("/targets" + (qs ? `?${qs}` : ""));
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = (await r.json()) as { targets: Target[] };
  return body.targets;
}

export async function getTarget(id: string): Promise<Target> {
  const r = await authFetch(`/targets/${encodeURIComponent(id)}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()) as Target;
}

export async function createTarget(payload: {
  name: string;
  address: string;
  kind?: TargetKind;
  engagement_id?: string | null;
  source_meta?: Record<string, unknown>;
  scope_tag?: ScopeTag;
}): Promise<Target> {
  const r = await authFetch("/targets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()) as Target;
}

export async function updateTarget(id: string, patch: Partial<Pick<
  Target, "name" | "address" | "scope_tag" | "engagement_id" | "source_meta" | "hidden"
>>): Promise<Target> {
  const r = await authFetch(`/targets/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()) as Target;
}

export async function deleteTarget(id: string): Promise<void> {
  const r = await authFetch(`/targets/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
}

// ── Discovery ───────────────────────────────────────────────────────────────

export type TailscalePeer = {
  role: "self" | "peer";
  name: string;
  address: string;
  dns_name: string;
  os: string;
  online: boolean;
  last_seen: string | null;
};

export type SshHost = {
  name: string;
  address: string;
  user: string;
  port: number;
  identity_file: string;
};

export type LanHost = {
  address: string;
  mac: string;
  hostname: string;
  is_self: boolean;
};

export async function discoverTailscale(): Promise<{
  available: boolean; peers: TailscalePeer[]; tailnet?: string; error?: string;
}> {
  const r = await authFetch("/targets/discover/tailscale");
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function discoverSsh(): Promise<{
  available: boolean; hosts: SshHost[]; path?: string; error?: string;
}> {
  const r = await authFetch("/targets/discover/ssh");
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function discoverLan(): Promise<{
  available: boolean; hosts: LanHost[]; subnet?: string; local_ip?: string; error?: string;
}> {
  const r = await authFetch("/targets/discover/lan");
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
