/**
 * Tool liveness — "are the tools active?"
 *
 * The backend's capability gate (lib/exposure.py) only *registers* the routers
 * it exposes; everything else 404s. GET /system/tools returns the registered
 * route paths (HTTP + WebSocket) — the truthful source of which tools can
 * actually run. We map each frontend tool id to its backend route prefix and
 * derive a status:
 *
 *   live    — route registered AND the tool's capability is enabled (Tier-1, or
 *             an operator-enabled group). It will run.
 *   gated   — route registered but the capability group is OFF in Settings.
 *             Enable it to use the tool (backend scope/auth still enforce).
 *   offline — route NOT registered (gated off server-side / backend down). 404.
 *   unknown — no route mapping for this id (new tool not yet mapped here).
 *
 * The Workbench shows this as a colored dot per tool and a "Test all" probe.
 */
import { useSyncExternalStore } from "react";

import { BACKEND_URL } from "../../api";
import { isToolEnabled } from "./capability";
import type { ToolDescriptor } from "./types";

export type ToolStatus = "live" | "gated" | "offline" | "unknown";

/** tool id → a backend route prefix that must appear in /system/tools. */
export const TOOL_ROUTE: Record<string, string> = {
  // Discovery / core
  dns_recon: "/ws/dns-recon",
  ip_checker: "/ip/",
  whois: "/whois/",
  ping: "/ws/ping",
  port_scanner: "/ws/port-scan",
  tls_audit: "/tls/audit/",
  http_probe: "/ws/http-probe",
  local_discovery: "/ws/local-discovery",
  lan_scan: "/ws/lan-scan",
  // Recon
  fingerprint: "/fingerprint/",
  nmap: "/ws/nmap",
  // OSINT
  ct_log: "/ct/search/",
  email_security: "/email/audit/",
  takeover: "/takeover/check/",
  reverse_ip: "/reverse-ip/",
  breach: "/breach/",
  dorking: "/dorking/",
  github_leak: "/github-leak/",
  // Web Recon
  subdomain_enum: "/ws/subdom-enum",
  cms: "/cms/",
  jwt: "/jwt/",
  graphql: "/graphql/",
  // Web Exploit
  xss: "/ws/xss",
  sqli: "/ws/sqli",
  cmdi: "/ws/cmdi",
  lfi: "/ws/lfi",
  ssrf: "/ws/ssrf",
  idor: "/ws/idor",
  // Active Directory
  ldap_enum: "/ldap/enum",
  smb_enum: "/smb/enum",
  kerberos_roast: "/kerberoast/run",
  bloodhound_ingest: "/bloodhound/run",
  lateral: "/lateral/",
  ad_spray: "/ws/ad-spray",
  // Red Team
  exploits: "/exploits/",
  reverse_shell: "/reverse-shell/",
  c2_beacon: "/c2/",
  // Code
  codescan: "/codescan",
};

// ── External store ──────────────────────────────────────────────────────────
type State = {
  routes: Set<string> | null; // null = never probed
  loading: boolean;
  error: string | null;
  probedAt: number | null;
};

let state: State = { routes: null, loading: false, error: null, probedAt: null };
const listeners = new Set<() => void>();

function set(next: Partial<State>) {
  state = { ...state, ...next };
  listeners.forEach((l) => l());
}

/** Fetch /system/tools and cache the registered-route set. Safe to call often. */
export async function probeTools(): Promise<void> {
  if (state.loading) return;
  set({ loading: true, error: null });
  try {
    const r = await fetch(`${BACKEND_URL}/system/tools`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const body = (await r.json()) as { routes?: string[] };
    set({
      routes: new Set(body.routes ?? []),
      loading: false,
      probedAt: Date.now(),
    });
  } catch (e) {
    set({
      routes: new Set(), // empty → everything reads offline (backend down)
      loading: false,
      error: e instanceof Error ? e.message : "probe failed",
      probedAt: Date.now(),
    });
  }
}

/** True when some registered route matches the tool's mapped prefix. */
function isRegistered(routes: Set<string>, prefix: string): boolean {
  for (const p of routes) if (p === prefix || p.startsWith(prefix)) return true;
  return false;
}

/** Status for one tool given the current probe. `null` routes = not probed yet. */
export function statusFor(tool: ToolDescriptor, routes: Set<string> | null): ToolStatus {
  const prefix = TOOL_ROUTE[tool.id];
  if (!prefix) return "unknown";
  if (!routes) return "unknown"; // hasn't been probed — render neutral
  if (!isRegistered(routes, prefix)) return "offline";
  return isToolEnabled(tool) ? "live" : "gated";
}

export const STATUS_META: Record<ToolStatus, { label: string; color: string; hint: string }> = {
  live: { label: "Active", color: "rgb(var(--success-rgb))", hint: "Route registered and capability enabled — ready to run." },
  gated: { label: "Gated", color: "rgb(var(--amber-rgb))", hint: "Route exists but the capability group is off — enable it in Settings." },
  offline: { label: "Offline", color: "rgb(var(--danger-rgb))", hint: "Backend route not registered (Tier 2/3 not exposed, or backend down)." },
  unknown: { label: "Unknown", color: "rgb(var(--ink-dim-rgb))", hint: "Not yet probed, or no route mapping." },
};

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/** React hook: the current liveness state (re-renders on probe + capability changes). */
export function useLiveness(): State {
  return useSyncExternalStore(subscribe, () => state);
}
