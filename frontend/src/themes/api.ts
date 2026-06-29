// Typed client for the /themes distribution router. The renderer never fetches
// a remote .side itself — the backend resolves git tags, verifies the TOFU
// hash, caches immutably, and hands back the validated JSON we apply.
import { authFetch } from "../api";
import type { SideTheme } from "./sideSchema";

export type ManifestEntry = { url: string; version?: string; official: boolean; origin?: string };
export type Manifest = { default_manifest_url: string; themes: ManifestEntry[] };

export type ResolveResult = {
  url: string;
  version: string;
  hash: string;
  official: boolean;
  source: "curated" | "tofu" | "locked";
  verified: boolean;
  name?: string;
};

/** Thrown when the backend refuses a fetch because an immutable version's
 *  content changed (TOFU hash mismatch) — a tampering signal. */
export class TamperError extends Error {
  constructor(public info: { url: string; version: string; expected: string; got: string }) {
    super(`hash mismatch for ${info.url}@${info.version}`);
    this.name = "TamperError";
  }
}

async function body(r: Response): Promise<any> {
  try { return await r.json(); } catch { return {}; }
}

export async function getManifest(): Promise<Manifest> {
  const r = await authFetch("/themes/manifest");
  if (!r.ok) throw new Error(`manifest HTTP ${r.status}`);
  return r.json();
}

export async function resolveTheme(url: string, version?: string): Promise<ResolveResult> {
  const r = await authFetch("/themes/resolve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, version }),
  });
  if (r.status === 409) {
    const b = await body(r);
    const d = b?.detail ?? b;
    throw new TamperError({ url: d.url ?? url, version: d.version ?? version ?? "", expected: d.expected ?? "", got: d.got ?? "" });
  }
  if (!r.ok) {
    const b = await body(r);
    const d = b?.detail ?? b;
    const errs = d?.errors?.join("; ") ?? d?.error ?? `HTTP ${r.status}`;
    throw new Error(errs);
  }
  return r.json();
}

export async function fetchThemeFile(url: string, version: string): Promise<SideTheme> {
  const r = await authFetch(`/themes/file?url=${encodeURIComponent(url)}&version=${encodeURIComponent(version)}`);
  if (!r.ok) throw new Error(`file HTTP ${r.status}`);
  return r.json();
}

export async function addSource(url: string, version?: string): Promise<Manifest> {
  const r = await authFetch("/themes/manifests", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, version }),
  });
  if (!r.ok) throw new Error(`add HTTP ${r.status}`);
  return r.json();
}

export async function removeSource(url: string): Promise<Manifest> {
  const r = await authFetch(`/themes/manifests?url=${encodeURIComponent(url)}`, { method: "DELETE" });
  if (!r.ok) throw new Error(`remove HTTP ${r.status}`);
  return r.json();
}
