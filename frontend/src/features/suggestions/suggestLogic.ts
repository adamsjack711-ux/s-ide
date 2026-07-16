/**
 * suggestLogic — pure, deterministic derivation of inline suggestions
 * (the IntelliSense analog, F7). No network, no React, no bus: the panel does
 * the reads (listAssets + getCoverage + the sub-target records) and hands the
 * already-fetched inputs here to be turned into a suggestion list.
 *
 * Two families of suggestion:
 *   1. PARAM suggestions — from known assets of the in-context sub-target:
 *      each host/service/endpoint becomes a suggested target/param for a tool.
 *   2. NEXT-STEP suggestions — from coverage gaps: each area whose `covered`
 *      is false becomes a suggestion to run the check that closes the gap.
 *
 * SECURITY INVARIANTS (advisory only; mirror CONTRACT.md + the F7 spec):
 *   - ADVISORY: a suggestion NEVER runs anything. Its `apply` intent is at most
 *     an `openTool` navigation (toolId + optional prefilled param) — see the
 *     panel. This module produces data, not actions.
 *   - ARM GATE: a param suggestion is produced ONLY for a sub-target that is
 *     currently armed. An un-armed sub-target yields NO param suggestion — it is
 *     not actionable, so we never propose acting on it.
 *   - SCOPE: a param suggestion whose derived target is OUTSIDE the engagement
 *     scope is dropped. When a scope allow-list is supplied, an asset that does
 *     not match any scope entry produces NO suggestion.
 * The pure functions here are the single place these filters live so a view
 * can't drift from them; the panel only renders + dismisses what comes out.
 */
import type { Asset, EngagementCoverage } from "../../shell/model";
import type { CoverageArea } from "../../lib/engagement";
import type { SubTarget } from "../../lib/spine";
import { areaStatusLine, areaTone, type CoverageTone } from "../../lib/coverageView";

/** Which family a suggestion belongs to (drives grouping + icon in the panel). */
export type SuggestionKind = "param" | "next-step";

/**
 * A single advisory suggestion. `apply` is a NAVIGATION intent only — the panel
 * turns it into an `openTool` bus emit (never a run). `toolId` is the tool the
 * operator would open; `param`/`paramValue` pre-fill the tool when present.
 */
export type Suggestion = {
  /** Stable id (dedupe key + dismiss key). */
  id: string;
  kind: SuggestionKind;
  /** Short headline shown as the row title. */
  title: string;
  /** One-line rationale ("why this is suggested"). */
  detail: string;
  /** The tool the "Apply" affordance would OPEN (navigate to, never run). */
  toolId: string;
  /** For param suggestions: the concrete value to pre-fill (e.g. a host/URL). */
  paramValue?: string;
  /** Tone token so the panel colors the row consistently with the coverage grid. */
  tone: CoverageTone;
  /** The sub-target this suggestion is scoped to (param suggestions only). */
  subTargetId?: string;
  /** For next-step suggestions: the coverage area key that is still open. */
  areaKey?: string;
};

/** Everything the panel has already fetched, handed in for pure derivation. */
export type SuggestInput = {
  /** The engagement in context (scope owner). Null → no suggestions. */
  engagementId: string | null;
  /** The sub-target the operator is working in (from selectSubTarget). */
  activeSubTargetId: string | null;
  /**
   * The sub-target records for the active target, carrying the live `armed`
   * flag. Used to gate param suggestions: only an armed sub-target is
   * actionable. If the active sub-target isn't here (or isn't armed), NO param
   * suggestions are produced.
   */
  subTargets: SubTarget[];
  /** Assets recorded under the active sub-target (listAssets({subTargetId})). */
  assets: Asset[];
  /** Coverage matrix for the engagement (getCoverage). Null → no next-steps. */
  coverage: EngagementCoverage | null;
  /**
   * Engagement scope entries (host/URL globs). When non-empty, a param
   * suggestion whose derived target matches NO entry is dropped as out-of-scope.
   * When empty/undefined we do NOT invent scope — the arm gate already bounds
   * actionability — so an empty list imposes no scope constraint.
   */
  scope?: string[];
};

// ── Asset → param mapping ────────────────────────────────────────────────────

/**
 * Which tool a given asset kind would be handed to, and how to phrase it. Only
 * the kinds that map to a concrete, targetable param are actionable; `cert` and
 * `tech` are descriptive context, not a target, so they produce no suggestion.
 */
const ASSET_TOOL: Partial<Record<Asset["kind"], { toolId: string; noun: string }>> = {
  host: { toolId: "port-scanner", noun: "host" },
  service: { toolId: "nmap", noun: "service" },
  endpoint: { toolId: "web-exploit", noun: "endpoint" },
};

/**
 * The concrete target value an asset contributes. Prefers an explicit
 * address/url/host prop, else the asset's key. Trimmed; empty → null (no value,
 * no suggestion).
 */
export function assetTarget(asset: Asset): string | null {
  const p = asset.props ?? {};
  const raw =
    (typeof p.address === "string" && p.address) ||
    (typeof p.url === "string" && p.url) ||
    (typeof p.host === "string" && p.host) ||
    asset.key ||
    "";
  const t = String(raw).trim();
  return t.length ? t : null;
}

/**
 * Normalise a value/scope entry to a bare host for scope comparison: strip a
 * scheme, any path, and a :port. Lets `https://api.example.com/x` match a scope
 * entry of `api.example.com`.
 */
function bareHost(value: string): string {
  let v = value.trim().toLowerCase();
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme://
  v = v.split("/")[0]; // path
  v = v.split("?")[0];
  v = v.replace(/:\d+$/, ""); // :port
  return v;
}

/**
 * Is `value` within the engagement scope? An empty scope list is treated as "no
 * constraint" (the arm gate already bounds actionability). Otherwise the value
 * is in scope iff its bare host equals, is a subdomain of, or (for a wildcard
 * entry `*.foo`) matches a scope entry's bare host.
 */
export function inScope(value: string, scope?: string[]): boolean {
  if (!scope || scope.length === 0) return true;
  const host = bareHost(value);
  if (!host) return false;
  return scope.some((entry) => {
    const s = bareHost(entry.startsWith("*.") ? entry.slice(2) : entry);
    if (!s) return false;
    return host === s || host.endsWith(`.${s}`);
  });
}

// ── Coverage gap → next-step mapping ─────────────────────────────────────────

/** The tool that would close a given coverage area's gap. */
const AREA_TOOL: Record<string, string> = {
  discovery: "lan-scan",
  recon: "port-scanner",
  ports: "port-scanner",
  services: "nmap",
  web: "web-exploit",
  tls: "tls-auditor",
  findings: "findings",
  report: "reporting",
};

function areaToolFor(area: CoverageArea): string {
  return AREA_TOOL[area.key] ?? "workbench";
}

/**
 * The open (un-covered) coverage areas, in the matrix's own order. This is the
 * gap set the next-step suggestions are built from.
 */
export function openAreas(coverage: EngagementCoverage | null): CoverageArea[] {
  if (!coverage) return [];
  return coverage.areas.filter((a) => !a.covered);
}

/** One next-step suggestion per open coverage area. Reuses coverageView tone. */
export function nextStepSuggestions(coverage: EngagementCoverage | null): Suggestion[] {
  return openAreas(coverage).map((area) => ({
    id: `next:${area.key}`,
    kind: "next-step" as const,
    title: `Close gap: ${area.label}`,
    detail: `${areaStatusLine(area)} — ${area.description}`,
    toolId: areaToolFor(area),
    tone: areaTone(area),
    areaKey: area.key,
  }));
}

// ── Param suggestions (arm- and scope-gated) ─────────────────────────────────

/**
 * Param suggestions from the active sub-target's assets. Returns [] (NO
 * suggestions) when:
 *   - there is no engagement or no active sub-target,
 *   - the active sub-target is not found among the records, OR
 *   - the active sub-target is NOT armed (arm gate).
 * Each surviving asset that maps to a targetable kind, has a non-empty value,
 * and is in scope becomes one suggestion. De-duplicated by (tool, value).
 */
export function paramSuggestions(input: SuggestInput): Suggestion[] {
  const { engagementId, activeSubTargetId, subTargets, assets, scope } = input;
  if (!engagementId || !activeSubTargetId) return [];

  const sub = subTargets.find((s) => s.id === activeSubTargetId);
  // Arm gate: an un-armed (or unknown) sub-target is not actionable → no params.
  if (!sub || !sub.armed) return [];

  const out: Suggestion[] = [];
  const seen = new Set<string>();
  for (const asset of assets) {
    // Ignore assets recorded under a different scope than the one in context.
    if (asset.subTargetId !== activeSubTargetId) continue;
    const map = ASSET_TOOL[asset.kind];
    if (!map) continue; // cert/tech: context, not a target
    const value = assetTarget(asset);
    if (!value) continue;
    if (!inScope(value, scope)) continue; // scope gate
    const dedupe = `${map.toolId}::${value.toLowerCase()}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    out.push({
      id: `param:${asset.subTargetId}:${asset.assetId}`,
      kind: "param",
      title: `Target ${map.noun}: ${value}`,
      detail: `Discovered ${asset.kind}${asset.tool ? ` via ${asset.tool}` : ""} — open ${map.toolId} pre-filled with this ${map.noun}.`,
      toolId: map.toolId,
      paramValue: value,
      tone: areaTone({ covered: true } as CoverageArea),
      subTargetId: asset.subTargetId,
    });
  }
  return out;
}

// ── Top-level derivation ─────────────────────────────────────────────────────

/**
 * The whole suggestion list for the current context: param suggestions
 * (arm/scope-gated) first, then next-step gap suggestions. Pure — same input,
 * same output — so the panel and the tests exercise the exact same rules.
 */
export function deriveSuggestions(input: SuggestInput): Suggestion[] {
  if (!input.engagementId) return [];
  return [...paramSuggestions(input), ...nextStepSuggestions(input.coverage)];
}
