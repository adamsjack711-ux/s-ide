/**
 * Read-only model API (Foundation lane) — the ONE surface every feature reads
 * shared engagement state through. No feature keeps a private copy of findings /
 * assets / runs / coverage; it calls these functions and re-reads on the
 * `modelChanged` bus event. (Phase-2 test T3 mutates a finding and asserts every
 * view reflects it with no manual refresh — a stale view means a private cache.)
 *
 * Everything here is a thin, typed projection over the existing clients
 * (lib/engagement, lib/spine, lib/methodAnalysis) and the backend routes. It
 * adapts the backend's snake_case records to the camelCase canonical refs in
 * shell/refs.ts so features touch only the frozen vocabulary. It performs READS
 * only — writes stay on their existing audited paths (promoteToFinding,
 * patchTrackedFinding, createPairingFinding, …), which now also emit
 * `modelChanged` so these reads stay fresh.
 *
 * Resolution notes (from the backend's real shape):
 *   - Findings carry a provenance triple only in the spine's PairingFinding, so
 *     listFindings/getFinding return those (id + subTargetId + targetId).
 *   - Assets have no persistent id; we synthesise a stable assetId = `kind:key`
 *     and scope them by scope_key (the sub-target/engagement scope string).
 *   - There is no per-engagement runs endpoint; listRuns fans out over the
 *     engagement's armed sub-targets.
 *   - Root cause anchors to a STEP today, not a code location; resolveAnchor is
 *     an honest best-effort that returns null when nothing anchors (never a
 *     fabricated file:line).
 */
import { authFetch } from "../api";
import {
  listEngagements, fetchCoverage,
  type Engagement, type EngagementCoverage, type Finding,
  type FindingSeverity, type FindingStatus,
} from "../lib/engagement";
import {
  listAllPairingFindings, listRuns as listSubTargetRuns, engagementArmed,
  type PairingFinding, type PairingRun, type SubTarget,
} from "../lib/spine";
import {
  analyzeMethod,
  type FindingMethod, type AnalyzedStep, type MethodGap,
} from "../lib/methodAnalysis";
import type {
  EngagementId, FindingRef, AssetRef, AssetKind, ConfLevel, Anchor, SubTargetRef,
} from "./refs";

// Re-export the canonical refs so a feature can `import { FindingRef, ... } from
// "../shell/model"` in one line alongside the read functions.
export type {
  EngagementId, TargetRef, SubTargetRef, AssetRef, AssetKind,
  FindingRef, StepRef, Anchor, ConfLevel,
} from "./refs";
export type {
  Engagement, EngagementCoverage, Finding, FindingSeverity, FindingStatus,
} from "../lib/engagement";
export type { PairingFinding, PairingRun } from "../lib/spine";
export type { FindingMethod, AnalyzedStep, MethodGap } from "../lib/methodAnalysis";

// ── Canonical projections ────────────────────────────────────────────────────

/** A step in a finding's evidence chain, already analysed (anchored/role/gaps
 *  computed deterministically). This is the canonical Step every feature reads. */
export type Step = AnalyzedStep;

/** A finding's full reasoning chain, ready to render / step through. */
export type EvidenceChain = {
  findingId: string;
  /** The raw method envelope (state / root_cause / remediation), or null if the
   *  finding has no method recorded yet. */
  method: FindingMethod | null;
  /** Ordered, analysed steps (empty when no chain captured). */
  steps: Step[];
  /** Deterministic gaps in the chain (missing-confirmation / unused / non-sequitur). */
  gaps: MethodGap[];
};

/** An asset discovered while probing a sub-target. `assetId` is synthesised as
 *  `kind:key` (stable within a scope) since the backend keys assets by
 *  (scope, kind, key) with no standalone id. */
export type Asset = {
  subTargetId: string;   // the scope_key the asset was recorded under
  assetId: string;       // `${kind}:${key}` — stable within the scope
  kind: AssetKind;
  key: string;
  props: Record<string, unknown>;
  tool: string;
};

/** One entry in the append-only audit/timeline ledger. Permissive by design —
 *  the backend row carries tool-specific extras; features read the common
 *  fields and fall back to the index signature for the rest. */
export type AuditEntry = {
  id: string;
  ts?: string;
  iso?: string;
  tool?: string;
  status?: "started" | "completed" | "error" | "stopped" | "refused" | string;
  engagement_id?: string | null;
  target?: string;
  summary?: string;
  [k: string]: unknown;
};

// ── Engagements ──────────────────────────────────────────────────────────────

/** The engagement record for `id`, or null if unknown. (No single-GET route
 *  exists; we resolve from the list, including archived.) */
export async function getEngagement(id: EngagementId): Promise<Engagement | null> {
  const list = await listEngagements(true);
  return list.find((e) => e.id === id) ?? null;
}

// ── Findings ─────────────────────────────────────────────────────────────────

export type FindingFilter = {
  severity?: FindingSeverity[];
  status?: FindingStatus[];
  confidence?: ConfLevel[];
  subTargetId?: string;
};

/** All findings for an engagement (with the provenance triple), newest-relevant
 *  order preserved from the backend, optionally filtered. */
export async function listFindings(
  engagementId: EngagementId,
  filter?: FindingFilter,
): Promise<PairingFinding[]> {
  const all = await listAllPairingFindings();
  let out = all.filter((f) => f.engagement_id === engagementId);
  if (filter?.severity?.length) {
    const set = new Set(filter.severity);
    out = out.filter((f) => set.has(f.severity));
  }
  if (filter?.status?.length) {
    const set = new Set(filter.status);
    out = out.filter((f) => set.has(f.status));
  }
  if (filter?.confidence?.length) {
    const set = new Set(filter.confidence);
    out = out.filter((f) => set.has(confLevel(f)));
  }
  if (filter?.subTargetId) {
    out = out.filter((f) => f.sub_target_id === filter.subTargetId);
  }
  return out;
}

/** A single finding by ref (or bare id). Null if not found in the active scope. */
export async function getFinding(
  ref: FindingRef | string,
): Promise<PairingFinding | null> {
  const id = typeof ref === "string" ? ref : ref.findingId;
  const all = await listAllPairingFindings();
  return all.find((f) => f.id === id) ?? null;
}

/**
 * Confidence of a finding. INVARIANT (T5): only a finding whose tracked status
 * is `confirmed` reads as `confirmed`; everything else is `suspected`. A view
 * MUST NOT upgrade suspected→confirmed — always derive through this function.
 */
export function confLevel(f: Pick<Finding, "status">): ConfLevel {
  return f.status === "confirmed" ? "confirmed" : "suspected";
}

/** The provenance-triple ref for a spine finding. */
export function toFindingRef(f: PairingFinding): FindingRef {
  return { findingId: f.id, subTargetId: f.sub_target_id, targetId: f.target_id };
}

// ── Evidence chain (the "debugger" source) ───────────────────────────────────

/** A finding's ordered, analysed reasoning chain. Read-only replay data — never
 *  re-fires tools. Empty chain (no steps) is a valid, non-error state. */
export async function getEvidenceChain(findingId: string): Promise<EvidenceChain> {
  let method: FindingMethod | null = null;
  try {
    const r = await authFetch(`/method/findings/${encodeURIComponent(findingId)}`);
    if (r.ok) method = (await r.json()) as FindingMethod;
  } catch {
    method = null;
  }
  const { steps, gaps } = analyzeMethod({ steps: method?.steps ?? [] });
  return { findingId, method, steps, gaps };
}

// ── Coverage ─────────────────────────────────────────────────────────────────

export function getCoverage(engagementId: EngagementId): Promise<EngagementCoverage> {
  return fetchCoverage(engagementId);
}

// ── Runs ─────────────────────────────────────────────────────────────────────

/**
 * Pairing runs for an engagement. With a sub-target ref, one call; without, fan
 * out over the engagement's armed sub-targets and flatten (there is no
 * per-engagement runs route). Failures on individual sub-targets are skipped so
 * one bad sub-target doesn't sink the whole list.
 */
export async function listRuns(
  engagementId: EngagementId,
  subTargetRef?: Pick<SubTargetRef, "subTargetId">,
): Promise<PairingRun[]> {
  if (subTargetRef?.subTargetId) {
    return listSubTargetRuns(subTargetRef.subTargetId);
  }
  let armed: SubTarget[] = [];
  try {
    armed = await engagementArmed(engagementId);
  } catch {
    return [];
  }
  const perSub = await Promise.all(
    armed.map((s) => listSubTargetRuns(s.id).catch(() => [] as PairingRun[])),
  );
  return perSub.flat();
}

/**
 * A single run by id. No direct route exists, so we scan the active engagement's
 * runs (optionally narrowed by sub-target). Returns null if not found — callers
 * that already hold the run object should prefer it over this scan.
 */
export async function getRun(
  runId: string,
  scope?: { engagementId: EngagementId; subTargetId?: string },
): Promise<PairingRun | null> {
  if (!scope?.engagementId) return null;
  const runs = await listRuns(
    scope.engagementId,
    scope.subTargetId ? { subTargetId: scope.subTargetId } : undefined,
  );
  return runs.find((r) => r.id === runId) ?? null;
}

// ── Assets ───────────────────────────────────────────────────────────────────

/**
 * Assets recorded under a sub-target's scope. Reads GET /method/assets/{scope}.
 * With no ref, returns [] (assets are always scope-relative). Synthesises a
 * stable assetId per (kind,key).
 */
export async function listAssets(
  subTargetRef?: Pick<SubTargetRef, "subTargetId">,
): Promise<Asset[]> {
  const scope = subTargetRef?.subTargetId;
  if (!scope) return [];
  try {
    const r = await authFetch(`/method/assets/${encodeURIComponent(scope)}`);
    if (!r.ok) return [];
    const body = (await r.json()) as {
      assets?: { kind: string; key: string; props?: Record<string, unknown>; tool?: string }[];
    };
    return (body.assets ?? []).map((a) => ({
      subTargetId: scope,
      assetId: `${a.kind}:${a.key}`,
      kind: a.kind as AssetKind,
      key: a.key,
      props: a.props ?? {},
      tool: a.tool ?? "",
    }));
  } catch {
    return [];
  }
}

/** Build an AssetRef from a resolved Asset. */
export function toAssetRef(a: Asset): AssetRef {
  return { subTargetId: a.subTargetId, assetId: a.assetId, kind: a.kind };
}

// ── Audit / timeline ledger ──────────────────────────────────────────────────

export type AuditFilter = {
  tool?: string;
  status?: string;
  limit?: number;
};

/**
 * The append-only audit ledger for an engagement (runs, arm/disarm,
 * attestations, state changes), newest-first. Read-only — this endpoint has no
 * writer. Returns [] on failure (a missing ledger is an empty timeline, not an
 * error).
 */
export async function listAudit(
  engagementId: EngagementId,
  filter?: AuditFilter,
): Promise<AuditEntry[]> {
  const qs = new URLSearchParams();
  if (engagementId) qs.set("engagement_id", engagementId);
  if (filter?.tool) qs.set("tool", filter.tool);
  if (filter?.status) qs.set("status", filter.status);
  qs.set("limit", String(filter?.limit ?? 200));
  try {
    const r = await authFetch(`/audit-log?${qs.toString()}`);
    if (!r.ok) return [];
    const body = (await r.json()) as { actions?: AuditEntry[] };
    return body.actions ?? [];
  } catch {
    return [];
  }
}

// ── Anchor resolution (root cause) ───────────────────────────────────────────

const URL_RE = /^(https?:)?\/\//i;
// A `file:line` token, e.g. `src/auth/login.ts:42` or `parser.py:10`. The file
// part must look like a real path — contain a `/`, OR end in an allow-listed
// source extension — so a bare `host:port` (`api.example.com:8080`, `10.0.0.5:443`)
// in evidence text is NOT mistaken for a source location and turned into a bogus
// file anchor. KEEP IN SYNC with the identical regex in features/search/searchLogic.ts.
const FILE_LINE_RE =
  /((?:[\w.~-]*\/[\w./~-]+)|(?:[\w.~-]+\.(?:tsx?|jsx?|mjs|cjs|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|cs|kt|swift|scala|sh|sql|html?|css|scss|less|json|ya?ml|toml|ini|cfg|conf|xml|vue|svelte|md))):(\d+)/i;

/**
 * Best-effort root-cause anchor for a finding. HONEST: returns null when nothing
 * in the model anchors the finding to a location — the pivot then surfaces "no
 * root cause anchored yet" rather than inventing a file:line. Resolution order:
 *   1. A step's action.params.file (+ optional line / lab) → file anchor.
 *   2. A `file:line` token in a step's evidence/interpretation → file anchor.
 *   3. The finding's target parsed as a URL → route anchor (its path).
 *   4. Otherwise null.
 */
export async function resolveAnchor(ref: FindingRef | string): Promise<Anchor | null> {
  const findingId = typeof ref === "string" ? ref : ref.findingId;
  const chain = await getEvidenceChain(findingId);
  // 1 + 2: look through steps for a concrete file location.
  for (const s of chain.steps) {
    const p = s.action?.params as Record<string, unknown> | undefined;
    const file = typeof p?.file === "string" ? p.file : undefined;
    if (file) {
      const line = typeof p?.line === "number" ? p.line : undefined;
      const labId = typeof p?.labId === "string" ? p.labId : undefined;
      return { kind: "file", file, line, labId };
    }
    const hay = `${s.interpretation ?? ""}\n${
      typeof s.evidence?.raw_output === "string" ? s.evidence.raw_output : ""
    }`;
    const m = FILE_LINE_RE.exec(hay);
    if (m) return { kind: "file", file: m[1], line: Number(m[2]) };
  }
  // 3: fall back to the finding's target as a route, if it's URL-shaped.
  const f = await getFinding(findingId);
  const target = f?.target ?? "";
  if (target && (URL_RE.test(target) || target.startsWith("/"))) {
    try {
      const route = URL_RE.test(target)
        ? new URL(target.startsWith("//") ? `https:${target}` : target).pathname
        : target;
      return { kind: "route", route };
    } catch {
      return { kind: "route", route: target };
    }
  }
  return null;
}
