/**
 * stepLogic — the PURE, deterministic core of the F9 evidence-chain debugger.
 * No network, no React, no bus. Everything here is a total function over an
 * already-analysed Step[] (the model's canonical `Step`, i.e. AnalyzedStep):
 * index clamping, forward/back/reset stepping, trigger-step ("BREAK") detection,
 * and secret redaction of a step for display.
 *
 * Why a separate module: the panel is a thin shell around these functions; the
 * safety-critical decisions (bounds, "is this step inferred?", "where does the
 * vuln get established?", "what must be masked before render?") are unit-tested
 * here with fixtures and never touch the wire. See stepLogic.test.ts.
 *
 * SECURITY: this is read-only replay logic. It NEVER runs a tool. `redactStep`
 * masks secrets so the panel can render captured evidence without leaking
 * tokens/keys/cookies/Authorization. An unanchored step is INFERRED — callers
 * must label it as such and never present it as fact (see `isInferred`).
 */
import type { Step, FindingMethod } from "../../shell/model";

// ── Index / stepping (debugger controls) ─────────────────────────────────────

/**
 * Clamp a desired step index into the valid range for `steps`. An empty chain
 * has no valid index → returns 0 (the panel renders its empty state instead of
 * indexing). Never returns an out-of-bounds index.
 */
export function clampIndex(index: number, steps: readonly Step[]): number {
  if (steps.length === 0) return 0;
  if (Number.isNaN(index)) return 0; // NaN has no meaningful position → first step
  const max = steps.length - 1;
  // +Infinity → last, -Infinity → first, else truncate toward zero.
  if (index === Infinity) return max;
  if (index === -Infinity) return 0;
  const i = Math.trunc(index);
  if (i < 0) return 0;
  if (i > max) return max;
  return i;
}

/** Step forward one (clamped at the last step). */
export function stepForward(index: number, steps: readonly Step[]): number {
  return clampIndex(index + 1, steps);
}

/** Step back one (clamped at the first step). */
export function stepBack(index: number, steps: readonly Step[]): number {
  return clampIndex(index - 1, steps);
}

/** Reset to the first step (index 0). Reset is defined even for an empty chain. */
export function reset(): number {
  return 0;
}

/** True when the given index is the first step of a non-empty chain. */
export function atStart(index: number, steps: readonly Step[]): boolean {
  return steps.length === 0 || clampIndex(index, steps) <= 0;
}

/** True when the given index is the last step of a non-empty chain. */
export function atEnd(index: number, steps: readonly Step[]): boolean {
  return steps.length === 0 || clampIndex(index, steps) >= steps.length - 1;
}

// ── Inferred vs. anchored ────────────────────────────────────────────────────

/**
 * A step is INFERRED when it is NOT anchored — its rationale isn't grounded in a
 * prior result in the chain (see lib/methodAnalysis `anchored`). The panel MUST
 * render an inferred step as a guess, never as established fact. This is the one
 * predicate the UI uses to decide the "inferred" label, so it lives here and is
 * tested directly.
 */
export function isInferred(step: Step): boolean {
  return !step.anchored;
}

/** Human status for a step's grounding — drives the badge text. */
export function anchoredStatus(step: Step): "anchored" | "inferred" {
  return step.anchored ? "anchored" : "inferred";
}

// ── Trigger step (the "BREAK" target) ────────────────────────────────────────

/**
 * Same assertion vocabulary as lib/methodAnalysis (kept local so this module is
 * self-contained and testable without importing analysis internals). A step
 * whose interpretation asserts a result is a candidate for "this established the
 * vulnerability".
 */
const ASSERTION_HINTS = [
  "confirm", "confirmed", "vulnerable", "exploitable", "succeed", "succeeded",
  "success", "works", "worked", "proves", "proven", "verified", "valid",
  "leaked", "leak", "exposed", "bypass", "bypassed", "injected", "executed",
  "compromise", "compromised", "access", "achieved",
];

function assertsResult(interpretation: string | null | undefined): boolean {
  if (!interpretation) return false;
  const lc = interpretation.toLowerCase();
  return ASSERTION_HINTS.some((w) => new RegExp(`\\b${w}\\b`, "i").test(lc));
}

/**
 * Find the "trigger" step — the one that ESTABLISHED the vulnerability, where a
 * debugger would BREAK. Resolution order (most authoritative first):
 *
 *   1. method.root_cause.anchor names a step id present in the chain → that step.
 *   2. Otherwise the LAST step whose interpretation asserts a result (the final
 *      claim that the finding holds).
 *   3. Otherwise the last step of the chain (the terminus is the de-facto result).
 *
 * Returns the step's INDEX (into `steps` as passed), or null for an empty chain.
 * `steps` should be in the same order the panel renders (ordinal order from the
 * model). Deterministic — same inputs, same index.
 */
export function findTriggerIndex(
  steps: readonly Step[],
  method?: Pick<FindingMethod, "root_cause"> | null,
): number | null {
  if (steps.length === 0) return null;

  // 1: explicit root-cause anchor to a step id.
  const anchorId = method?.root_cause?.anchor;
  if (typeof anchorId === "string" && anchorId.length > 0) {
    const idx = steps.findIndex((s) => s.id === anchorId);
    if (idx >= 0) return idx;
  }

  // 2: last step that asserts a result.
  for (let i = steps.length - 1; i >= 0; i--) {
    if (assertsResult(steps[i].interpretation)) return i;
  }

  // 3: terminus.
  return steps.length - 1;
}

// ── Secret redaction (before ANY evidence/request/response is rendered) ───────

/**
 * Redaction patterns applied to any string shown to the user (evidence
 * raw_output, request/response text, param values). Conservative: over-masking a
 * benign token is acceptable; leaking a real one is not. Order matters — longer /
 * more specific patterns first.
 */
const REDACTIONS: { re: RegExp; replace: (m: string, ...g: string[]) => string }[] = [
  // Authorization / auth headers: keep the scheme, mask the credential.
  {
    re: /\b(authorization|proxy-authorization)\s*[:=]\s*(bearer|basic|digest|negotiate|token)?\s*\S+/gi,
    replace: (_m, key: string, scheme?: string) =>
      `${key}: ${scheme ? scheme + " " : ""}«redacted»`,
  },
  // Cookie / Set-Cookie headers — mask the whole value.
  {
    re: /\b(set-cookie|cookie)\s*[:=]\s*[^\r\n]+/gi,
    replace: (_m, key: string) => `${key}: «redacted»`,
  },
  // Common secret-bearing key/value pairs (json, query, headers, env).
  {
    re: /\b(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|secret|password|passwd|pwd|client[_-]?secret|private[_-]?key|session[_-]?id|sessionid|token|auth)\b(\s*["']?\s*[:=]\s*["']?)([^\s"',&}]+)/gi,
    replace: (_m, key: string, sep: string) => `${key}${sep}«redacted»`,
  },
  // Bearer tokens / JWT-ish blobs appearing bare.
  { re: /\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/g, replace: () => "Bearer «redacted»" },
  { re: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g, replace: () => "«redacted-jwt»" },
  // AWS access key ids.
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: () => "«redacted-aws-key»" },
  // Long hex/base64-ish secrets (32+ chars) — likely keys, not evidence text.
  { re: /\b[A-Fa-f0-9]{32,}\b/g, replace: () => "«redacted-secret»" },
];

/** Mask secrets in a single string. Safe on any input; returns "" for nullish. */
export function redactString(text: unknown): string {
  if (typeof text !== "string" || text.length === 0) return "";
  let out = text;
  for (const { re, replace } of REDACTIONS) {
    out = out.replace(re, replace as (substring: string, ...args: any[]) => string);
  }
  return out;
}

/** Deep-redact a params object's string values for safe display. */
export function redactParams(
  params: Record<string, unknown> | undefined | null,
): Record<string, unknown> {
  if (!params || typeof params !== "object") return {};
  const out: Record<string, unknown> = {};
  const SENSITIVE = /(key|token|secret|password|passwd|pwd|auth|cookie|session)/i;
  for (const [k, v] of Object.entries(params)) {
    if (SENSITIVE.test(k)) {
      out[k] = "«redacted»";
    } else if (typeof v === "string") {
      out[k] = redactString(v);
    } else if (v && typeof v === "object" && !Array.isArray(v)) {
      out[k] = redactParams(v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * A single step projected into a redacted, display-ready shape. This is what the
 * panel renders — the raw Step never reaches the DOM directly, so secrets can't
 * leak through evidence/interpretation/params. `inferred` is precomputed so the
 * UI can't forget to label it.
 */
export type RedactedStep = {
  id: string;
  ordinal: number;
  toolId: string;
  params: Record<string, unknown>;
  rawOutput: string;
  hash?: string;
  timestamp?: string | number;
  interpretation: string | null;
  hasInterpretation: boolean;
  anchored: boolean;
  inferred: boolean;
};

/** Project a Step into a redacted, render-safe view. Pure & total. */
export function redactStep(step: Step): RedactedStep {
  const toolId =
    typeof step.action?.tool_id === "string" && step.action.tool_id
      ? step.action.tool_id
      : "(unknown tool)";
  const rawOut = redactString(step.evidence?.raw_output);
  return {
    id: step.id,
    ordinal: step.ordinal,
    toolId,
    params: redactParams(step.action?.params as Record<string, unknown> | undefined),
    rawOutput: rawOut,
    hash: step.evidence?.hash,
    timestamp: step.evidence?.timestamp,
    // Interpretation is operator text; still run it through redaction in case a
    // secret was pasted into a rationale. Preserve null (no rationale recorded)
    // so the UI can distinguish "no why" from "empty why".
    interpretation:
      typeof step.interpretation === "string"
        ? redactString(step.interpretation)
        : null,
    hasInterpretation: step.hasInterpretation,
    anchored: step.anchored,
    inferred: isInferred(step),
  };
}
