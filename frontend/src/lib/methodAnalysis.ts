/**
 * methodAnalysis — pure, deterministic reconstruction of an operator's method
 * from a finding's Step chain. No network, no React, no side effects.
 *
 * The Step model (mirrors backend lib/method.py / routers/method.py):
 *   action + evidence  → FACT      (what tool ran, what the log captured)
 *   interpretation     → INFERENCE (the operator's "why", may be null)
 *   links_from         → the id of the prior step whose output justifies this one
 *
 * A step is *anchored* when its `links_from` names an EARLIER step that actually
 * exists in the chain — i.e. its rationale is grounded in a real prior result.
 * An unanchored step's "why" is not backed by anything in the chain; we surface
 * it as a guess and NEVER fabricate a rationale for it.
 */

/** A raw step as returned by GET /method/findings/{fid}. */
export interface MethodStep {
  id: string;
  finding_id: string;
  ordinal: number;
  /** FACT — the tool invocation. */
  action: { tool_id?: string; params?: Record<string, unknown> } & Record<string, unknown>;
  /** FACT — what the log captured. */
  evidence: {
    raw_output?: string;
    hash?: string;
    timestamp?: string | number;
  } & Record<string, unknown>;
  /** INFERENCE — the operator's stated "why". May be null. */
  interpretation: string | null;
  /** The prior step id this step's output justifies, or null. */
  links_from: string | null;
  anchored: boolean;
  prev_hash: string;
  row_hash: string;
}

/** The method as returned by GET /method/findings/{fid}. */
export interface FindingMethod {
  finding_id: string;
  state: "open" | "fixed" | "verified" | string;
  root_cause: { anchor?: string; explanation?: string } | null;
  remediation: { change?: string; why?: string } | null;
  steps: MethodStep[];
}

/** FACT lives in action+evidence; INFERENCE lives in interpretation. */
export type StepRole = "fact" | "inference";

/** A step with our computed annotations layered on. */
export interface AnalyzedStep extends MethodStep {
  /**
   * Recomputed locally: links_from is set AND a step with that id exists
   * EARLIER in the chain. We do not trust the stored `anchored` flag blindly —
   * this is the deterministic, auditable version.
   */
  anchored: boolean;
  /** Always "fact" — the action+evidence are the factual spine of the step. */
  role: StepRole;
  /** True when the operator recorded an interpretation (the INFERENCE layer). */
  hasInterpretation: boolean;
}

export type GapType =
  | "missing_confirmation"
  | "unused_output"
  | "non_sequitur";

export interface MethodGap {
  type: GapType;
  stepId: string;
  note: string;
}

export interface MethodAnalysis {
  steps: AnalyzedStep[];
  gaps: MethodGap[];
}

/**
 * Words in an interpretation that assert a result/state was achieved. If a step
 * claims one of these but no later step links back to it, that result was never
 * confirmed downstream → MISSING CONFIRMATION.
 */
const ASSERTION_HINTS = [
  "confirm",
  "confirmed",
  "vulnerable",
  "exploitable",
  "succeed",
  "succeeded",
  "success",
  "works",
  "worked",
  "proves",
  "proven",
  "verified",
  "valid",
  "leaked",
  "leak",
  "exposed",
  "bypass",
  "bypassed",
  "injected",
  "executed",
  "compromise",
  "compromised",
  "access",
  "achieved",
];

function assertsResult(interpretation: string | null): boolean {
  if (!interpretation) return false;
  const lc = interpretation.toLowerCase();
  return ASSERTION_HINTS.some((w) => {
    // word-boundary-ish match to avoid e.g. "successor" tripping "success"
    const re = new RegExp(`\\b${w}\\b`, "i");
    return re.test(lc);
  });
}

/**
 * Analyze a finding's step chain. Pure & deterministic — same input always
 * yields the same output, with steps kept in ordinal order.
 *
 * Anchoring rule: a step is anchored iff `links_from` is set AND a step with
 * that id appears strictly earlier (lower ordinal / earlier index) in the
 * chain. Forward or self references do not anchor.
 */
export function analyzeMethod(method: Pick<FindingMethod, "steps">): MethodAnalysis {
  const ordered = [...(method.steps ?? [])].sort((a, b) => a.ordinal - b.ordinal);

  // Map id → index for "earlier in the chain" checks.
  const indexById = new Map<string, number>();
  ordered.forEach((s, i) => indexById.set(s.id, i));

  const analyzed: AnalyzedStep[] = ordered.map((s, i) => {
    const target = s.links_from;
    const targetIdx = target != null ? indexById.get(target) : undefined;
    const anchored = target != null && targetIdx !== undefined && targetIdx < i;
    return {
      ...s,
      anchored,
      role: "fact",
      hasInterpretation:
        typeof s.interpretation === "string" && s.interpretation.trim().length > 0,
    };
  });

  // Which step ids are referenced as a `links_from` by some LATER step?
  // (Used for both unused-output and missing-confirmation detection.)
  const referencedByLater = new Set<string>();
  analyzed.forEach((s, i) => {
    const target = s.links_from;
    if (target == null) return;
    const targetIdx = indexById.get(target);
    if (targetIdx !== undefined && targetIdx < i) referencedByLater.add(target);
  });

  const gaps: MethodGap[] = [];

  for (let i = 0; i < analyzed.length; i++) {
    const s = analyzed[i];

    // (a) MISSING CONFIRMATION — the step asserts a result but no later step
    // links back to it to confirm/build on that result.
    if (assertsResult(s.interpretation) && !referencedByLater.has(s.id)) {
      gaps.push({
        type: "missing_confirmation",
        stepId: s.id,
        note: "Asserts a result, but no later step confirms or builds on it.",
      });
    }

    // (b) UNUSED OUTPUT — the step produced evidence but no later step's
    // links_from references it. (Skip the final step: nothing can follow it,
    // so "unused" would be a false positive — its output is the terminus.)
    const isLast = i === analyzed.length - 1;
    const hasEvidence =
      !!s.evidence &&
      (typeof s.evidence.raw_output === "string"
        ? s.evidence.raw_output.length > 0
        : Object.keys(s.evidence).length > 0);
    if (!isLast && hasEvidence && !referencedByLater.has(s.id)) {
      gaps.push({
        type: "unused_output",
        stepId: s.id,
        note: "Produced evidence that no later step references.",
      });
    }

    // (c) NON-SEQUITUR — links_from is null or dangling (points nowhere valid /
    // not earlier), so the step's "why" isn't justified by a prior result.
    // The very first step is exempt: it legitimately opens the chain.
    if (i > 0 && !s.anchored) {
      const dangling = s.links_from != null; // set, but didn't resolve earlier
      gaps.push({
        type: "non_sequitur",
        stepId: s.id,
        note: dangling
          ? "links_from points to no earlier step — its rationale is dangling."
          : "No links_from — its rationale isn't tied to any prior result.",
      });
    }
  }

  return { steps: analyzed, gaps };
}

/** Human label for a gap type (UI-facing). */
export function gapLabel(type: GapType): string {
  switch (type) {
    case "missing_confirmation":
      return "Missing confirmation";
    case "unused_output":
      return "Unused output";
    case "non_sequitur":
      return "Non-sequitur";
  }
}
