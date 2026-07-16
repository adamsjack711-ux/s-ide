/**
 * pivotLogic — the PURE, deterministic core of F3 (Pivot navigation).
 *
 * No network, no React, no bus, no model. Given an INCOMING selection event plus
 * whatever the model already resolved (an Anchor / a step location / nothing),
 * these functions decide WHAT — if anything — the pivot router should publish.
 * The headless router (Pivot.tsx) is a thin shell that does the async resolution
 * (resolveAnchor / getEvidenceChain) and then hands the result here to get the
 * publish decision. That keeps the safety-critical routing rules — "ignore my own
 * echo", "never re-broadcast selectAsset", "a dangling ref publishes nothing" —
 * unit-testable with fixtures and off the wire. See pivotLogic.test.ts.
 *
 * The pivot is a pure connector: it NEVER runs a tool, NEVER mutates the model,
 * NEVER upgrades a finding's confidence. It only translates one selection into
 * (at most) one `selectAnchor` broadcast so the code view + inspector can follow.
 *
 * FEEDBACK-LOOP SAFETY: the router both PUBLISHES `selectAnchor` and (via its
 * inspector) SUBSCRIBES to selection events. Every decision here is guarded on
 * the incoming event's `source`: an event we ourselves emitted (source === our
 * id) is ignored, so a `selectFinding`→`selectAnchor` broadcast can never bounce
 * back and re-trigger us. We also NEVER subscribe-and-republish the same event
 * kind (no selectAnchor→selectAnchor).
 */
import type { Anchor, FindingRef, StepRef } from "../../shell/refs";

/** The id every pivot broadcast is stamped with (and the one we ignore on input). */
export const PIVOT_SOURCE = "pivot";

/**
 * The router's only outbound action: broadcast a `selectAnchor` carrying the
 * resolved location + the originating finding id. A decision of `null` means
 * "publish NOTHING" (a dangling ref, an own-echo, or a selectAsset — the asset
 * panel highlights itself and the pivot stays quiet).
 */
export type PivotDecision =
  | { emit: "selectAnchor"; payload: { ref: Anchor; findingId: string; source: string } }
  | null;

/** Build the single `selectAnchor` broadcast for a resolved anchor. */
function toSelectAnchor(anchor: Anchor, findingId: string): PivotDecision {
  return {
    emit: "selectAnchor",
    payload: { ref: anchor, findingId, source: PIVOT_SOURCE },
  };
}

/**
 * Decision for an incoming `selectFinding`.
 *
 * @param source   the publishing feature's id (from the event).
 * @param ref      the focused finding.
 * @param anchor   what the model's `resolveAnchor(ref)` returned (Anchor | null).
 *
 * Rules:
 *   - own echo (source === PIVOT_SOURCE) → publish nothing (loop guard).
 *   - anchor resolved                    → broadcast `selectAnchor` (fixdiff +
 *     inspector follow), tagged with the originating findingId.
 *   - anchor === null (dangling ref)     → publish NOTHING; the inspector surfaces
 *     "no root cause anchored yet" — we never fabricate a location.
 */
export function decideOnSelectFinding(
  source: string,
  ref: FindingRef,
  anchor: Anchor | null,
): PivotDecision {
  if (source === PIVOT_SOURCE) return null; // ignore our own echo — no loop
  if (!anchor) return null; // dangling ref → nothing published (honest gap)
  return toSelectAnchor(anchor, ref.findingId);
}

/**
 * Decision for an incoming `selectStep`.
 *
 * The caller resolves the step's location and passes it as `anchor`: prefer the
 * step's OWN `action.params.file` (via the finding's evidence chain), else fall
 * back to the finding's root-cause anchor (`resolveAnchor(findingId)`). Either way
 * the resolved location (or null) arrives here.
 *
 * Rules mirror selectFinding: own-echo → nothing; a resolved location →
 * `selectAnchor` (tagged with the step's findingId); nothing resolved → nothing.
 */
export function decideOnSelectStep(
  source: string,
  ref: StepRef,
  anchor: Anchor | null,
): PivotDecision {
  if (source === PIVOT_SOURCE) return null; // ignore our own echo — no loop
  if (!anchor) return null; // no location resolved → publish nothing
  return toSelectAnchor(anchor, ref.findingId);
}

/**
 * Decision for an incoming `selectAsset`.
 *
 * Per spec the pivot publishes NOTHING for an asset selection: the asset tree
 * highlights itself and the graph node reacts on its own. The inspector MAY
 * update its displayed context, but the router never re-broadcasts. Always null.
 */
export function decideOnSelectAsset(): PivotDecision {
  return null;
}

/**
 * Resolve a STEP's own file location from its evidence chain, WITHOUT any
 * network — pure over the already-loaded steps. Pull the step by `stepId` and,
 * if its `action.params.file` is set, build a { kind:"file" } anchor from it
 * (+ optional line / labId). Returns null when the step is absent or carries no
 * file param, so the caller falls back to the finding-level anchor. Never throws;
 * never fabricates a location.
 *
 * `steps` is the model's canonical Step[] (AnalyzedStep) shape; we only read
 * `id` and `action.params`, so the param type is kept minimal here to keep this
 * module free of the model import surface.
 */
export function stepFileAnchor(
  steps: ReadonlyArray<{ id: string; action?: { params?: Record<string, unknown> } | null }>,
  stepId: string,
): Anchor | null {
  const step = steps.find((s) => s.id === stepId);
  const params = step?.action?.params as Record<string, unknown> | undefined;
  const file = typeof params?.file === "string" ? params.file : undefined;
  if (!file) return null;
  const line = typeof params?.line === "number" ? params.line : undefined;
  const labId = typeof params?.labId === "string" ? params.labId : undefined;
  return { kind: "file", file, line, labId };
}
