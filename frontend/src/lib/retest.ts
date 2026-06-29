/**
 * Retest = replay the recorded Step chain for a finding to verify a fix.
 *
 * Talks to the backend `POST /labfs/{labId}/retest` (routers/labfs.py). Each
 * recorded Step is replayed (or, today, marked as a replay plug-in point); when
 * every previously-succeeding step now fails to reproduce its exploit, the
 * backend flips the finding's method state to "verified".
 */

import { api } from "../api";
import { listTargets } from "./targets";
import type { Finding } from "./engagement";

/** One step's replay outcome, mirroring backend `RetestStep`. */
export interface RetestStep {
  ordinal: number;
  tool_id: string;
  /** True once the step's tool was actually re-executed against the lab. */
  replayed: boolean;
  /** Human note — points at the re-exec plug-in until wiring lands. */
  note: string;
}

/** Full retest result, mirroring backend `RetestResult`. */
export interface RetestResult {
  finding_id: string;
  steps: RetestStep[];
  /** True when every step now fails to reproduce → fix confirmed. */
  verified: boolean;
  /** The finding's method state after the retest ("open" | "fixed" | "verified"). */
  state: string;
}

/**
 * Replay the Step chain recorded for `findingId` against the lab container.
 * Resolves to the per-step replay result; rejects (ApiError) on transport /
 * backend error.
 */
export async function retestFinding(
  labId: string,
  findingId: string,
): Promise<RetestResult> {
  return api<RetestResult>(`/labfs/${encodeURIComponent(labId)}/retest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId }),
  });
}

/**
 * Resolve the lab a finding was recorded against, or null if there isn't one.
 *
 * Lab-derived targets register with `kind="lab"` and carry `source_meta.lab_id`
 * plus an `address` of the form `host:port` (see backend lib/targets.py). A
 * finding's `target` mirrors that address, so we match the finding's target
 * against the engagement's lab targets and read back the lab id. Manual /
 * external findings have no lab and return null — the caller disables retest.
 */
export async function resolveFindingLabId(finding: Finding): Promise<string | null> {
  if (!finding.target) return null;
  let labs;
  try {
    labs = await listTargets({
      engagementId: finding.engagement_id,
      kind: "lab",
      includeHidden: true,
    });
  } catch {
    return null;
  }
  const want = finding.target.trim();
  const hit = labs.find(
    (t) => t.address === want || t.address.replace(/^https?:\/\//, "") === want,
  );
  const labId = hit?.source_meta?.lab_id;
  return typeof labId === "string" && labId ? labId : null;
}

/**
 * Append a step that durably records an operator-confirmed "why" for a prior
 * step. The steps log is append-only + hash-chained (backend lib/method.py), so
 * a confirmation is written as a NEW step whose `interpretation` is the supplied
 * rationale and whose `links_from` anchors it to the step being explained — it
 * survives reloads and shows up in the reconstructed method. We never invent the
 * rationale; this only persists text the operator typed.
 */
export async function confirmStepWhy(
  findingId: string,
  stepId: string,
  why: string,
): Promise<void> {
  await api<unknown>(`/method/findings/${encodeURIComponent(findingId)}/steps`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: { tool_id: "operator:confirm-why", params: { step: stepId } },
      evidence: { raw_output: why },
      interpretation: why,
      links_from: stepId,
      anchored: true,
    }),
  });
}
