/**
 * Retest = replay the recorded Step chain for a finding to verify a fix.
 *
 * Talks to the backend `POST /labfs/{labId}/retest` (routers/labfs.py). Each
 * recorded Step is replayed (or, today, marked as a replay plug-in point); when
 * every previously-succeeding step now fails to reproduce its exploit, the
 * backend flips the finding's method state to "verified".
 */

import { api } from "../api";

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
