/**
 * problemsLogic — pure, deterministic sort/filter/count for the Problems panel.
 *
 * No network, no React, no bus. Everything here operates on an already-fetched
 * list of findings (each already paired with its derived fix-state + confidence
 * level) so it can be unit-tested with fixtures. The panel does the reads
 * (listFindings + getEvidenceChain) and the confLevel() derivation, then hands
 * the enriched rows here to be ordered / filtered / tallied.
 *
 * SECURITY INVARIANT (mirrors CONTRACT.md + shell/model.ts confLevel): confidence
 * is NEVER computed here from a raw status by upgrading — the caller must pass a
 * ConfLevel already derived via confLevel(). deriveConfLevel() below is a pure
 * mirror of the model's rule for TEST use only: `confirmed` iff status is exactly
 * "confirmed"; everything else is `suspected`. It can only ever LOWER, never
 * fabricate a `confirmed`.
 */
import type {
  PairingFinding, FindingSeverity, FindingStatus, ConfLevel,
} from "../../shell/model";

/** The tracked fix-state read off a finding's evidence-chain method envelope. */
export type FixState = "open" | "fixed" | "verified";

export const FIX_STATES: FixState[] = ["open", "fixed", "verified"];

/**
 * A finding enriched with the two derived facts the panel renders and filters
 * on: its fix-STATE (from getEvidenceChain → method?.state, default "open") and
 * its ConfLevel (from confLevel(), never upgraded). The row keeps the whole
 * finding so the panel can render title/severity/target and build the ref.
 */
export type ProblemRow = {
  finding: PairingFinding;
  fixState: FixState;
  conf: ConfLevel;
};

// Severity ranking + order now live in lib/severity (one source of truth,
// derived from FINDING_SEVERITIES). Re-exported so ProblemsPanel's import stays put.
import { severityRank, SEVERITY_ORDER } from "../../lib/severity";
export { SEVERITY_ORDER };

/**
 * Normalise a raw method state string to one of the three canonical fix-states.
 * Anything that isn't exactly "fixed" or "verified" (including missing method,
 * legacy values, or a null) collapses to "open" — the safe default per spec.
 */
export function normalizeFixState(raw: string | null | undefined): FixState {
  if (raw === "fixed") return "fixed";
  if (raw === "verified") return "verified";
  return "open";
}

/**
 * PURE mirror of shell/model.ts confLevel() for tests only. NEVER upgrades:
 * only an exact "confirmed" status yields "confirmed"; all else "suspected".
 * Production code derives conf via the real confLevel() and passes it in.
 */
export function deriveConfLevel(status: FindingStatus | string): ConfLevel {
  return status === "confirmed" ? "confirmed" : "suspected";
}

/**
 * Stable severity sort: critical → high → medium → low → info. Findings of equal
 * severity keep their incoming (backend) order — a stable sort, so the panel's
 * newest-relevant ordering survives within a severity band.
 */
export function sortRowsBySeverity(rows: ProblemRow[]): ProblemRow[] {
  return rows
    .map((row, i) => ({ row, i }))
    .sort((a, b) => {
      const d = severityRank(a.row.finding.severity) - severityRank(b.row.finding.severity);
      return d !== 0 ? d : a.i - b.i;
    })
    .map((x) => x.row);
}

/** Active filter selection. Empty/absent arrays mean "no constraint on this axis". */
export type ProblemFilters = {
  severity?: FindingSeverity[];
  fixState?: FixState[];
  confidence?: ConfLevel[];
  subTargetId?: string | null;
};

/**
 * Apply the client-side filters. Each axis is independent (AND across axes,
 * OR within an axis). An empty array or absent value on an axis imposes no
 * constraint. `subTargetId` null/empty means "all sub-targets".
 */
export function filterRows(rows: ProblemRow[], filters: ProblemFilters): ProblemRow[] {
  const sevSet = filters.severity?.length ? new Set(filters.severity) : null;
  const stateSet = filters.fixState?.length ? new Set(filters.fixState) : null;
  const confSet = filters.confidence?.length ? new Set(filters.confidence) : null;
  const sub = filters.subTargetId || null;

  return rows.filter((r) => {
    if (sevSet && !sevSet.has(r.finding.severity)) return false;
    if (stateSet && !stateSet.has(r.fixState)) return false;
    if (confSet && !confSet.has(r.conf)) return false;
    if (sub && r.finding.sub_target_id !== sub) return false;
    return true;
  });
}

/** Per-severity tally, keyed by every severity (missing = 0) in canonical order. */
export type SeverityCounts = Record<FindingSeverity, number>;

export function countBySeverity(rows: ProblemRow[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of rows) {
    const s = r.finding.severity;
    if (s in counts) counts[s as FindingSeverity] += 1;
  }
  return counts;
}

/**
 * The distinct sub-target ids present in the rows, in first-seen order. Drives
 * the sub-target filter control (derived from the data, not a separate fetch).
 */
export function subTargetIds(rows: ProblemRow[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of rows) {
    const id = r.finding.sub_target_id;
    if (id && !seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

/**
 * One-shot pipeline the panel calls each render: filter first, then severity-sort
 * the survivors. Counts/sub-target lists are computed by the panel over the
 * UNFILTERED set (so badges show the true totals) via the helpers above.
 */
export function buildProblemView(
  rows: ProblemRow[],
  filters: ProblemFilters,
): ProblemRow[] {
  return sortRowsBySeverity(filterRows(rows, filters));
}
