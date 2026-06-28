// Pure presentation helpers for the engagement coverage matrix
// (components/CoverageMatrix.tsx). The backend owns *what's* covered
// (backend/lib/coverage.py); these turn a CoverageArea into the bits the
// grid renders — roll-up percentage, headline, per-area status line, and
// the tone token that colors each cell. Kept here so they're unit-testable
// without rendering the component.

import type { CoverageArea, EngagementCoverage } from "./engagement";

export function coveragePercent(cov: Pick<EngagementCoverage, "covered_count" | "total">): number {
  if (cov.total <= 0) return 0;
  return Math.round((cov.covered_count / cov.total) * 100);
}

export function coverageHeadline(
  cov: Pick<EngagementCoverage, "covered_count" | "total">,
): string {
  return `${cov.covered_count} / ${cov.total} areas covered`;
}

// One-line status for an area cell. Findings and report read as plain
// "done/not done"; the recon areas surface the run count since re-running
// them is normal and the count signals how much attention an area got.
export function areaStatusLine(area: CoverageArea): string {
  if (!area.covered) return "Not yet checked";
  if (area.key === "report") return "Report exported";
  if (area.key === "findings") {
    return area.runs === 1 ? "1 finding" : `${area.runs} findings`;
  }
  const runs = area.runs === 1 ? "1 run" : `${area.runs} runs`;
  return area.last_tool ? `${runs} · ${area.last_tool}` : runs;
}

// Tone token for the cell — green when covered, muted when not. Returned as
// a small object so the component can spread it onto dot/border/text without
// re-deriving the covered branch three times.
export type CoverageTone = {
  dot: string;
  border: string;
  text: string;
};

export function areaTone(area: CoverageArea): CoverageTone {
  return area.covered
    ? { dot: "bg-success", border: "border-success/40", text: "text-success" }
    : { dot: "bg-ink-dim", border: "border-divider", text: "text-ink-dim" };
}
