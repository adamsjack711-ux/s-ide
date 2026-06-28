import { useCallback, useEffect, useMemo, useState } from "react";
import CoveragePanel from "./CoveragePanel";
import FindingsPanel from "./FindingsPanel";
import FindingDetail from "./findings/FindingDetail";
import {
  listFindings,
  useActiveEngagementId,
  type Finding,
  type FindingSeverity,
} from "../lib/engagement";
import { emit, useBus } from "../shell/bus";

const SEV_RANK: Record<FindingSeverity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

/**
 * Findings activity view — a faceted "Triage Queue" (source/status facets +
 * severity chips + finding rows) beside an investigation detail pane for the
 * selected finding (outline tabs: Description / Data Flow / Vulnerable Code /
 * Remediation / History). Coverage matrix sits on top, unchanged.
 */
export default function FindingsView() {
  const eid = useActiveEngagementId();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<FindingSeverity | "all">("all");

  const refresh = useCallback(() => {
    if (!eid) { setFindings([]); return; }
    listFindings(eid).then(setFindings).catch(() => setFindings([]));
  }, [eid]);

  useEffect(refresh, [refresh]);
  useBus("findingsChanged", refresh);

  // Severity-sorted, then newest first within a band.
  const sorted = useMemo(
    () =>
      [...findings].sort(
        (a, b) =>
          SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
          (b.ts ?? "").localeCompare(a.ts ?? ""),
      ),
    [findings],
  );

  // Keep selection valid as the list changes; default to the first row.
  useEffect(() => {
    if (sorted.length === 0) { setSelectedId(null); return; }
    if (!selectedId || !sorted.some((f) => f.id === selectedId)) {
      setSelectedId(sorted[0].id);
    }
  }, [sorted, selectedId]);

  const selected = sorted.find((f) => f.id === selectedId) ?? null;

  const select = useCallback((f: Finding) => {
    setSelectedId(f.id);
    emit("focusFinding", { findingId: f.id }); // keep copilot reconstruction wiring
  }, []);

  if (!eid) {
    return (
      <div className="flex h-full items-center justify-center bg-bg-base p-6 text-sm text-ink-dim">
        Select an engagement to see findings.
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-bg-base">
      <CoveragePanel />
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <div className="min-h-0 min-w-0 border-r border-divider">
          <FindingsPanel
            findings={sorted}
            selectedId={selectedId}
            onSelect={select}
            sevFilter={sevFilter}
            onSevFilter={setSevFilter}
          />
        </div>
        <div className="hidden min-h-0 min-w-0 lg:block">
          {selected ? (
            <FindingDetail finding={selected} onChanged={refresh} />
          ) : (
            <div className="flex h-full items-center justify-center p-6 text-sm text-ink-dim">
              Select a finding to investigate.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
