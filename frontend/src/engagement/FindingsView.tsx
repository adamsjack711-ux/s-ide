import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import CoveragePanel from "./CoveragePanel";
import SelfAssessPanel from "./SelfAssessPanel";
import FindingsPanel from "./FindingsPanel";
import FindingDetail from "./findings/FindingDetail";
import {
  listFindings,
  useActiveEngagementId,
  type Finding,
  type FindingSeverity,
} from "../lib/engagement";
import { emit, useBus } from "../shell/bus";
import { registerCommand } from "../shell/commands";
import { bindingFor } from "../shell/keymap";
import { notify, dismiss } from "../shell/toast";
import { resolveFindingLabId, retestFinding } from "../lib/retest";
import { RETEST_COMING_SOON, COMING_SOON_TOOLTIP } from "../lib/comingSoon";

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

  // Keep a live ref to the selected finding so the contextual ⌘K commands
  // (registered once) always act on the current selection.
  const selectedRef = useRef<Finding | null>(null);
  selectedRef.current = selected;

  // Honor focusFinding from elsewhere (e.g. the promote-success "View finding"
  // toast action) by adopting it as the selection.
  const onFocusFinding = useCallback(
    ({ findingId }: { findingId: string }) => setSelectedId(findingId),
    [],
  );
  useBus("focusFinding", onFocusFinding);

  // Arrow-key navigation over the visible list. Up/Down move the selection;
  // ignored while a text field / select has focus so typing isn't hijacked.
  const onListKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      const visible = sevFilter === "all" ? sorted : sorted.filter((f) => f.severity === sevFilter);
      if (visible.length === 0) return;
      e.preventDefault();
      const idx = visible.findIndex((f) => f.id === selectedId);
      const next =
        e.key === "ArrowDown"
          ? visible[Math.min(idx + 1, visible.length - 1)]
          : visible[Math.max(idx - 1, 0)];
      if (next) select(next);
    },
    [sorted, sevFilter, selectedId, select],
  );

  // Retest the selected finding: resolve its lab, replay the recorded steps,
  // surface the outcome. Shared by the detail button + the ⌘K command.
  const retestSelected = useCallback(async () => {
    // Retest replay is scaffolded but not wired yet (the backend endpoint
    // returns 501/NOT_IMPLEMENTED). Surface an honest notice instead of
    // firing a request that can't verify anything.
    if (RETEST_COMING_SOON) {
      notify({ kind: "info", message: COMING_SOON_TOOLTIP + ": retest replay." });
      return;
    }
    const f = selectedRef.current;
    if (!f) {
      notify({ kind: "info", message: "Select a finding to retest." });
      return;
    }
    const labId = await resolveFindingLabId(f);
    if (!labId) {
      notify({ kind: "error", message: "This finding has no associated lab to retest." });
      return;
    }
    const id = notify({ kind: "info", message: `Retesting ${f.title}…`, duration: 0 });
    try {
      const res = await retestFinding(labId, f.id);
      if (res.verified) {
        notify({ kind: "success", message: "Fix verified — the exploit no longer reproduces." });
      } else {
        notify({
          kind: "info",
          message: `Retest replayed ${res.steps.length} step${res.steps.length === 1 ? "" : "s"} — still ${res.state}.`,
        });
      }
      refresh();
    } catch (e: any) {
      notify({ kind: "error", message: e?.message || "retest failed" });
    } finally {
      dismiss(id); // clear the in-progress toast
    }
  }, [refresh]);

  // Register the contextual commands once (bindings come from the foundation
  // keymap: ⌘⇧F promote-to-finding, ⌘⇧R retest).
  useEffect(() => {
    const offPromote = registerCommand({
      id: "promote-to-finding",
      title: "Promote result to finding",
      keywords: ["finding", "promote", "log", "report"],
      binding: bindingFor("promote-to-finding"),
      // ToolPanel owns the focused result + the `promote` payload; re-broadcast
      // so the active tool surface can open its promote modal.
      run: () => emit("command:run", { commandId: "promote-to-finding" }),
    });
    const offRetest = registerCommand({
      id: "retest",
      title: "Retest finding",
      keywords: ["retest", "verify", "replay", "finding", "fix"],
      binding: bindingFor("retest"),
      run: () => void retestSelected(),
    });
    return () => {
      offPromote();
      offRetest();
    };
  }, [retestSelected]);

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
      <SelfAssessPanel />
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <div className="min-h-0 min-w-0 border-r border-divider">
          <FindingsPanel
            findings={sorted}
            selectedId={selectedId}
            onSelect={select}
            sevFilter={sevFilter}
            onSevFilter={setSevFilter}
            onKeyNav={onListKeyDown}
          />
        </div>
        <div className="hidden min-h-0 min-w-0 lg:block">
          {selected ? (
            <FindingDetail finding={selected} onChanged={refresh} onRetest={retestSelected} />
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
