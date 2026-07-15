/**
 * PHASE-2 · T1 (cross-link integrity, both directions) + T3 (single source of
 * truth), executed against the REAL bus + registries + feature modules, with
 * ONLY the model API mocked (so panels get deterministic data instead of hitting
 * the backend). Nothing is stubbed at the feature boundary — the cross-links run
 * entirely through the bus.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";

// Deterministic model surface (all runtime exports of shell/model).
const m = vi.hoisted(() => ({
  listFindings: vi.fn(),
  getFinding: vi.fn(),
  getEvidenceChain: vi.fn(),
  resolveAnchor: vi.fn(),
  getCoverage: vi.fn(),
  listRuns: vi.fn(),
  getRun: vi.fn(),
  listAssets: vi.fn(),
  listAudit: vi.fn(),
  getEngagement: vi.fn(),
  confLevel: vi.fn((f: any) => (f?.status === "confirmed" ? "confirmed" : "suspected")),
  toFindingRef: vi.fn((f: any) => ({ findingId: f.id, subTargetId: f.sub_target_id, targetId: f.target_id })),
  toAssetRef: vi.fn((a: any) => ({ subTargetId: a.subTargetId, assetId: a.assetId, kind: a.kind })),
}));
vi.mock("../shell/model", () => m);

// Feature modules self-register on import (pivot router + panels).
import "../features/pivot/Pivot";
import "../features/debugger/EvidenceDebuggerPanel";
import "../features/problems/ProblemsPanel";

import { getView } from "../shell/views";
import { emit, on } from "../shell/bus";
import { setActiveEngagementId } from "../lib/engagement";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const FINDING: any = {
  id: "f-1", engagement_id: "e-1", title: "SQL injection in login",
  severity: "high", status: "suspected", cvss: null, cvss_vector: null,
  tool: "sqli", target: "https://app.test/login", description: "reflected via user param",
  evidence: "", ai_summary: "", linked_result_id: null,
  sub_target_id: "st-1", target_id: "t-1", ts: "2026-07-11T10:00:00Z", updated_at: "2026-07-11T10:00:00Z",
};
const CHAIN_STEPS = [
  { id: "s-1", finding_id: "f-1", ordinal: 0, action: { tool_id: "http" }, evidence: { raw_output: "GET /login marker-alpha" }, interpretation: null, links_from: null, anchored: false, role: "fact", hasInterpretation: false, prev_hash: "", row_hash: "" },
  { id: "s-2", finding_id: "f-1", ordinal: 1, action: { tool_id: "sqli", params: { file: "app/auth.py", line: 42 } }, evidence: { raw_output: "' OR 1=1 --" }, interpretation: "auth bypassed", links_from: "s-1", anchored: true, role: "fact", hasInterpretation: true, prev_hash: "", row_hash: "" },
];
const CHAIN = { findingId: "f-1", method: { finding_id: "f-1", state: "open", root_cause: { anchor: "s-2" }, remediation: null, steps: CHAIN_STEPS }, steps: CHAIN_STEPS, gaps: [] };
const FILE_ANCHOR = { kind: "file", file: "app/auth.py", line: 42 };

async function flush() {
  // Let queued microtasks (async model reads) settle inside act().
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
}
function mount(view: string): { container: HTMLElement; root: Root } {
  const Comp = getView(view)!.component!;
  const container = document.createElement("div");
  document.body.appendChild(container);
  let root!: Root;
  act(() => { root = createRoot(container); root.render(React.createElement(Comp, { params: {} })); });
  return { container, root };
}

beforeEach(() => {
  Object.values(m).forEach((fn) => (fn as Mock).mockReset?.());
  m.confLevel.mockImplementation((f: any) => (f?.status === "confirmed" ? "confirmed" : "suspected"));
  m.toFindingRef.mockImplementation((f: any) => ({ findingId: f.id, subTargetId: f.sub_target_id, targetId: f.target_id }));
  m.listFindings.mockResolvedValue([FINDING]);
  m.getFinding.mockResolvedValue(FINDING);
  m.getEvidenceChain.mockResolvedValue(CHAIN);
  m.resolveAnchor.mockResolvedValue(FILE_ANCHOR);
  m.getCoverage.mockResolvedValue({ engagement_id: "e-1", areas: [], covered_count: 0, total: 0 });
  m.listRuns.mockResolvedValue([]);
  m.listAssets.mockResolvedValue([]);
  m.listAudit.mockResolvedValue([]);
  m.getEngagement.mockResolvedValue({ id: "e-1", name: "Test", scope: [], exclusions: [], notes: "", status: "active", type: "web-app", provenance: "lab", source_root: "", primary_target: "", created_at: "", updated_at: "" });
});

describe("Phase-2 T1 — cross-link integrity (both directions, bus-only)", () => {
  it("forward: selectFinding → pivot resolves anchor → re-publishes selectAnchor", async () => {
    const anchors: any[] = [];
    const off = on("selectAnchor", (p) => anchors.push(p));
    await act(async () => {
      emit("selectFinding", { ref: { findingId: "f-1", subTargetId: "st-1", targetId: "t-1" }, source: "search" });
    });
    await flush();
    off();
    expect(m.resolveAnchor).toHaveBeenCalled();
    expect(anchors).toHaveLength(1);
    expect(anchors[0].source).toBe("pivot");
    expect(anchors[0].findingId).toBe("f-1");
    expect(anchors[0].ref).toMatchObject({ kind: "file", file: "app/auth.py", line: 42 });
  });

  it("forward: debugger loads the chain when a finding is selected (via bus)", async () => {
    const { container, root } = mount("debugger");
    expect(container.textContent).not.toContain("marker-alpha");
    await act(async () => {
      emit("selectFinding", { ref: { findingId: "f-1", subTargetId: "st-1", targetId: "t-1" }, source: "problems" });
    });
    await flush();
    expect(m.getEvidenceChain).toHaveBeenCalledWith("f-1");
    // The debugger rendered the loaded chain's first step (reacted via bus).
    expect(container.textContent).toContain("marker-alpha");
    act(() => root.unmount());
    container.remove();
  });

  it("reverse: selectStep (from debugger) → pivot re-publishes selectAnchor for that step", async () => {
    const anchors: any[] = [];
    const off = on("selectAnchor", (p) => anchors.push(p));
    await act(async () => {
      emit("selectStep", { ref: { findingId: "f-1", stepId: "s-2" }, source: "debugger" });
    });
    await flush();
    off();
    // Step s-2 carries action.params.file → pivot anchors to it.
    expect(anchors.length).toBeGreaterThanOrEqual(1);
    expect(anchors[anchors.length - 1].ref).toMatchObject({ kind: "file", file: "app/auth.py" });
  });

  it("loop guard: pivot ignores its own echo (no selectAnchor from a pivot-sourced event)", async () => {
    const anchors: any[] = [];
    const off = on("selectAnchor", (p) => anchors.push(p));
    await act(async () => {
      emit("selectFinding", { ref: { findingId: "f-1", subTargetId: "st-1", targetId: "t-1" }, source: "pivot" });
    });
    await flush();
    off();
    expect(anchors).toHaveLength(0);
  });
});

describe("Phase-2 T1 — graph node click → bus → code view (pivot inspector) reacts", () => {
  it("a graph-sourced selectAnchor makes the pivot inspector show the location", async () => {
    const { container, root } = mount("pivot");
    await flush();
    await act(async () => {
      emit("selectAnchor", { ref: { kind: "file", file: "app/db.py", line: 12 }, source: "graph" });
    });
    await flush();
    // The pivot inspector (subscriber) rendered the anchor the graph published —
    // proving graph node click → selectAnchor → code view reacts, via the bus.
    expect(container.textContent).toContain("app/db.py");
    act(() => root.unmount());
    container.remove();
  });
});

describe("Phase-2 T3 — single source of truth (re-read on modelChanged, no private cache)", () => {
  it("Problems re-reads the model on modelChanged and reflects the mutation", async () => {
    setActiveEngagementId("e-1");
    const { container, root } = mount("problems");
    await flush();
    expect(container.textContent).toContain("SQL injection in login");
    const callsAfterMount = m.listFindings.mock.calls.length;
    expect(callsAfterMount).toBeGreaterThan(0);

    // Mutate the model behind the API: same finding now critical + confirmed.
    m.listFindings.mockResolvedValue([{ ...FINDING, severity: "critical", status: "confirmed", title: "SQL injection in login (escalated)" }]);
    await act(async () => { emit("modelChanged", { entity: "finding", id: "f-1", op: "update" }); });
    await flush();

    // The view re-read (no cached copy) and now shows the mutated record.
    expect(m.listFindings.mock.calls.length).toBeGreaterThan(callsAfterMount);
    expect(container.textContent).toContain("escalated");
    act(() => root.unmount());
    container.remove();
    setActiveEngagementId(null);
  });
});
