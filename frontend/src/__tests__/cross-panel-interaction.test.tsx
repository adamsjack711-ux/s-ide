/**
 * Cross-panel interaction tests — the bugs the review found live BETWEEN panels,
 * where unit tests don't reach. Complements phase2-seams (selectFinding/Step/
 * Anchor + modelChanged) with the reactors it didn't cover and, crucially, the
 * stale-async RACE guards that PR#19 added to FixDiff and that Pivot/debugger
 * already carry — proven here so a regression fails CI.
 *
 * Everything runs against the REAL bus + registries + feature modules; only the
 * model API is mocked (deterministic data, controllable async timing).
 */
import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";

const m = vi.hoisted(() => ({
  listFindings: vi.fn(),
  getFinding: vi.fn(),
  getEvidenceChain: vi.fn(),
  resolveAnchor: vi.fn(),
  getCoverage: vi.fn(),
  listRuns: vi.fn(),
  listAssets: vi.fn(),
  listSubTargets: vi.fn(),
  listAudit: vi.fn(),
  getEngagement: vi.fn(),
  readLabFile: vi.fn(),
  scanSource: vi.fn(),
  confLevel: vi.fn((f: any) => (f?.status === "confirmed" ? "confirmed" : "suspected")),
  toFindingRef: vi.fn((f: any) => ({ findingId: f.id, subTargetId: f.sub_target_id, targetId: f.target_id })),
  toAssetRef: vi.fn((a: any) => ({ subTargetId: a.subTargetId, assetId: a.assetId, kind: a.kind })),
}));
vi.mock("../shell/model", () => m);

import "../features/pivot/Pivot";
import "../features/debugger/EvidenceDebuggerPanel";
import "../features/suggestions/Suggestions";
import "../features/fixdiff/FixDiffPanel";
import "../features/search/SearchPanel";

import { getView } from "../shell/views";
import { emit } from "../shell/bus";
import { setActiveEngagementId } from "../lib/engagement";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

function chain(findingId: string, marker: string) {
  const steps = [{
    id: `${findingId}-s1`, finding_id: findingId, ordinal: 0,
    action: { tool_id: "http", params: { file: `${findingId}.py`, line: 7 } },
    evidence: { raw_output: marker }, interpretation: "note", links_from: null,
    anchored: true, role: "fact", hasInterpretation: true, prev_hash: "", row_hash: "",
  }];
  return { findingId, method: { finding_id: findingId, state: "open", root_cause: { anchor: steps[0].id }, remediation: null, steps }, steps, gaps: [] };
}
const finding = (id: string) => ({
  id, engagement_id: "e-1", title: `Finding ${id}`, severity: "high", status: "suspected",
  tool: "t", target: "https://app.test/x", description: "", evidence: "", ai_summary: "",
  sub_target_id: "st-1", target_id: "t-1", ts: "", updated_at: "",
});
function ref(id: string) { return { findingId: id, subTargetId: "st-1", targetId: "t-1" }; }

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}
async function flush() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
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
  m.listFindings.mockResolvedValue([]);
  m.getFinding.mockImplementation((r: any) => Promise.resolve(finding(typeof r === "string" ? r : r.findingId)));
  m.getEvidenceChain.mockResolvedValue(chain("f-x", "marker-x"));
  m.resolveAnchor.mockResolvedValue({ kind: "file", file: "x.py", line: 1 });
  m.getCoverage.mockResolvedValue({ engagement_id: "e-1", areas: [], covered_count: 0, total: 0 });
  m.listRuns.mockResolvedValue([]);
  m.listAssets.mockResolvedValue([]);
  m.listSubTargets.mockResolvedValue([]);
  m.listAudit.mockResolvedValue([]);
  m.readLabFile.mockResolvedValue(null);
  m.scanSource.mockResolvedValue(null);
  m.getEngagement.mockResolvedValue({ id: "e-1", name: "T", scope: [], exclusions: [], notes: "", status: "active", type: "web-app", provenance: "lab", source_root: "", primary_target: "", created_at: "", updated_at: "" });
});

describe("reactor: selectSubTarget → Suggestions re-scopes", () => {
  it("re-fetches assets for the newly focused sub-target", async () => {
    setActiveEngagementId("e-1");
    const { container, root } = mount("suggestions");
    await flush();
    m.listAssets.mockClear();

    await act(async () => {
      emit("selectSubTarget", { ref: { subTargetId: "st-9", targetId: "t-1" }, source: "targets" });
    });
    await flush();

    // The panel re-scoped: it fetched assets for st-9 (the newly focused sub-target).
    expect(m.listAssets).toHaveBeenCalledWith({ subTargetId: "st-9" });
    act(() => root.unmount());
    container.remove();
    setActiveEngagementId(null);
  });
});

describe("reactor: selectFinding → FixDiff loads the finding", () => {
  it("reads the finding's chain when a finding is broadcast", async () => {
    const { container, root } = mount("fixdiff");
    await flush();
    await act(async () => { emit("selectFinding", { ref: ref("f-7"), source: "problems" }); });
    await flush();
    // FixDiff reacted via the bus and pulled the finding's data.
    expect(m.getEvidenceChain).toHaveBeenCalledWith("f-7");
    act(() => root.unmount());
    container.remove();
  });
});

describe("efficiency: SearchPanel code scan is engagement-scoped, not per-mutation", () => {
  it("runs the code scan once per engagement, not on every modelChanged", async () => {
    setActiveEngagementId("e-1");
    m.getEngagement.mockResolvedValue({ id: "e-1", name: "T", scope: [], exclusions: [], notes: "", status: "active", type: "web-app", provenance: "lab", source_root: "/src", primary_target: "", created_at: "", updated_at: "" });
    m.scanSource.mockResolvedValue([]);

    const { container, root } = mount("search");
    await flush();
    // The 4000-file scan ran once for the engagement.
    expect(m.scanSource).toHaveBeenCalledTimes(1);
    const findingsCalls = m.listFindings.mock.calls.length;

    // A finding mutation re-reads the mutable corpus…
    await act(async () => { emit("modelChanged", { entity: "finding", id: "f-1", op: "update" }); });
    await flush();
    expect(m.listFindings.mock.calls.length).toBeGreaterThan(findingsCalls);
    // …but must NOT re-run the code scan (source files didn't change).
    expect(m.scanSource).toHaveBeenCalledTimes(1);

    act(() => root.unmount());
    container.remove();
    setActiveEngagementId(null);
  });
});

describe("stale-async race: a slower earlier load must not clobber a newer selection", () => {
  it("debugger: rapid A→B with out-of-order resolution renders B, not A", async () => {
    const dA = deferred<any>();
    const dB = deferred<any>();
    m.getEvidenceChain.mockImplementation((id: string) =>
      id === "f-A" ? dA.promise : id === "f-B" ? dB.promise : Promise.resolve(chain(id, "other")));

    const { container, root } = mount("debugger");
    await flush();

    // Select A then B in quick succession (both loads now in flight).
    await act(async () => { emit("selectFinding", { ref: ref("f-A"), source: "problems" }); });
    await act(async () => { emit("selectFinding", { ref: ref("f-B"), source: "problems" }); });

    // B's load resolves first and renders.
    await act(async () => { dB.resolve(chain("f-B", "chain-BRAVO")); await Promise.resolve(); });
    await flush();
    expect(container.textContent).toContain("chain-BRAVO");

    // A's (superseded) load resolves LAST — the guard must drop it.
    await act(async () => { dA.resolve(chain("f-A", "chain-ALPHA")); await Promise.resolve(); });
    await flush();
    expect(container.textContent).toContain("chain-BRAVO");
    expect(container.textContent).not.toContain("chain-ALPHA");

    act(() => root.unmount());
    container.remove();
  });

  it("pivot inspector: rapid A→B with out-of-order finding load renders B, not A", async () => {
    // The pivot INSPECTOR loads the finding for an incoming selectAnchor (its
    // seq-guarded path). The router relays selectFinding→selectAnchor; here we
    // drive the inspector's selectAnchor path directly (the router doesn't
    // listen to selectAnchor), isolating the panel's guard.
    const dA = deferred<any>();
    const dB = deferred<any>();
    m.getFinding.mockImplementation((r: any) => {
      const id = typeof r === "string" ? r : r.findingId;
      return id === "f-A" ? dA.promise : id === "f-B" ? dB.promise : Promise.resolve(finding(id));
    });

    const { container, root } = mount("pivot");
    await flush();

    await act(async () => { emit("selectAnchor", { ref: { kind: "file", file: "alpha.py", line: 3 }, findingId: "f-A", source: "graph" }); });
    await act(async () => { emit("selectAnchor", { ref: { kind: "file", file: "bravo.py", line: 2 }, findingId: "f-B", source: "graph" }); });

    // B's finding load resolves first and renders.
    await act(async () => { dB.resolve(finding("f-B")); await Promise.resolve(); });
    await flush();
    expect(container.textContent).toContain("bravo.py");

    // A's superseded finding load resolves LAST — the guard must drop it.
    await act(async () => { dA.resolve(finding("f-A")); await Promise.resolve(); });
    await flush();
    expect(container.textContent).toContain("bravo.py");
    expect(container.textContent).not.toContain("alpha.py");

    act(() => root.unmount());
    container.remove();
  });
});
