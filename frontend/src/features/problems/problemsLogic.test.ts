/**
 * Pure unit coverage for problemsLogic — no network, no React, no bus. Fixture
 * findings only. Asserts:
 *   - severity sort order (critical→high→medium→low→info), stable within a band
 *   - filter behavior across every axis (severity / fix-state / confidence /
 *     sub-target), independently and combined
 *   - per-severity count tallies
 *   - the confLevel mapping NEVER yields "confirmed" for a non-confirmed status
 */
import { describe, it, expect } from "vitest";
import type { PairingFinding } from "../../shell/model";
import {
  sortRowsBySeverity,
  filterRows,
  countBySeverity,
  subTargetIds,
  normalizeFixState,
  deriveConfLevel,
  buildProblemView,
  type ProblemRow,
  type FixState,
} from "./problemsLogic";

// ── Fixtures ─────────────────────────────────────────────────────────────────

let seq = 0;
function finding(over: Partial<PairingFinding>): PairingFinding {
  const id = over.id ?? `f${seq++}`;
  return {
    id,
    engagement_id: "eng-1",
    ts: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    title: `Finding ${id}`,
    severity: "medium",
    cvss: null,
    cvss_vector: null,
    tool: "nmap",
    target: "https://example.test/",
    description: "",
    evidence: "",
    ai_summary: "",
    linked_result_id: null,
    status: "open",
    sub_target_id: "sub-a",
    target_id: "tgt-1",
    ...over,
  };
}

function row(
  over: Partial<PairingFinding>,
  fixState: FixState = "open",
): ProblemRow {
  const f = finding(over);
  return { finding: f, fixState, conf: deriveConfLevel(f.status) };
}

// ── Severity sort ────────────────────────────────────────────────────────────

describe("sortRowsBySeverity", () => {
  it("orders critical → high → medium → low → info", () => {
    const rows = [
      row({ id: "lo", severity: "low" }),
      row({ id: "cr", severity: "critical" }),
      row({ id: "in", severity: "info" }),
      row({ id: "hi", severity: "high" }),
      row({ id: "me", severity: "medium" }),
    ];
    expect(sortRowsBySeverity(rows).map((r) => r.finding.id)).toEqual([
      "cr", "hi", "me", "lo", "in",
    ]);
  });

  it("is stable within a severity band (keeps incoming order)", () => {
    const rows = [
      row({ id: "h1", severity: "high" }),
      row({ id: "h2", severity: "high" }),
      row({ id: "h3", severity: "high" }),
    ];
    expect(sortRowsBySeverity(rows).map((r) => r.finding.id)).toEqual([
      "h1", "h2", "h3",
    ]);
  });

  it("does not mutate the input array", () => {
    const rows = [row({ id: "a", severity: "low" }), row({ id: "b", severity: "critical" })];
    const before = rows.map((r) => r.finding.id);
    sortRowsBySeverity(rows);
    expect(rows.map((r) => r.finding.id)).toEqual(before);
  });
});

// ── Filters ──────────────────────────────────────────────────────────────────

describe("filterRows", () => {
  const rows = [
    row({ id: "a", severity: "critical", sub_target_id: "sub-a", status: "confirmed" }, "open"),
    row({ id: "b", severity: "high", sub_target_id: "sub-b", status: "open" }, "fixed"),
    row({ id: "c", severity: "low", sub_target_id: "sub-a", status: "open" }, "verified"),
  ];

  it("with no constraints returns everything", () => {
    expect(filterRows(rows, {}).map((r) => r.finding.id)).toEqual(["a", "b", "c"]);
    expect(
      filterRows(rows, { severity: [], fixState: [], confidence: [], subTargetId: null }),
    ).toHaveLength(3);
  });

  it("filters by severity (multi)", () => {
    expect(filterRows(rows, { severity: ["critical", "low"] }).map((r) => r.finding.id))
      .toEqual(["a", "c"]);
  });

  it("filters by fix-state", () => {
    expect(filterRows(rows, { fixState: ["fixed", "verified"] }).map((r) => r.finding.id))
      .toEqual(["b", "c"]);
  });

  it("filters by confidence", () => {
    expect(filterRows(rows, { confidence: ["confirmed"] }).map((r) => r.finding.id))
      .toEqual(["a"]);
    expect(filterRows(rows, { confidence: ["suspected"] }).map((r) => r.finding.id))
      .toEqual(["b", "c"]);
  });

  it("filters by sub-target", () => {
    expect(filterRows(rows, { subTargetId: "sub-a" }).map((r) => r.finding.id))
      .toEqual(["a", "c"]);
  });

  it("ANDs across axes", () => {
    expect(
      filterRows(rows, { subTargetId: "sub-a", severity: ["low"] }).map((r) => r.finding.id),
    ).toEqual(["c"]);
  });
});

// ── Counts ───────────────────────────────────────────────────────────────────

describe("countBySeverity", () => {
  it("tallies every severity, zero-filling absent bands", () => {
    const rows = [
      row({ severity: "critical" }),
      row({ severity: "high" }),
      row({ severity: "high" }),
      row({ severity: "high" }),
      row({ severity: "medium" }),
      row({ severity: "medium" }),
    ];
    expect(countBySeverity(rows)).toEqual({
      critical: 1, high: 3, medium: 2, low: 0, info: 0,
    });
  });

  it("on an empty list returns all-zero", () => {
    expect(countBySeverity([])).toEqual({
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    });
  });
});

// ── Sub-target derivation ────────────────────────────────────────────────────

describe("subTargetIds", () => {
  it("returns distinct sub-target ids in first-seen order", () => {
    const rows = [
      row({ sub_target_id: "sub-b" }),
      row({ sub_target_id: "sub-a" }),
      row({ sub_target_id: "sub-b" }),
      row({ sub_target_id: "sub-c" }),
    ];
    expect(subTargetIds(rows)).toEqual(["sub-b", "sub-a", "sub-c"]);
  });
});

// ── Fix-state normalisation ──────────────────────────────────────────────────

describe("normalizeFixState", () => {
  it("passes through fixed / verified", () => {
    expect(normalizeFixState("fixed")).toBe("fixed");
    expect(normalizeFixState("verified")).toBe("verified");
  });

  it("defaults everything else (missing / legacy / null) to open", () => {
    expect(normalizeFixState(null)).toBe("open");
    expect(normalizeFixState(undefined)).toBe("open");
    expect(normalizeFixState("open")).toBe("open");
    expect(normalizeFixState("in_progress")).toBe("open");
    expect(normalizeFixState("")).toBe("open");
  });
});

// ── Confidence invariant (SECURITY) ──────────────────────────────────────────

describe("deriveConfLevel never upgrades to confirmed", () => {
  it("maps ONLY an exact 'confirmed' status to confirmed", () => {
    expect(deriveConfLevel("confirmed")).toBe("confirmed");
  });

  it("maps every non-confirmed status to suspected", () => {
    const nonConfirmed = [
      "open", "false_positive", "remediated", "triaged", "fixed",
      "wont_fix", "CONFIRMED", "confirmed ", " confirmed", "verified",
      "", "unknown",
    ];
    for (const s of nonConfirmed) {
      expect(deriveConfLevel(s)).toBe("suspected");
    }
  });
});

// ── End-to-end pipeline ──────────────────────────────────────────────────────

describe("buildProblemView", () => {
  it("filters then severity-sorts the survivors", () => {
    const rows = [
      row({ id: "a", severity: "low", sub_target_id: "sub-a" }),
      row({ id: "b", severity: "critical", sub_target_id: "sub-b" }),
      row({ id: "c", severity: "high", sub_target_id: "sub-a" }),
      row({ id: "d", severity: "medium", sub_target_id: "sub-a" }),
    ];
    // only sub-a rows, then severity-sorted: high(c) → medium(d) → low(a)
    expect(
      buildProblemView(rows, { subTargetId: "sub-a" }).map((r) => r.finding.id),
    ).toEqual(["c", "d", "a"]);
  });
});
