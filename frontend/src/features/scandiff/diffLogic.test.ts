/**
 * Unit tests for the F4 scan-over-scan diff logic. NO network, NO React — pure
 * fixtures of runs + findings. Covers: new / fixed / regressed / unchanged
 * classification, severity-regression, first-run, and the timestamp-window
 * run→finding attribution heuristic.
 */
import { describe, it, expect } from "vitest";
import {
  diffFindingSets,
  attributeFindingsToRun,
  issueKey,
  severityRank,
  type DiffRun,
  type DiffFinding,
} from "./diffLogic";

const SUB = "sub-1";

function f(over: Partial<DiffFinding>): DiffFinding {
  return {
    id: over.id ?? "f-" + Math.random().toString(36).slice(2),
    sub_target_id: over.sub_target_id ?? SUB,
    title: over.title ?? "SQL injection",
    tool: over.tool ?? "sqlmap",
    target: over.target ?? "https://app/login",
    severity: over.severity ?? "high",
    status: over.status ?? "open",
    ts: over.ts ?? "2026-07-11T10:30:00Z",
  };
}

function run(over: Partial<DiffRun>): DiffRun {
  return {
    id: over.id ?? "r-1",
    sub_target_id: over.sub_target_id ?? SUB,
    started_at: over.started_at ?? "2026-07-11T10:00:00Z",
    // Preserve an explicit `null` (open-ended run) — only fill the default when
    // the caller omitted the field entirely.
    ended_at: "ended_at" in over ? over.ended_at! : "2026-07-11T11:00:00Z",
  };
}

describe("issueKey", () => {
  it("is stable across differing ids/severity and normalises case/whitespace", () => {
    const a = f({ id: "a", severity: "low", title: "  XSS  ", tool: "ZAP", target: "/q" });
    const b = f({ id: "b", severity: "critical", title: "xss", tool: "zap", target: "/q" });
    expect(issueKey(a)).toBe(issueKey(b));
  });
});

describe("severityRank", () => {
  it("orders info < low < medium < high < critical", () => {
    expect(severityRank("info")).toBeLessThan(severityRank("low"));
    expect(severityRank("low")).toBeLessThan(severityRank("medium"));
    expect(severityRank("medium")).toBeLessThan(severityRank("high"));
    expect(severityRank("high")).toBeLessThan(severityRank("critical"));
  });
});

describe("diffFindingSets — buckets", () => {
  it("classifies new / fixed / unchanged", () => {
    const earlier = [
      f({ title: "Fixed issue", tool: "t1", target: "/a", severity: "medium" }),
      f({ title: "Stable issue", tool: "t2", target: "/b", severity: "high" }),
    ];
    const later = [
      f({ title: "Stable issue", tool: "t2", target: "/b", severity: "high" }),
      f({ title: "Brand new", tool: "t3", target: "/c", severity: "low" }),
    ];
    const d = diffFindingSets(earlier, later);
    expect(d.counts).toEqual({ new: 1, fixed: 1, regressed: 0, unchanged: 1 });
    expect(d.new[0].finding.title).toBe("Brand new");
    expect(d.fixed[0].finding.title).toBe("Fixed issue");
    expect(d.unchanged[0].finding.title).toBe("Stable issue");
    expect(d.isFirstRun).toBe(false);
  });

  it("flags severity worsening as regressed, not unchanged", () => {
    const earlier = [f({ title: "Weak TLS", tool: "tls", target: "/x", severity: "low" })];
    const later = [f({ title: "Weak TLS", tool: "tls", target: "/x", severity: "critical" })];
    const d = diffFindingSets(earlier, later);
    expect(d.counts.regressed).toBe(1);
    expect(d.counts.unchanged).toBe(0);
    const row = d.regressed[0];
    expect(row.earlierSeverity).toBe("low");
    expect(row.laterSeverity).toBe("critical");
  });

  it("severity IMPROVING stays unchanged (not regressed)", () => {
    const earlier = [f({ title: "Weak TLS", tool: "tls", target: "/x", severity: "critical" })];
    const later = [f({ title: "Weak TLS", tool: "tls", target: "/x", severity: "low" })];
    const d = diffFindingSets(earlier, later);
    expect(d.counts.regressed).toBe(0);
    expect(d.counts.unchanged).toBe(1);
  });

  it("regressed row surfaces the LATER finding (for click-through)", () => {
    const earlier = [f({ id: "old", title: "T", tool: "x", target: "/", severity: "low" })];
    const later = [f({ id: "new", title: "T", tool: "x", target: "/", severity: "high" })];
    const d = diffFindingSets(earlier, later);
    expect(d.regressed[0].finding.id).toBe("new");
  });

  it("de-dupes duplicate issue keys within a run to the worst severity", () => {
    const later = [
      f({ id: "d1", title: "Dup", tool: "x", target: "/", severity: "low" }),
      f({ id: "d2", title: "Dup", tool: "x", target: "/", severity: "critical" }),
    ];
    const d = diffFindingSets([], later, true);
    // Empty earlier but earlier run present → all "new", one row, worst severity.
    expect(d.counts.new).toBe(1);
    expect(d.new[0].finding.severity).toBe("critical");
  });
});

describe("diffFindingSets — first run", () => {
  it("treats a lone baseline as all-new with isFirstRun set", () => {
    const later = [
      f({ title: "A", tool: "t", target: "/1", severity: "high" }),
      f({ title: "B", tool: "t", target: "/2", severity: "low" }),
    ];
    const d = diffFindingSets([], later, /* earlierRunPresent */ false);
    expect(d.isFirstRun).toBe(true);
    expect(d.counts).toEqual({ new: 2, fixed: 0, regressed: 0, unchanged: 0 });
    // Worst-first ordering.
    expect(d.new[0].finding.severity).toBe("high");
  });

  it("empty later on a real diff yields all-fixed", () => {
    const earlier = [f({ title: "Gone", tool: "t", target: "/", severity: "medium" })];
    const d = diffFindingSets(earlier, [], true);
    expect(d.counts).toEqual({ new: 0, fixed: 1, regressed: 0, unchanged: 0 });
  });
});

describe("attributeFindingsToRun — timestamp-window heuristic", () => {
  const baseline = run({
    id: "r-base",
    started_at: "2026-07-11T09:00:00Z",
    ended_at: "2026-07-11T09:30:00Z",
  });
  const latest = run({
    id: "r-latest",
    started_at: "2026-07-11T12:00:00Z",
    ended_at: "2026-07-11T12:30:00Z",
  });

  it("keeps only same-sub-target findings inside the window", () => {
    const findings = [
      f({ id: "in", ts: "2026-07-11T09:15:00Z" }),
      f({ id: "before", ts: "2026-07-11T08:00:00Z" }),
      f({ id: "after", ts: "2026-07-11T10:00:00Z" }),
      f({ id: "other-sub", sub_target_id: "sub-2", ts: "2026-07-11T09:15:00Z" }),
    ];
    const got = attributeFindingsToRun(baseline, findings);
    expect(got.map((x) => x.id)).toEqual(["in"]);
  });

  it("attributes each finding to the correct run in a two-run window", () => {
    const findings = [
      f({ id: "b1", ts: "2026-07-11T09:15:00Z" }),
      f({ id: "l1", ts: "2026-07-11T12:15:00Z" }),
    ];
    const b = attributeFindingsToRun(baseline, findings, [latest]);
    const l = attributeFindingsToRun(latest, findings, [baseline]);
    expect(b.map((x) => x.id)).toEqual(["b1"]);
    expect(l.map((x) => x.id)).toEqual(["l1"]);
  });

  it("open-ended (null ended_at) run extends to +infinity but yields to a later run", () => {
    const openBase = run({ id: "r-open", started_at: "2026-07-11T09:00:00Z", ended_at: null });
    const findings = [
      f({ id: "b1", ts: "2026-07-11T09:15:00Z" }),
      f({ id: "l1", ts: "2026-07-11T12:15:00Z" }), // falls in openBase window AND latest window
    ];
    // Without knowledge of the later run, openBase claims both.
    expect(attributeFindingsToRun(openBase, findings).map((x) => x.id)).toEqual(["b1", "l1"]);
    // With the later run passed, l1 is claimed by the more-recent run.
    expect(
      attributeFindingsToRun(openBase, findings, [latest]).map((x) => x.id),
    ).toEqual(["b1"]);
  });

  it("skips findings with unparseable timestamps rather than mis-attributing", () => {
    const findings = [f({ id: "bad", ts: "not-a-date" })];
    expect(attributeFindingsToRun(baseline, findings)).toEqual([]);
  });
});

describe("end-to-end via attribution + diff", () => {
  it("regression across two runs from a shared finding pool", () => {
    const baseline = run({ id: "r1", started_at: "2026-07-11T09:00:00Z", ended_at: "2026-07-11T09:30:00Z" });
    const latest = run({ id: "r2", started_at: "2026-07-11T12:00:00Z", ended_at: "2026-07-11T12:30:00Z" });
    const pool = [
      f({ id: "e-tls", title: "Weak TLS", tool: "tls", target: "/", severity: "low", ts: "2026-07-11T09:10:00Z" }),
      f({ id: "e-gone", title: "Open port", tool: "nmap", target: "/", severity: "medium", ts: "2026-07-11T09:12:00Z" }),
      f({ id: "l-tls", title: "Weak TLS", tool: "tls", target: "/", severity: "high", ts: "2026-07-11T12:10:00Z" }),
      f({ id: "l-new", title: "XSS", tool: "zap", target: "/q", severity: "medium", ts: "2026-07-11T12:12:00Z" }),
    ];
    const eF = attributeFindingsToRun(baseline, pool, [latest]);
    const lF = attributeFindingsToRun(latest, pool, [baseline]);
    const d = diffFindingSets(eF, lF, true);
    expect(d.counts).toEqual({ new: 1, fixed: 1, regressed: 1, unchanged: 0 });
    expect(d.new[0].finding.title).toBe("XSS");
    expect(d.fixed[0].finding.title).toBe("Open port");
    expect(d.regressed[0].finding.title).toBe("Weak TLS");
  });
});
