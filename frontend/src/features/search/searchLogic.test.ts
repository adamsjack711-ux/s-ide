/**
 * Pure unit coverage for F1 search logic. NO network — every input is a fixture
 * array shaped like the model API's return values. Asserts:
 *   - grouping: each of the five groups is produced from its own input,
 *   - ranking: substring hits outrank subsequence hits; word-boundary bonus,
 *   - selection descriptors map to the right canonical event,
 *   - secret redaction masks Authorization / cookies / tokens / api keys,
 *   - empty/blank query yields no groups, no-match yields no rows.
 */
import { describe, it, expect } from "vitest";
import {
  groupSearch, fuzzyScore, bestFieldScore, redactSecrets, countRows,
  type SearchInputs,
} from "./searchLogic";
import type { PairingFinding, PairingRun, Asset, Step } from "../../shell/model";

// ── Fixtures ──────────────────────────────────────────────────────────────────

function finding(over: Partial<PairingFinding>): PairingFinding {
  return {
    id: "f1",
    engagement_id: "e1",
    ts: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    title: "SQL injection in login",
    severity: "high",
    cvss: null,
    cvss_vector: null,
    tool: "sqlmap",
    target: "https://app.test/login",
    description: "Tainted SQL via string concatenation",
    evidence: "",
    ai_summary: "",
    linked_result_id: null,
    status: "open",
    sub_target_id: "st1",
    target_id: "t1",
    ...over,
  };
}

function asset(over: Partial<Asset>): Asset {
  return {
    subTargetId: "st1",
    assetId: "service:8080",
    kind: "service",
    key: "8080",
    props: { banner: "nginx 1.25" },
    tool: "nmap",
    ...over,
  };
}

function step(over: Partial<Step>): Step {
  return {
    id: "s1",
    finding_id: "f1",
    ordinal: 1,
    action: { tool_id: "curl", params: {} },
    evidence: { raw_output: "HTTP/1.1 200 OK", hash: "", timestamp: "" },
    interpretation: "server reflects the payload",
    links_from: null,
    anchored: false,
    prev_hash: "",
    row_hash: "",
    role: "fact",
    hasInterpretation: true,
    ...over,
  } as Step;
}

function run(over: Partial<PairingRun>): PairingRun {
  return {
    id: "r1",
    sub_target_id: "st1",
    engagement_id: "e1",
    target_id: "t1",
    tool: "nikto",
    status: "completed",
    started_at: "2026-01-01T00:00:00Z",
    ended_at: "2026-01-01T00:01:00Z",
    output: "Found admin panel at src/admin.py:42",
    summary: "nikto found an exposed admin panel",
    ...over,
  };
}

// ── fuzzyScore / ranking ────────────────────────────────────────────────────

describe("fuzzyScore", () => {
  it("returns 0 for blank query or empty text", () => {
    expect(fuzzyScore("", "anything")).toBe(0);
    expect(fuzzyScore("x", "")).toBe(0);
  });

  it("scores an exact substring above a subsequence match", () => {
    const sub = fuzzyScore("sql", "sql injection"); // substring
    const seq = fuzzyScore("sqi", "sql injection"); // subsequence s-q-i
    expect(sub).toBeGreaterThan(0);
    expect(seq).toBeGreaterThan(0);
    expect(sub).toBeGreaterThan(seq);
  });

  it("gives a word-boundary substring a higher score than a mid-word one", () => {
    const boundary = fuzzyScore("log", "the log file");
    const midword = fuzzyScore("log", "catalogue");
    expect(boundary).toBeGreaterThan(midword);
  });

  it("returns 0 when not all query chars appear", () => {
    expect(fuzzyScore("zzz", "sql injection")).toBe(0);
  });

  it("bestFieldScore takes the max across candidate fields", () => {
    const s = bestFieldScore("nmap", [undefined, "no match here", "nmap scan"]);
    expect(s).toBeGreaterThan(0);
    expect(s).toBe(fuzzyScore("nmap", "nmap scan"));
  });
});

// ── grouping ────────────────────────────────────────────────────────────────

describe("groupSearch grouping", () => {
  const inputs: SearchInputs = {
    findings: [
      finding({ id: "f1", title: "SQL injection in login" }),
      finding({ id: "f2", title: "Open redirect", description: "unrelated" }),
    ],
    assets: [asset({ key: "8080", props: { note: "sql console exposed" } })],
    evidence: [
      { findingId: "f1", step: step({ interpretation: "SQL error leaked in response" }) },
    ],
    runs: [run({ summary: "sqlmap dumped the users table" })],
    code: [
      { file: "src/db.py", line: 10, title: "Tainted SQL via f-string", type: "SQL Injection", severity: "high", snippet: "q = f\"SELECT {x}\"" },
    ],
  };

  it("produces all five groups when the query hits each", () => {
    const groups = groupSearch("sql", inputs);
    const kinds = groups.map((g) => g.kind).sort();
    expect(kinds).toEqual(["assets", "code", "evidence", "findings", "output"].sort());
  });

  it("labels groups with human names", () => {
    const groups = groupSearch("sql", inputs);
    const byKind = Object.fromEntries(groups.map((g) => [g.kind, g.label]));
    expect(byKind.findings).toBe("Findings");
    expect(byKind.code).toBe("Code");
  });

  it("drops findings that do not match", () => {
    const groups = groupSearch("injection", inputs);
    const findingsGroup = groups.find((g) => g.kind === "findings")!;
    const ids = findingsGroup.rows.map((r) => r.id);
    expect(ids).toContain("finding:f1");
    expect(ids).not.toContain("finding:f2"); // "Open redirect" has no "injection"
  });

  it("omits a group whose input array is missing (no source_root → no Code)", () => {
    const groups = groupSearch("sql", { ...inputs, code: undefined });
    expect(groups.find((g) => g.kind === "code")).toBeUndefined();
  });

  it("returns no groups for a blank query", () => {
    expect(groupSearch("   ", inputs)).toEqual([]);
  });

  it("returns groups but zero rows when nothing matches", () => {
    const groups = groupSearch("zzqqxx", inputs);
    expect(countRows(groups)).toBe(0);
  });
});

// ── selection descriptors ────────────────────────────────────────────────────

describe("groupSearch selection descriptors", () => {
  it("a finding row carries a FindingRef triple", () => {
    const groups = groupSearch("injection", {
      findings: [finding({ id: "f9", sub_target_id: "stX", target_id: "tX" })],
    });
    const row = groups[0].rows[0];
    expect(row.select).toEqual({
      kind: "finding",
      ref: { findingId: "f9", subTargetId: "stX", targetId: "tX" },
    });
  });

  it("an asset row carries an AssetRef", () => {
    const groups = groupSearch("8080", { assets: [asset({})] });
    const row = groups[0].rows[0];
    expect(row.select).toEqual({
      kind: "asset",
      ref: { subTargetId: "st1", assetId: "service:8080", kind: "service" },
    });
  });

  it("an evidence row carries {findingId, stepId}", () => {
    const groups = groupSearch("reflects", {
      evidence: [{ findingId: "fE", step: step({ id: "sE", interpretation: "reflects payload" }) }],
    });
    const row = groups[0].rows[0];
    expect(row.select).toEqual({ kind: "step", findingId: "fE", stepId: "sE" });
  });

  it("a code row carries a file anchor", () => {
    const groups = groupSearch("tainted", {
      code: [{ file: "src/db.py", line: 10, title: "Tainted SQL", type: "SQLi", severity: "high", snippet: "" }],
    });
    const row = groups[0].rows[0];
    expect(row.select).toEqual({ kind: "anchor", file: "src/db.py", line: 10 });
  });

  it("an output row with a file:line in its text anchors there", () => {
    const groups = groupSearch("admin", {
      runs: [run({ summary: "found admin", output: "see src/admin.py:42" })],
    });
    const row = groups[0].rows[0];
    expect(row.select).toEqual({ kind: "anchor", file: "src/admin.py", line: 42 });
  });
});

// ── ranking within a group ──────────────────────────────────────────────────

describe("groupSearch ranking", () => {
  it("ranks a title substring hit above a description-only subsequence hit", () => {
    // Neutralise tool/target (both default to "sqlmap"/a login URL) so this test
    // isolates title-vs-description ranking.
    const groups = groupSearch("sql", {
      findings: [
        finding({ id: "weak", title: "Access control gap", description: "sequential ids", tool: "burp", target: "https://app.test/x" }),
        finding({ id: "strong", title: "SQL injection", description: "n/a", tool: "burp", target: "https://app.test/y" }),
      ],
    });
    const rows = groups[0].rows;
    expect(rows[0].id).toBe("finding:strong");
  });
});

// ── never upgrade suspected → confirmed ──────────────────────────────────────

describe("confidence", () => {
  it("marks a non-confirmed finding as suspected", () => {
    const groups = groupSearch("injection", { findings: [finding({ status: "open" })] });
    expect(groups[0].rows[0].conf).toBe("suspected");
  });
  it("marks a confirmed finding as confirmed", () => {
    const groups = groupSearch("injection", { findings: [finding({ status: "confirmed" })] });
    expect(groups[0].rows[0].conf).toBe("confirmed");
  });
});

// ── redaction ────────────────────────────────────────────────────────────────

describe("redactSecrets", () => {
  it("masks an Authorization Bearer header", () => {
    const out = redactSecrets("Authorization: Bearer abc123secrettoken");
    expect(out).not.toContain("abc123secrettoken");
    expect(out.toLowerCase()).toContain("redacted");
  });

  it("masks a Cookie header", () => {
    const out = redactSecrets("Cookie: session=deadbeefsecret; other=1");
    expect(out).not.toContain("deadbeefsecret");
  });

  it("masks a token / api_key assignment", () => {
    const out = redactSecrets('{"api_key": "sk-livedeadbeef12345"}');
    expect(out).not.toContain("sk-livedeadbeef12345");
  });

  it("masks an AWS access key id", () => {
    const out = redactSecrets("key AKIAIOSFODNN7EXAMPLE here");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("leaves benign text untouched", () => {
    expect(redactSecrets("just a normal sentence")).toBe("just a normal sentence");
  });

  it("redacted content flows into rendered snippets", () => {
    const groups = groupSearch("output", {
      runs: [run({ summary: "output shows Authorization: Bearer leakytoken99", output: "" })],
    });
    const row = groups[0].rows[0];
    expect(row.snippet ?? "").not.toContain("leakytoken99");
  });
});
