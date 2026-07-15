/**
 * Unit coverage for timelineLogic (F6). NO network, NO React, NO bus — pure
 * functions over fixture audit rows. Asserts the three things the spec names:
 * chronological ordering, label derivation, and secret redaction. Also covers
 * classification + reference extraction, and the read-only invariant (never
 * mutate an input row).
 */
import { describe, it, expect } from "vitest";
import {
  redactSecrets,
  pickIso,
  toEpoch,
  normalizeStatus,
  extractFindingId,
  extractSubTargetId,
  classify,
  deriveLabel,
  normalizeEntry,
  buildTimeline,
} from "./timelineLogic";
import type { AuditEntry } from "../../shell/model";

// ── Fixtures (shapes mirror lib/audit_log._row_to_dict + spine extras) ────────

const rows: AuditEntry[] = [
  {
    id: "a3",
    tool: "port_scanner",
    status: "completed",
    engagement_id: "eng1",
    target: "10.0.0.5",
    summary: "3 open ports",
    ts_start: "2026-07-11T10:02:00Z",
    ts_end: "2026-07-11T10:02:30Z",
  },
  {
    id: "a1",
    tool: "arm",
    status: "completed",
    engagement_id: "eng1",
    target: "sub-web",
    summary: "armed sub-target",
    sub_target_id: "sub-web",
    ts_start: "2026-07-11T10:00:00Z",
  },
  {
    id: "a2",
    tool: "promote_finding",
    status: "completed",
    engagement_id: "eng1",
    target: "https://app.test/login",
    summary: "SQLi on login",
    finding_id: "f-42",
    sub_target_id: "sub-web",
    ts_start: "2026-07-11T10:01:00Z",
  },
];

describe("redactSecrets", () => {
  it("masks Authorization header value but keeps the name", () => {
    const out = redactSecrets("curl -H 'Authorization: Bearer abcdef123456' https://x");
    expect(out).toContain("Authorization");
    expect(out).not.toContain("abcdef123456");
    expect(out).toContain("«redacted»");
  });

  it("masks token/apikey/password kv pairs", () => {
    expect(redactSecrets("token=supersecretvalue1234")).not.toContain("supersecretvalue1234");
    expect(redactSecrets("api_key=AKIAIOSFODNN7EXAMPLE")).toContain("«redacted»");
    expect(redactSecrets("--password hunter2horse")).not.toContain("hunter2horse");
  });

  it("masks cookies and JWTs and AWS keys", () => {
    expect(redactSecrets("Cookie: session=deadbeefdeadbeef")).not.toContain("deadbeefdeadbeef");
    const jwt = "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM";
    expect(redactSecrets(`bearer token ${jwt}`)).not.toContain(jwt);
    expect(redactSecrets("key AKIAIOSFODNN7EXAMPLE here")).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("is idempotent and safe on non-strings", () => {
    const once = redactSecrets("token=abc123secretvalue");
    expect(redactSecrets(once)).toBe(once);
    expect(redactSecrets(undefined)).toBe("");
    expect(redactSecrets(null)).toBe("");
    expect(redactSecrets(42)).toBe("");
  });

  it("leaves benign scan text untouched", () => {
    const t = "nmap -sT 10.0.0.5 found 3 open ports";
    expect(redactSecrets(t)).toBe(t);
  });
});

describe("timestamp helpers", () => {
  it("pickIso prefers end over start over permissive", () => {
    expect(pickIso({ id: "x", ts_end: "E", ts_start: "S" })).toBe("E");
    expect(pickIso({ id: "x", ts_start: "S" })).toBe("S");
    expect(pickIso({ id: "x", ts: "T" })).toBe("T");
    expect(pickIso({ id: "x" })).toBe("");
  });

  it("toEpoch is NaN-safe (unparseable -> 0)", () => {
    expect(toEpoch("2026-07-11T10:00:00Z")).toBeGreaterThan(0);
    expect(toEpoch("not-a-date")).toBe(0);
    expect(toEpoch("")).toBe(0);
  });
});

describe("classification + references", () => {
  it("classifies rows by tool/keyword and finding reference", () => {
    expect(classify(rows[0])).toBe("run");        // port_scanner
    expect(classify(rows[1])).toBe("arm");         // arm
    expect(classify(rows[2])).toBe("finding");     // has finding_id
    expect(classify({ id: "e", tool: "disarm" })).toBe("disarm");
    expect(classify({ id: "e", tool: "attest_scope" })).toBe("attestation");
    expect(classify({ id: "e" })).toBe("event");   // no tool -> event, not dropped
  });

  it("extracts finding + sub-target ids across spellings", () => {
    expect(extractFindingId(rows[2])).toBe("f-42");
    expect(extractFindingId({ id: "x", findingId: "f-9" })).toBe("f-9");
    expect(extractFindingId(rows[0])).toBeUndefined();
    expect(extractSubTargetId(rows[1])).toBe("sub-web");
    expect(extractSubTargetId({ id: "x", subTargetId: "s-2" })).toBe("s-2");
    expect(extractSubTargetId(rows[0])).toBeUndefined();
  });

  it("normalizeStatus maps to the known set", () => {
    expect(normalizeStatus("completed")).toBe("completed");
    expect(normalizeStatus("refused")).toBe("refused");
    expect(normalizeStatus("weird")).toBe("unknown");
    expect(normalizeStatus(undefined)).toBe("unknown");
  });
});

describe("deriveLabel", () => {
  it("labels a run with tool + status", () => {
    expect(deriveLabel("run", "port_scanner", "completed")).toBe("port_scanner — completed");
    expect(deriveLabel("run", "port_scanner", "unknown")).toBe("port_scanner");
  });
  it("labels a finding as created", () => {
    expect(deriveLabel("finding", "promote_finding", "completed")).toBe("Finding created");
  });
  it("labels arm/disarm/attestation", () => {
    expect(deriveLabel("arm", "arm", "completed")).toBe("Sub-target armed: arm");
    expect(deriveLabel("disarm", "", "completed")).toBe("Sub-target disarmed");
    expect(deriveLabel("attestation", "", "completed")).toBe("Attestation");
  });
});

describe("normalizeEntry", () => {
  it("produces a redacted, ref-carrying entry without mutating the row", () => {
    const row: AuditEntry = {
      id: "z",
      tool: "curl",
      status: "completed",
      target: "https://api.test?token=leakedsecretvalue99",
      summary: "Authorization: Bearer topsecrettoken12345",
      finding_id: "f-7",
      sub_target_id: "sub-a",
      ts_start: "2026-07-11T09:00:00Z",
    };
    const frozen = JSON.stringify(row);
    const e = normalizeEntry(row);

    expect(e.kind).toBe("finding");
    expect(e.findingId).toBe("f-7");
    expect(e.subTargetId).toBe("sub-a");
    expect(e.label).toBe("Finding created");
    expect(e.target).not.toContain("leakedsecretvalue99");
    expect(e.detail).not.toContain("topsecrettoken12345");
    expect(e.detail).toContain("«redacted»");
    expect(e.ts).toBeGreaterThan(0);
    // READ-ONLY: the input row is untouched.
    expect(JSON.stringify(row)).toBe(frozen);
  });

  it("keeps unparseable-timestamp rows (ts=0) rather than dropping them", () => {
    const e = normalizeEntry({ id: "bad", tool: "x", status: "completed", ts_start: "nope" });
    expect(e.ts).toBe(0);
    expect(e.id).toBe("bad");
  });
});

describe("buildTimeline (chronological ordering)", () => {
  it("sorts oldest -> newest by default", () => {
    const out = buildTimeline(rows);
    expect(out.map((e) => e.id)).toEqual(["a1", "a2", "a3"]);
    // strictly non-decreasing timestamps
    for (let i = 1; i < out.length; i++) {
      expect(out[i].ts).toBeGreaterThanOrEqual(out[i - 1].ts);
    }
  });

  it("sorts newest -> oldest with order=desc", () => {
    const out = buildTimeline(rows, "desc");
    expect(out.map((e) => e.id)).toEqual(["a3", "a2", "a1"]);
  });

  it("is stable within equal timestamps (preserves input order)", () => {
    const tie: AuditEntry[] = [
      { id: "first", tool: "a", ts_start: "2026-07-11T10:00:00Z" },
      { id: "second", tool: "b", ts_start: "2026-07-11T10:00:00Z" },
    ];
    expect(buildTimeline(tie).map((e) => e.id)).toEqual(["first", "second"]);
  });

  it("redacts every rendered entry in the built timeline", () => {
    const leaky: AuditEntry[] = [
      {
        id: "leak",
        tool: "curl",
        status: "completed",
        target: "https://x?api_key=abcd1234efgh5678",
        summary: "ok",
        ts_start: "2026-07-11T10:00:00Z",
      },
    ];
    const [e] = buildTimeline(leaky);
    expect(e.target).not.toContain("abcd1234efgh5678");
  });
});
