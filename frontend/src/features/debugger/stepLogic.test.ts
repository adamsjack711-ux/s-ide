/**
 * Pure unit coverage for stepLogic — no network, no React, no bus. Fixture
 * Step[] only. Asserts:
 *   - stepping bounds (clamp / forward / back / reset / atStart / atEnd),
 *     including the empty-chain edge case
 *   - inferred labeling: an unanchored step is INFERRED, an anchored one is not
 *   - trigger ("BREAK") detection across all three resolution tiers
 *     (root_cause.anchor → last asserting step → terminus)
 *   - secret redaction of a step (tokens / keys / cookies / Authorization,
 *     params, JWTs) so nothing sensitive survives into the render shape
 */
import { describe, it, expect } from "vitest";
import type { Step, FindingMethod } from "../../shell/model";
import {
  clampIndex,
  stepForward,
  stepBack,
  reset,
  atStart,
  atEnd,
  isInferred,
  anchoredStatus,
  findTriggerIndex,
  redactString,
  redactParams,
  redactStep,
} from "./stepLogic";

// ── Fixtures ─────────────────────────────────────────────────────────────────

function step(over: Partial<Step> & { id: string; ordinal: number }): Step {
  return {
    finding_id: "f1",
    action: { tool_id: "nmap", params: {} },
    evidence: { raw_output: "", hash: undefined, timestamp: undefined },
    interpretation: null,
    links_from: null,
    anchored: false,
    prev_hash: "",
    row_hash: "",
    role: "fact",
    hasInterpretation: false,
    ...over,
  } as Step;
}

/** A 3-step chain: s1 opens, s2 anchors to s1, s3 asserts a result (anchored). */
function chain(): Step[] {
  return [
    step({ id: "s1", ordinal: 1, anchored: false, interpretation: "recon" }),
    step({
      id: "s2",
      ordinal: 2,
      anchored: true,
      links_from: "s1",
      interpretation: "probing the login endpoint",
    }),
    step({
      id: "s3",
      ordinal: 3,
      anchored: true,
      links_from: "s2",
      interpretation: "SQL injection confirmed — auth bypass exploitable",
    }),
  ];
}

// ── Stepping bounds ──────────────────────────────────────────────────────────

describe("stepping bounds", () => {
  const steps = chain();

  it("clamps into range", () => {
    expect(clampIndex(-5, steps)).toBe(0);
    expect(clampIndex(0, steps)).toBe(0);
    expect(clampIndex(2, steps)).toBe(2);
    expect(clampIndex(99, steps)).toBe(2);
  });

  it("handles non-finite / fractional indices", () => {
    expect(clampIndex(NaN, steps)).toBe(0);
    expect(clampIndex(Infinity, steps)).toBe(2);
    expect(clampIndex(1.9, steps)).toBe(1);
  });

  it("empty chain has no valid index", () => {
    expect(clampIndex(0, [])).toBe(0);
    expect(clampIndex(3, [])).toBe(0);
    expect(atStart(0, [])).toBe(true);
    expect(atEnd(0, [])).toBe(true);
  });

  it("forward stops at the last step", () => {
    expect(stepForward(0, steps)).toBe(1);
    expect(stepForward(1, steps)).toBe(2);
    expect(stepForward(2, steps)).toBe(2); // clamped
  });

  it("back stops at the first step", () => {
    expect(stepBack(2, steps)).toBe(1);
    expect(stepBack(1, steps)).toBe(0);
    expect(stepBack(0, steps)).toBe(0); // clamped
  });

  it("reset returns to 0", () => {
    expect(reset()).toBe(0);
  });

  it("atStart / atEnd track the edges", () => {
    expect(atStart(0, steps)).toBe(true);
    expect(atStart(1, steps)).toBe(false);
    expect(atEnd(2, steps)).toBe(true);
    expect(atEnd(1, steps)).toBe(false);
  });
});

// ── Inferred labeling ────────────────────────────────────────────────────────

describe("inferred labeling", () => {
  it("an unanchored step is inferred, an anchored one is not", () => {
    const [s1, s2] = chain();
    expect(isInferred(s1)).toBe(true); // s1 unanchored
    expect(isInferred(s2)).toBe(false); // s2 anchored
    expect(anchoredStatus(s1)).toBe("inferred");
    expect(anchoredStatus(s2)).toBe("anchored");
  });

  it("redactStep carries the inferred flag through", () => {
    const [s1, s2] = chain();
    expect(redactStep(s1).inferred).toBe(true);
    expect(redactStep(s2).inferred).toBe(false);
  });
});

// ── Trigger ("BREAK") detection ──────────────────────────────────────────────

describe("trigger detection", () => {
  it("prefers an explicit root_cause.anchor to a step id", () => {
    const steps = chain();
    const method = { root_cause: { anchor: "s2" } } as Pick<FindingMethod, "root_cause">;
    expect(findTriggerIndex(steps, method)).toBe(1);
  });

  it("ignores a root_cause.anchor that names no step in the chain", () => {
    const steps = chain();
    const method = { root_cause: { anchor: "nope" } } as Pick<FindingMethod, "root_cause">;
    // falls through to last asserting step (s3 says 'confirmed'/'exploitable')
    expect(findTriggerIndex(steps, method)).toBe(2);
  });

  it("falls back to the LAST step that asserts a result", () => {
    const steps = [
      step({ id: "a", ordinal: 1, interpretation: "vulnerable to XSS" }),
      step({ id: "b", ordinal: 2, interpretation: "just navigating, no claim" }),
      step({ id: "c", ordinal: 3, interpretation: "access achieved — shell obtained" }),
    ];
    expect(findTriggerIndex(steps, null)).toBe(2);
  });

  it("falls back to the terminus when nothing asserts a result", () => {
    const steps = [
      step({ id: "a", ordinal: 1, interpretation: "looked around" }),
      step({ id: "b", ordinal: 2, interpretation: "kept looking" }),
    ];
    expect(findTriggerIndex(steps, null)).toBe(1);
  });

  it("returns null for an empty chain", () => {
    expect(findTriggerIndex([], null)).toBeNull();
  });
});

// ── Secret redaction ─────────────────────────────────────────────────────────

describe("redaction", () => {
  it("masks Authorization headers but keeps the scheme", () => {
    const out = redactString("Authorization: Bearer abcdef123456ghijkl");
    expect(out).toContain("Authorization:");
    expect(out).toContain("«redacted»");
    expect(out).not.toContain("abcdef123456ghijkl");
  });

  it("masks cookies", () => {
    const out = redactString("Cookie: session=deadbeefcafebabe1234; theme=dark");
    expect(out).not.toContain("deadbeefcafebabe1234");
    expect(out).toContain("«redacted»");
  });

  it("masks api keys / tokens / passwords in key=value shape", () => {
    expect(redactString('api_key="sk_live_supersecretvalue"')).not.toContain("supersecretvalue");
    expect(redactString("password=hunter2hunter2")).not.toContain("hunter2hunter2");
    expect(redactString('"access_token": "tok_abc123def456"')).not.toContain("tok_abc123def456");
  });

  it("masks bare JWTs and AWS keys", () => {
    const jwt = "eyJhbGciOi.eyJzdWIi.SflKxwRJSMe";
    expect(redactString(`token ${jwt}`)).not.toContain(jwt);
    expect(redactString("AKIAIOSFODNN7EXAMPLE")).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("leaves ordinary evidence text intact", () => {
    const text = "PORT 443/tcp open https\nnginx 1.25.3";
    expect(redactString(text)).toBe(text);
  });

  it("is safe on nullish input", () => {
    expect(redactString(undefined)).toBe("");
    expect(redactString(null)).toBe("");
    expect(redactString(123)).toBe("");
  });

  it("redacts sensitive param keys and string values", () => {
    const out = redactParams({
      url: "https://x.test/login",
      token: "topsecrettoken",
      nested: { authorization: "Bearer zzz999yyy888" },
      port: 443,
    });
    expect(out.token).toBe("«redacted»");
    expect(out.url).toBe("https://x.test/login");
    expect(out.port).toBe(443);
    expect((out.nested as any).authorization).toBe("«redacted»");
  });

  it("redactStep masks evidence, params, and interpretation together", () => {
    const s = step({
      id: "leak",
      ordinal: 1,
      action: { tool_id: "curl", params: { api_key: "sk_live_leakme12345", url: "/x" } },
      evidence: { raw_output: "Set-Cookie: sid=abcdef1234567890abcdef; HttpOnly", hash: "h", timestamp: 1 },
      interpretation: "captured session token=leakedtokenvalue for reuse",
    });
    const r = redactStep(s);
    expect(JSON.stringify(r)).not.toContain("sk_live_leakme12345");
    expect(r.rawOutput).not.toContain("abcdef1234567890abcdef");
    expect(r.interpretation).not.toContain("leakedtokenvalue");
    expect(r.params.url).toBe("/x"); // benign value preserved
    expect(r.toolId).toBe("curl");
  });
});
