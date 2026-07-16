/**
 * Unit coverage for fixdiff/diffRender — the PURE before/after diff + secret
 * redaction. No network, no React: fixture strings in, diff/mask out. Asserts
 * added/removed lines are identified and that a secret appearing in a line is
 * masked before it can reach the UI.
 */
import { describe, it, expect } from "vitest";
import { computeDiff, redactSecrets } from "./diffRender";

describe("redactSecrets", () => {
  it("masks an Authorization: Bearer header", () => {
    const out = redactSecrets("Authorization: Bearer sk_live_abcdef1234567890");
    expect(out).not.toContain("sk_live_abcdef1234567890");
    expect(out).toContain("«redacted»");
    expect(out).toContain("Authorization:"); // context preserved
  });

  it("masks a password assignment but keeps the key name", () => {
    const out = redactSecrets('password = "hunter2supersecret"');
    expect(out).not.toContain("hunter2supersecret");
    expect(out).toContain("«redacted»");
    expect(out).toContain("password");
  });

  it("masks a Cookie header and an api_key assignment", () => {
    expect(redactSecrets("Cookie: session=deadbeefcafefeed")).not.toContain("deadbeefcafefeed");
    const key = redactSecrets("api_key: AKIAIOSFODNN7EXAMPLE");
    expect(key).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(key).toContain("«redacted»");
  });

  it("leaves non-secret lines untouched", () => {
    const line = "const total = price + tax;";
    expect(redactSecrets(line)).toBe(line);
  });
});

describe("computeDiff", () => {
  it("identifies a removed vulnerable line and the added fixed line", () => {
    const before = ["def login(u, p):", '    query = "SELECT * FROM users WHERE u=" + u', "    return db.exec(query)"].join("\n");
    const after = ["def login(u, p):", "    query = db.prepare(SELECT_USER)", "    return db.exec(query, [u])"].join("\n");

    const diff = computeDiff(before, after);

    const removed = diff.lines.filter((l) => l.kind === "removed").map((l) => l.text);
    const added = diff.lines.filter((l) => l.kind === "added").map((l) => l.text);

    expect(diff.removedCount).toBe(2);
    expect(diff.addedCount).toBe(2);
    expect(removed).toContain('    query = "SELECT * FROM users WHERE u=" + u');
    expect(added).toContain("    query = db.prepare(SELECT_USER)");
    // The unchanged first line is context, present on both sides.
    const ctx = diff.lines.find((l) => l.kind === "context");
    expect(ctx?.text).toBe("def login(u, p):");
    expect(ctx?.beforeNo).toBe(1);
    expect(ctx?.afterNo).toBe(1);
    expect(diff.unchanged).toBe(false);
  });

  it("redacts a secret that appears inside a diffed (removed) line", () => {
    const before = 'const conn = "postgres://admin:supersecretpw@db/app"\npassword = "leakedtoken123"';
    const after = "const conn = process.env.DB_URL\npassword = process.env.PW";

    const diff = computeDiff(before, after);

    const allText = diff.lines.map((l) => l.text).join("\n");
    expect(allText).not.toContain("leakedtoken123");
    expect(allText).not.toContain("supersecretpw");
    expect(allText).toContain("«redacted»");
    // A removed line carrying the secret is still recorded as removed, just masked.
    const removedTexts = diff.lines.filter((l) => l.kind === "removed").map((l) => l.text);
    expect(removedTexts.some((t) => t.includes("«redacted»"))).toBe(true);
  });

  it("reports unchanged when before and after are identical", () => {
    const src = "line one\nline two\n";
    const diff = computeDiff(src, src);
    expect(diff.unchanged).toBe(true);
    expect(diff.addedCount).toBe(0);
    expect(diff.removedCount).toBe(0);
    expect(diff.lines.every((l) => l.kind === "context")).toBe(true);
  });

  it("handles a pure insertion (empty before)", () => {
    const diff = computeDiff("", "new()\nline");
    expect(diff.addedCount).toBe(2);
    expect(diff.removedCount).toBe(0);
    expect(diff.lines.every((l) => l.kind === "added")).toBe(true);
  });
});
