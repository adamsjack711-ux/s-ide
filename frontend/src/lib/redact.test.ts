/**
 * The shell-wide secret redactor. These lock in the UNION of what the (formerly
 * 6 copied) lane redactors covered — in particular the GitHub/Slack-token and
 * PEM-block masking that only the timeline copy had before consolidation, now
 * applied everywhere a secret could be rendered.
 */
import { describe, it, expect } from "vitest";
import { redactSecrets, redactString, REDACTION_MASK } from "./redact";

describe("redactSecrets (shared)", () => {
  it("masks headers, keeping the label", () => {
    expect(redactSecrets("Authorization: Bearer sk_live_abcdef1234567890"))
      .toBe(`Authorization: ${REDACTION_MASK}`);
    expect(redactSecrets("Cookie: session=deadbeefcafefeed; theme=dark"))
      .not.toContain("deadbeefcafefeed");
  });

  it("masks key=value secrets and bare tokens", () => {
    expect(redactSecrets('password = "hunter2supersecret"')).not.toContain("hunter2supersecret");
    expect(redactSecrets("api_key: AKIAIOSFODNN7EXAMPLE")).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("masks the token shapes that used to be timeline-only (now everywhere)", () => {
    expect(redactSecrets("token ghp_0123456789abcdefghijABCDEFGHIJ0123"))
      .not.toContain("ghp_0123456789abcdefghijABCDEFGHIJ0123");
    expect(redactSecrets("slack xoxb-1234567890-abcdefghijkl"))
      .not.toContain("xoxb-1234567890-abcdefghijkl");
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----";
    expect(redactSecrets(pem)).toBe(REDACTION_MASK);
  });

  it("is idempotent, tolerant of non-strings, and leaves benign prose intact", () => {
    const once = redactSecrets("token=abc123secretvalue");
    expect(redactSecrets(once)).toBe(once);
    expect(redactSecrets(undefined)).toBe("");
    expect(redactSecrets(null)).toBe("");
    expect(redactSecrets(42)).toBe("");
    expect(redactSecrets("nmap -sT 10.0.0.5 found 3 open ports"))
      .toBe("nmap -sT 10.0.0.5 found 3 open ports");
  });

  it("redactString is the same function", () => {
    expect(redactString).toBe(redactSecrets);
  });
});
