/**
 * Pure unit coverage for templateStore — no network, no React, no bus.
 * localStorage is the in-memory shim from src/test-setup.ts.
 *
 * Asserts:
 *   - round-trip persistence: save → load returns the same user templates
 *   - built-in loading: every shipped built-in passes the store's own validator
 *   - validation rejects a template with script / executable-looking content
 *   - finding template → PromoteFindingInput mapping (incl. CVSS score/severity
 *     derivation and references folded into the description)
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  STORAGE_KEY,
  validateTemplate,
  isUnsafeText,
  serializeUserTemplates,
  deserializeUserTemplates,
  loadUserTemplates,
  saveUserTemplates,
  upsertUserTemplate,
  removeUserTemplate,
  mergeTemplates,
  toPromoteInput,
  type FindingTemplate,
  type PlaybookTemplate,
  type Template,
} from "./templateStore";
import { BUILTIN_TEMPLATES } from "./builtins";

function findingTemplate(over: Partial<FindingTemplate> = {}): FindingTemplate {
  return {
    id: "user:finding:abc",
    kind: "finding",
    title: "Reflected XSS",
    severity: "high",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    description: "Input reflected without encoding.",
    remediation: "Encode output contextually.",
    references: ["OWASP XSS Cheat Sheet"],
    ...over,
  };
}

function playbookTemplate(over: Partial<PlaybookTemplate> = {}): PlaybookTemplate {
  return {
    id: "user:playbook:xyz",
    kind: "playbook",
    name: "My Recon",
    description: "A recon checklist.",
    steps: ["Confirm scope", "Enumerate hosts"],
    ...over,
  };
}

describe("validateTemplate", () => {
  it("accepts a well-formed finding template", () => {
    const res = validateTemplate(findingTemplate());
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.template.kind).toBe("finding");
      expect(res.template.id).toBe("user:finding:abc");
    }
  });

  it("accepts a well-formed playbook template", () => {
    const res = validateTemplate(playbookTemplate());
    expect(res.ok).toBe(true);
    if (res.ok && res.template.kind === "playbook") {
      expect(res.template.steps).toEqual(["Confirm scope", "Enumerate hosts"]);
    }
  });

  it("rejects a non-object / wrong kind", () => {
    expect(validateTemplate(null).ok).toBe(false);
    expect(validateTemplate("nope").ok).toBe(false);
    expect(validateTemplate({ kind: "malware" }).ok).toBe(false);
  });

  it("rejects a finding with an invalid CVSS vector", () => {
    const res = validateTemplate(findingTemplate({ cvssVector: "not-a-vector" }));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.join(" ")).toMatch(/cvss/i);
  });

  it("rejects an invalid severity", () => {
    const res = validateTemplate(findingTemplate({ severity: "spicy" as never }));
    expect(res.ok).toBe(false);
  });

  // ── SECURITY: executable / markup content is rejected ──────────────────────
  it("rejects a template containing script/executable content", () => {
    const attacks: Template[] = [
      findingTemplate({ description: "<script>alert(1)</script>" }),
      findingTemplate({ title: "javascript:alert(document.cookie)" }),
      findingTemplate({ remediation: "background:url(//evil)" }),
      findingTemplate({ references: ["<img src=x onerror=alert(1)>"] }),
      playbookTemplate({ steps: ["run <script>", "ok"] }),
      playbookTemplate({ description: "@import 'evil.css'" }),
    ];
    for (const bad of attacks) {
      const res = validateTemplate(bad);
      expect(res.ok, JSON.stringify(bad)).toBe(false);
      if (!res.ok) {
        expect(res.errors.join(" ")).toMatch(/disallowed content/);
      }
    }
    // sanity: the scanner flags these strings directly
    expect(isUnsafeText("<b>")).toBe(true);
    expect(isUnsafeText("javascript:void(0)")).toBe(true);
    expect(isUnsafeText("expression(alert(1))")).toBe(true);
    expect(isUnsafeText("plain safe text")).toBe(false);
  });

  // ── the scanner must NOT reject benign finding prose ───────────────────────
  it("accepts legitimate prose with $, braces, or a url query", () => {
    // This text renders as auto-escaped plain-text/markdown, so `$`/`{`/`}` and
    // an "…ons=…" substring are harmless — they must not fail validation.
    for (const s of [
      "The endpoint costs $5 per call",
      'A vulnerable JSON body like {"id":1} is reflected',
      "Interpolation such as ${user} is unescaped",
      "Request /api/list?companions=2 to trigger it",
    ]) {
      expect(isUnsafeText(s), s).toBe(false);
      expect(validateTemplate(findingTemplate({ description: s })).ok, s).toBe(true);
    }
    // but a real inline handler is still caught
    expect(isUnsafeText("<div onclick=steal()>")).toBe(true);
  });
});

describe("built-in loading", () => {
  it("ships at least one finding and one playbook built-in", () => {
    expect(BUILTIN_TEMPLATES.some((t) => t.kind === "finding")).toBe(true);
    expect(BUILTIN_TEMPLATES.some((t) => t.kind === "playbook")).toBe(true);
  });

  it("every built-in passes the store's own validator (no smuggled content)", () => {
    for (const t of BUILTIN_TEMPLATES) {
      const res = validateTemplate(t);
      expect(res.ok, `${t.id} failed: ${res.ok ? "" : res.errors.join(", ")}`).toBe(true);
    }
  });

  it("every built-in is flagged builtin:true and has a builtin: id", () => {
    for (const t of BUILTIN_TEMPLATES) {
      expect(t.builtin).toBe(true);
      expect(t.id.startsWith("builtin:")).toBe(true);
    }
  });
});

describe("round-trip persistence", () => {
  beforeEach(() => localStorage.clear());

  it("save → load returns the same user templates", () => {
    const templates = [findingTemplate(), playbookTemplate()];
    saveUserTemplates(templates);
    const loaded = loadUserTemplates();
    expect(loaded).toEqual(templates);
  });

  it("serialize/deserialize is a faithful round-trip", () => {
    const templates = [findingTemplate(), playbookTemplate()];
    const round = deserializeUserTemplates(serializeUserTemplates(templates));
    expect(round).toEqual(templates);
  });

  it("never persists built-ins into the user store", () => {
    const mixed: Template[] = [...BUILTIN_TEMPLATES, findingTemplate()];
    saveUserTemplates(mixed);
    const loaded = loadUserTemplates();
    expect(loaded).toHaveLength(1);
    expect(loaded[0].id).toBe("user:finding:abc");
  });

  it("deserialize tolerates garbage and drops invalid/executable entries", () => {
    expect(deserializeUserTemplates("not json")).toEqual([]);
    expect(deserializeUserTemplates(null)).toEqual([]);
    expect(deserializeUserTemplates('{"not":"array"}')).toEqual([]);
    // an array with one good + one malicious entry keeps only the good one
    const raw = JSON.stringify([
      findingTemplate(),
      findingTemplate({ id: "user:finding:evil", description: "<script>x</script>" }),
    ]);
    const out = deserializeUserTemplates(raw);
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("user:finding:abc");
  });

  it("bad JSON in localStorage does not throw loadUserTemplates", () => {
    localStorage.setItem(STORAGE_KEY, "{{{ broken");
    expect(loadUserTemplates()).toEqual([]);
  });
});

describe("user-set mutations", () => {
  it("upsert adds a new template and replaces an existing one by id", () => {
    let user: Template[] = [];
    user = upsertUserTemplate(user, findingTemplate());
    expect(user).toHaveLength(1);
    user = upsertUserTemplate(user, findingTemplate({ title: "Edited" }));
    expect(user).toHaveLength(1);
    expect((user[0] as FindingTemplate).title).toBe("Edited");
  });

  it("remove deletes by id but never a built-in", () => {
    const user = [findingTemplate()];
    expect(removeUserTemplate(user, "user:finding:abc")).toHaveLength(0);
    // a built-in id passed through remove is a no-op on the user set
    const withBuiltin: Template[] = [BUILTIN_TEMPLATES[0], findingTemplate()];
    const after = removeUserTemplate(withBuiltin, BUILTIN_TEMPLATES[0].id);
    expect(after.map((t) => t.id)).toContain(BUILTIN_TEMPLATES[0].id);
  });

  it("mergeTemplates puts built-ins first, then user templates", () => {
    const merged = mergeTemplates(BUILTIN_TEMPLATES, [findingTemplate()]);
    expect(merged.slice(0, BUILTIN_TEMPLATES.length)).toEqual(BUILTIN_TEMPLATES);
    expect(merged[merged.length - 1].id).toBe("user:finding:abc");
  });
});

describe("toPromoteInput (finding template → write-path input)", () => {
  it("maps title/severity/description and derives CVSS score + severity from the vector", () => {
    const t = findingTemplate({
      severity: "low", // deliberately mismatched; CVSS band should win
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8 critical
    });
    const input = toPromoteInput(t, "eng-123");
    expect(input.engagement_id).toBe("eng-123");
    expect(input.title).toBe("Reflected XSS");
    expect(input.cvss_vector).toBe(t.cvssVector);
    expect(input.cvss).toBeGreaterThan(0);
    expect(input.severity).toBe("critical"); // derived from the 9.8 score
    expect(input.tool).toBe("template");
  });

  it("folds remediation + references into the description declaratively", () => {
    const input = toPromoteInput(findingTemplate(), "eng-1");
    expect(input.description).toContain("Input reflected without encoding.");
    expect(input.description).toContain("Remediation:");
    expect(input.description).toContain("References:");
    expect(input.description).toContain("OWASP XSS Cheat Sheet");
  });

  it("keeps the declared severity and null CVSS when there is no vector", () => {
    const input = toPromoteInput(findingTemplate({ cvssVector: "" }), "eng-1");
    expect(input.severity).toBe("high");
    expect(input.cvss).toBeNull();
    expect(input.cvss_vector).toBeNull();
  });
});
