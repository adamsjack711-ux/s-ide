/**
 * F8 — Template store (pure logic; no network, no React, no bus).
 *
 * Templates are reusable, DECLARATIVE data — created once, instantiated many
 * times:
 *   - a FINDING template  = {title, description, severity, cvss vector,
 *                            remediation, references[]}
 *   - a PLAYBOOK template = {name, description, ordered steps[]} (step labels /
 *                            methodology ids only — NO executable content)
 *
 * This module owns everything that can be unit-tested with fixtures:
 *   - validate/parse a template (reject anything executable-looking),
 *   - serialize/deserialize the user template list for localStorage,
 *   - load built-ins + user templates as one merged, ordered list,
 *   - map a FINDING template → PromoteFindingInput (the normal audited write
 *     path in lib/engagement).
 *
 * SECURITY (mirrors the .side theme validator's philosophy — themes/validate.ts):
 * a template is DATA. Every free-text field is scanned and rejected if it looks
 * like markup or executable content (`<...>`, `javascript:`, `script`, `url(`,
 * `@import`, `expression(`, braces, backslash). Playbook steps carry no runnable
 * content by construction. The ONLY write path is promoteToFinding — this module
 * never calls it; it produces the input the panel hands to it.
 */
import type { FindingSeverity, PromoteFindingInput } from "../../lib/engagement";
import { parseVector, calculateScore, severityFromScore } from "../../lib/cvss";

// ── Types ────────────────────────────────────────────────────────────────────

export type TemplateKind = "finding" | "playbook";

type TemplateBase = {
  /** Stable id. Built-ins are `builtin:*`; user templates are `user:*`. */
  id: string;
  kind: TemplateKind;
  /** True for shipped built-ins (read-only in the UI). Absent/false = user. */
  builtin?: boolean;
};

export type FindingTemplate = TemplateBase & {
  kind: "finding";
  title: string;
  severity: FindingSeverity;
  /** Canonical CVSS v3.1 base vector string, or "" if none. */
  cvssVector: string;
  description: string;
  remediation: string;
  references: string[];
};

export type PlaybookTemplate = TemplateBase & {
  kind: "playbook";
  name: string;
  description: string;
  /** Ordered step LABELS / methodology ids — declarative, never executable. */
  steps: string[];
};

export type Template = FindingTemplate | PlaybookTemplate;

// ── Persistence ──────────────────────────────────────────────────────────────

/** Versioned localStorage key for the user's own (non-built-in) templates. */
export const STORAGE_KEY = "s-ide:templates:v1";

const VALID_SEVERITIES: readonly FindingSeverity[] = [
  "info", "low", "medium", "high", "critical",
];

// ── Safety scan (mirror of themes/validate.ts UNSAFE_RE philosophy) ──────────
// Any value containing markup or executable-looking content is rejected, so a
// template can never carry something that would run or inject when rendered.
//
// Note: unlike the theme validator (whose values are hex + font names, so the
// bare word "script" never legitimately appears), finding templates DESCRIBE
// web attacks in prose — "Cross-Site Scripting", "JavaScript", "a script tag"
// are legitimate English. So we reject the DANGEROUS FORMS — any `<...>` markup
// (which already catches `<script>`, `<img onerror=>`, etc.), the `javascript:`
// scheme, `url(...)`, `@import`, `expression(...)`, and template/brace/escape
// characters — WITHOUT rejecting the plain word "script".
const UNSAFE_RE =
  /[<>{}\\`$]|javascript:|vbscript:|data:text\/html|url\s*\(|@import|expression\s*\(|on\w+\s*=/i;

/** True if a free-text value looks like markup / executable content. */
export function isUnsafeText(v: string): boolean {
  return UNSAFE_RE.test(v);
}

export type ValidationResult<T> =
  | { ok: true; template: T; errors: [] }
  | { ok: false; errors: string[] };

const MAX_TEXT = 8000;
const MAX_STEPS = 100;
const MAX_REFS = 50;

function scanField(name: string, v: unknown, errors: string[], required: boolean): string {
  if (v == null || v === "") {
    if (required) errors.push(`${name} is required`);
    return "";
  }
  if (typeof v !== "string") {
    errors.push(`${name} must be a string`);
    return "";
  }
  if (v.length > MAX_TEXT) {
    errors.push(`${name} is too long`);
    return "";
  }
  if (isUnsafeText(v)) {
    errors.push(`${name} contains disallowed content`);
    return "";
  }
  return v;
}

/**
 * Validate + normalise an untrusted template object (from localStorage or the
 * editor form). Returns a clean, typed Template on success, or the list of
 * reasons it was rejected. Executable/markup content in ANY text field fails.
 */
export function validateTemplate(input: unknown): ValidationResult<Template> {
  const errors: string[] = [];
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, errors: ["template must be an object"] };
  }
  const o = input as Record<string, unknown>;

  const kind = o.kind;
  if (kind !== "finding" && kind !== "playbook") {
    return { ok: false, errors: [`kind must be "finding" or "playbook"`] };
  }
  const id = typeof o.id === "string" && o.id.trim() ? o.id : "";
  if (!id) errors.push("id is required");
  if (id && isUnsafeText(id)) errors.push("id contains disallowed content");
  // Only carry `builtin` when explicitly true, so validating a user template
  // (which never sets it) round-trips to an identical object.
  const builtinFlag = o.builtin === true ? { builtin: true as const } : {};

  if (kind === "finding") {
    const title = scanField("title", o.title, errors, true);
    const description = scanField("description", o.description, errors, false);
    const remediation = scanField("remediation", o.remediation, errors, false);

    const severity =
      typeof o.severity === "string" && (VALID_SEVERITIES as string[]).includes(o.severity)
        ? (o.severity as FindingSeverity)
        : (errors.push("severity must be one of info/low/medium/high/critical"), "info" as FindingSeverity);

    let cvssVector = "";
    if (o.cvssVector != null && o.cvssVector !== "") {
      cvssVector = scanField("cvssVector", o.cvssVector, errors, false);
      // A non-empty vector must parse to a valid v3.1 base vector.
      if (cvssVector && parseVector(cvssVector) === null) {
        errors.push("cvssVector is not a valid CVSS v3.1 vector");
      }
    }

    const references: string[] = [];
    if (o.references != null) {
      if (!Array.isArray(o.references)) {
        errors.push("references must be an array");
      } else if (o.references.length > MAX_REFS) {
        errors.push("too many references");
      } else {
        o.references.forEach((r, i) => {
          const s = scanField(`references[${i}]`, r, errors, false);
          if (s) references.push(s);
        });
      }
    }

    if (errors.length) return { ok: false, errors };
    return {
      ok: true, errors: [],
      template: {
        id, kind: "finding", ...builtinFlag, title, severity, cvssVector,
        description, remediation, references,
      },
    };
  }

  // playbook
  const name = scanField("name", o.name, errors, true);
  const description = scanField("description", o.description, errors, false);
  const steps: string[] = [];
  if (o.steps != null) {
    if (!Array.isArray(o.steps)) {
      errors.push("steps must be an array");
    } else if (o.steps.length > MAX_STEPS) {
      errors.push("too many steps");
    } else {
      o.steps.forEach((s, i) => {
        const v = scanField(`steps[${i}]`, s, errors, false);
        if (v) steps.push(v);
      });
    }
  }
  if (errors.length) return { ok: false, errors };
  return {
    ok: true, errors: [],
    template: { id, kind: "playbook", ...builtinFlag, name, description, steps },
  };
}

// ── Serialize / deserialize the USER list for localStorage ───────────────────

/**
 * Deserialize a raw localStorage string into the valid user templates it held.
 * Tolerant: bad JSON → []; any individual template that fails validation is
 * dropped (never crashes the panel, never lets executable content through).
 * Built-in entries are ignored here (built-ins are seeded from builtins.ts).
 */
export function deserializeUserTemplates(raw: string | null): Template[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const out: Template[] = [];
  for (const item of parsed) {
    const res = validateTemplate(item);
    if (res.ok && !res.template.builtin) out.push(res.template);
  }
  return out;
}

/** Serialize the user template list to a JSON string for persistence. */
export function serializeUserTemplates(templates: Template[]): string {
  // Persist only user templates (never re-persist built-ins).
  return JSON.stringify(templates.filter((t) => !t.builtin));
}

// ── localStorage-backed load / save (thin, still testable via the shim) ──────

/** Load the user's saved templates from localStorage. Returns [] on any error. */
export function loadUserTemplates(): Template[] {
  try {
    return deserializeUserTemplates(localStorage.getItem(STORAGE_KEY));
  } catch {
    return [];
  }
}

/** Persist the user's templates to localStorage. Silently no-ops on quota. */
export function saveUserTemplates(templates: Template[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, serializeUserTemplates(templates));
  } catch {
    /* quota / unavailable */
  }
}

// ── Merged view (built-ins + user), and mutations on the user set ────────────

/**
 * The full list the panel renders: built-ins first (as passed), then the user's
 * own templates. Built-ins are seeded by the caller from builtins.ts so this
 * module stays pure/decoupled from the constant data.
 */
export function mergeTemplates(builtins: Template[], user: Template[]): Template[] {
  return [...builtins, ...user];
}

/** Generate a stable-enough id for a new user template. */
export function newUserId(kind: TemplateKind): string {
  const rand = Math.random().toString(36).slice(2, 8);
  return `user:${kind}:${Date.now().toString(36)}${rand}`;
}

/**
 * Insert or replace a user template in the list by id (built-ins are never
 * touched — a matching built-in id is left alone and the entry is added as new).
 * Returns a NEW array (does not mutate).
 */
export function upsertUserTemplate(user: Template[], t: Template): Template[] {
  const i = user.findIndex((x) => x.id === t.id && !x.builtin);
  if (i === -1) return [...user, t];
  const copy = [...user];
  copy[i] = t;
  return copy;
}

/** Remove a user template by id (built-ins are immune). Returns a NEW array. */
export function removeUserTemplate(user: Template[], id: string): Template[] {
  return user.filter((t) => !(t.id === id && !t.builtin));
}

// ── Template → write-path input mapping ──────────────────────────────────────

/**
 * Map a FINDING template into the PromoteFindingInput the audited write path
 * (promoteToFinding) accepts. The panel calls promoteToFinding() with this so
 * `modelChanged` fires and every view refreshes — this module never writes.
 *
 * CVSS: when the template carries a valid vector, we compute its base score and
 * DERIVE the severity from the score (the CVSS band is the source of truth once
 * a finding is scored, matching lib/engagement's scoreFindingCvss). With no
 * vector we keep the template's declared severity and leave cvss null.
 */
export function toPromoteInput(
  t: FindingTemplate,
  engagementId: string,
): PromoteFindingInput {
  let cvss: number | null = null;
  let cvssVector: string | null = null;
  let severity: FindingSeverity = t.severity;

  if (t.cvssVector) {
    const parsed = parseVector(t.cvssVector);
    if (parsed) {
      const score = calculateScore(parsed);
      cvss = score;
      cvssVector = t.cvssVector;
      severity = severityFromScore(score);
    }
  }

  // Fold references into the description as a declarative "References:" block so
  // they survive into the finding without needing a new field on the write path.
  const refs = t.references.length
    ? `\n\nReferences:\n${t.references.map((r) => `- ${r}`).join("\n")}`
    : "";
  const remediation = t.remediation
    ? `\n\nRemediation:\n${t.remediation}`
    : "";
  const description = `${t.description}${remediation}${refs}`.trim();

  return {
    engagement_id: engagementId,
    title: t.title,
    severity,
    description,
    tool: "template",
    cvss,
    cvss_vector: cvssVector,
  };
}
