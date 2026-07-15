/**
 * F8 — Built-in templates, shipped as plain JSON constants.
 *
 * These are DECLARATIVE DATA only: a finding template is a reusable
 * {title, description, severity, cvss vector, remediation, references}; a
 * playbook template is a reusable {name, description, ordered step labels}.
 * There is NO executable content anywhere — steps are methodology labels, not
 * commands to run. Built-ins are seeded read-only alongside the user's own
 * templates in localStorage (see templateStore.ts); the user can instantiate a
 * built-in but cannot edit or delete it (fork by "duplicate to user template").
 *
 * Every built-in passes the same validator the store applies to user input
 * (validateTemplate) — a parity test in templateStore.test.ts asserts this, so
 * a built-in can never smuggle markup/executable content past the gate.
 *
 * CVSS vectors are canonical v3.1 base-metric strings (see lib/cvss.ts); the
 * store parses them and maps to the finding's cvss score/vector on instantiate.
 */
import type { FindingTemplate, PlaybookTemplate, Template } from "./templateStore";

// ── Finding templates — common web findings ─────────────────────────────────

const REFLECTED_XSS: FindingTemplate = {
  id: "builtin:xss-reflected",
  kind: "finding",
  builtin: true,
  title: "Reflected Cross-Site Scripting (XSS)",
  severity: "high",
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
  description:
    "User-supplied input is reflected into the HTTP response without adequate " +
    "output encoding, allowing an attacker to inject content that executes in " +
    "the victim's browser in the context of the vulnerable origin. A crafted " +
    "link delivers the payload; the response echoes it back and it runs on " +
    "load, enabling session theft, credential harvesting, or actions on behalf " +
    "of the victim.",
  remediation:
    "Contextually encode all reflected output (HTML body, attribute, JS, URL, " +
    "CSS contexts each need their own encoding). Prefer framework auto-escaping " +
    "and avoid raw HTML sinks. Add a restrictive Content-Security-Policy as " +
    "defense in depth and set HttpOnly on session cookies.",
  references: [
    "OWASP: Cross Site Scripting Prevention Cheat Sheet",
    "CWE-79: Improper Neutralization of Input During Web Page Generation",
  ],
};

const SQL_INJECTION: FindingTemplate = {
  id: "builtin:sqli",
  kind: "finding",
  builtin: true,
  title: "SQL Injection",
  severity: "critical",
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  description:
    "A parameter is concatenated into a SQL statement without parameterization, " +
    "letting an attacker alter the query's structure. This can expose or modify " +
    "arbitrary database contents, bypass authentication, and in some " +
    "configurations lead to command execution on the database host.",
  remediation:
    "Use parameterized queries / prepared statements for every database access; " +
    "never build SQL by string concatenation. Apply least-privilege database " +
    "accounts, validate input types, and use an ORM's safe query builder. Do not " +
    "rely on input filtering alone.",
  references: [
    "OWASP: SQL Injection Prevention Cheat Sheet",
    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
  ],
};

const IDOR: FindingTemplate = {
  id: "builtin:idor",
  kind: "finding",
  builtin: true,
  title: "Insecure Direct Object Reference (IDOR)",
  severity: "high",
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
  description:
    "An object identifier supplied by the client (e.g. a record id in the URL or " +
    "request body) is used to fetch data without verifying that the authenticated " +
    "user is authorized for that object. By enumerating or altering the " +
    "identifier, an attacker reads or modifies other users' resources.",
  remediation:
    "Enforce object-level authorization on every request server-side: check that " +
    "the current principal owns or may access the referenced object before " +
    "acting. Do not rely on unguessable ids alone. Scope queries to the " +
    "authenticated user and log access-control decisions.",
  references: [
    "OWASP API Security Top 10: Broken Object Level Authorization (BOLA)",
    "CWE-639: Authorization Bypass Through User-Controlled Key",
  ],
};

// ── Playbook template — recon methodology ───────────────────────────────────

const RECON_PLAYBOOK: PlaybookTemplate = {
  id: "builtin:playbook-recon",
  kind: "playbook",
  builtin: true,
  name: "Web Application Recon",
  description:
    "A declarative methodology checklist for the reconnaissance phase of a web " +
    "application engagement. Each step is a labelled activity, not an executable " +
    "command — instantiating it drafts the ordered checklist, it does not run " +
    "any tool.",
  steps: [
    "Confirm scope and authorization for every in-scope host",
    "Enumerate subdomains and resolve live hosts",
    "Fingerprint web servers, frameworks, and technologies",
    "Discover content and endpoints (directories, files, APIs)",
    "Map authentication and session-management surfaces",
    "Identify input vectors (params, headers, cookies, uploads)",
    "Review TLS configuration and security headers",
    "Record assets and candidate weaknesses for the testing phase",
  ],
};

/** All built-in templates, in display order (findings first, then playbooks). */
export const BUILTIN_TEMPLATES: Template[] = [
  SQL_INJECTION,
  REFLECTED_XSS,
  IDOR,
  RECON_PLAYBOOK,
];
