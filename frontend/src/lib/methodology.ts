/**
 * Methodology map — a representative subset of OWASP WSTG ids and PTES phases
 * → human labels. Playbook steps and lab coverage tag themselves with these
 * ids; the learning surface renders the labels and the coverage ticks.
 *
 * This is intentionally a *subset*, not the full WSTG/PTES catalogue — enough
 * to exercise the coverage UI across discovery → exploitation. Extend freely.
 */

export type MethodologyFramework = "WSTG" | "PTES";

export type MethodologyEntry = {
  id: string;
  framework: MethodologyFramework;
  /** Short human label (no framework prefix). */
  label: string;
  /** Phase / category bucket for grouped display. */
  phase: string;
};

/** OWASP Web Security Testing Guide — representative ids. */
const WSTG: MethodologyEntry[] = [
  // Information Gathering
  { id: "WSTG-INFO-02", framework: "WSTG", phase: "Information Gathering", label: "Fingerprint web server" },
  { id: "WSTG-INFO-04", framework: "WSTG", phase: "Information Gathering", label: "Enumerate apps on the webserver" },
  { id: "WSTG-INFO-08", framework: "WSTG", phase: "Information Gathering", label: "Fingerprint web framework" },
  { id: "WSTG-INFO-10", framework: "WSTG", phase: "Information Gathering", label: "Map application architecture" },
  // Configuration & Deployment
  { id: "WSTG-CONF-01", framework: "WSTG", phase: "Configuration", label: "Network/infra configuration" },
  { id: "WSTG-CONF-07", framework: "WSTG", phase: "Configuration", label: "Test HTTP Strict Transport Security" },
  // Identity
  { id: "WSTG-IDNT-04", framework: "WSTG", phase: "Identity", label: "Account enumeration" },
  // Authentication
  { id: "WSTG-ATHN-01", framework: "WSTG", phase: "Authentication", label: "Credentials over encrypted channel" },
  { id: "WSTG-ATHN-03", framework: "WSTG", phase: "Authentication", label: "Weak lockout mechanism" },
  // Authorization
  { id: "WSTG-ATHZ-02", framework: "WSTG", phase: "Authorization", label: "Bypass authorization schema" },
  { id: "WSTG-ATHZ-04", framework: "WSTG", phase: "Authorization", label: "Insecure direct object references (IDOR)" },
  // Session Management
  { id: "WSTG-SESS-02", framework: "WSTG", phase: "Session", label: "Cookie attributes" },
  // Input Validation
  { id: "WSTG-INPV-01", framework: "WSTG", phase: "Input Validation", label: "Reflected cross-site scripting" },
  { id: "WSTG-INPV-02", framework: "WSTG", phase: "Input Validation", label: "Stored cross-site scripting" },
  { id: "WSTG-INPV-05", framework: "WSTG", phase: "Input Validation", label: "SQL injection" },
  { id: "WSTG-INPV-12", framework: "WSTG", phase: "Input Validation", label: "Command injection" },
  { id: "WSTG-INPV-19", framework: "WSTG", phase: "Input Validation", label: "Server-side request forgery (SSRF)" },
  // Error Handling
  { id: "WSTG-ERRH-01", framework: "WSTG", phase: "Error Handling", label: "Improper error handling" },
  // Cryptography
  { id: "WSTG-CRYP-01", framework: "WSTG", phase: "Cryptography", label: "Weak transport-layer protection" },
];

/** PTES — the seven engagement phases. */
const PTES: MethodologyEntry[] = [
  { id: "PTES-PRE", framework: "PTES", phase: "PTES", label: "Pre-engagement interactions" },
  { id: "PTES-INTEL", framework: "PTES", phase: "PTES", label: "Intelligence gathering" },
  { id: "PTES-RECON", framework: "PTES", phase: "PTES", label: "Reconnaissance" },
  { id: "PTES-THREAT", framework: "PTES", phase: "PTES", label: "Threat modeling" },
  { id: "PTES-VULN", framework: "PTES", phase: "PTES", label: "Vulnerability analysis" },
  { id: "PTES-EXPLOIT", framework: "PTES", phase: "PTES", label: "Exploitation" },
  { id: "PTES-POST", framework: "PTES", phase: "PTES", label: "Post-exploitation" },
  { id: "PTES-REPORT", framework: "PTES", phase: "PTES", label: "Reporting" },
];

/** Full list, for coverage display (grouped by `framework` / `phase`). */
export const METHODOLOGY: MethodologyEntry[] = [...WSTG, ...PTES];

const BY_ID: Record<string, MethodologyEntry> = Object.fromEntries(
  METHODOLOGY.map((e) => [e.id, e]),
);

/** All ids, in catalogue order — handy for a coverage matrix. */
export const METHODOLOGY_IDS: string[] = METHODOLOGY.map((e) => e.id);

/** Look up a single entry by id (undefined if unknown). */
export function methodologyEntry(id: string): MethodologyEntry | undefined {
  return BY_ID[id];
}

/**
 * Human label for a methodology id, e.g. "WSTG-INPV-01" → "WSTG-INPV-01 ·
 * Reflected cross-site scripting". Unknown ids pass through unchanged so
 * authoring isn't blocked on the catalogue being complete.
 */
export function methodologyLabel(id: string): string {
  const e = BY_ID[id];
  return e ? `${e.id} · ${e.label}` : id;
}

/** Just the short label (no id prefix); falls back to the id. */
export function methodologyShortLabel(id: string): string {
  return BY_ID[id]?.label ?? id;
}

/** Entries grouped by framework then phase — for a grouped coverage view. */
export function methodologyByFramework(): {
  framework: MethodologyFramework;
  phases: { phase: string; entries: MethodologyEntry[] }[];
}[] {
  const frameworks: MethodologyFramework[] = ["WSTG", "PTES"];
  return frameworks.map((framework) => {
    const entries = METHODOLOGY.filter((e) => e.framework === framework);
    const phaseNames = Array.from(new Set(entries.map((e) => e.phase)));
    return {
      framework,
      phases: phaseNames.map((phase) => ({
        phase,
        entries: entries.filter((e) => e.phase === phase),
      })),
    };
  });
}
