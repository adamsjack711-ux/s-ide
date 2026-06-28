// CVSS v3.1 calculator. Pure JS — no deps.
//
// Reference: https://www.first.org/cvss/v3.1/specification-document
// Vector format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
//
// Only Base metrics are implemented (the 8 required ones). Temporal /
// Environmental modifiers are stripped if present but don't affect the score.

export type Metric = "AV" | "AC" | "PR" | "UI" | "S" | "C" | "I" | "A";

export type CvssVector = Record<Metric, string>;

export const METRICS: { id: Metric; label: string; options: { value: string; label: string }[] }[] = [
  {
    id: "AV", label: "Attack Vector",
    options: [
      { value: "N", label: "Network" },
      { value: "A", label: "Adjacent" },
      { value: "L", label: "Local" },
      { value: "P", label: "Physical" },
    ],
  },
  {
    id: "AC", label: "Attack Complexity",
    options: [{ value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    id: "PR", label: "Privileges Required",
    options: [
      { value: "N", label: "None" },
      { value: "L", label: "Low" },
      { value: "H", label: "High" },
    ],
  },
  {
    id: "UI", label: "User Interaction",
    options: [{ value: "N", label: "None" }, { value: "R", label: "Required" }],
  },
  {
    id: "S", label: "Scope",
    options: [{ value: "U", label: "Unchanged" }, { value: "C", label: "Changed" }],
  },
  {
    id: "C", label: "Confidentiality",
    options: [{ value: "H", label: "High" }, { value: "L", label: "Low" }, { value: "N", label: "None" }],
  },
  {
    id: "I", label: "Integrity",
    options: [{ value: "H", label: "High" }, { value: "L", label: "Low" }, { value: "N", label: "None" }],
  },
  {
    id: "A", label: "Availability",
    options: [{ value: "H", label: "High" }, { value: "L", label: "Low" }, { value: "N", label: "None" }],
  },
];

// Weights from the v3.1 spec
const AV_W = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 } as const;
const AC_W = { L: 0.77, H: 0.44 } as const;
const PR_W_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 } as const;
const PR_W_CHANGED   = { N: 0.85, L: 0.68, H: 0.50 } as const;
const UI_W = { N: 0.85, R: 0.62 } as const;
const CIA_W = { H: 0.56, L: 0.22, N: 0.0 } as const;

export const DEFAULT_VECTOR: CvssVector = {
  AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H",
};

/** Map a numeric score to its severity bucket per the v3.1 rating scale. */
export function severityFromScore(score: number): "critical" | "high" | "medium" | "low" | "info" {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0)    return "low";
  return "info";
}

function roundUp(n: number): number {
  // Per spec: round-up to one decimal place (different from standard rounding).
  const i = Math.round(n * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

/** Compute base score from a vector. Returns 0 if any metric is invalid. */
export function calculateScore(v: CvssVector): number {
  const av = (AV_W as any)[v.AV];
  const ac = (AC_W as any)[v.AC];
  const pr = v.S === "C" ? (PR_W_CHANGED as any)[v.PR] : (PR_W_UNCHANGED as any)[v.PR];
  const ui = (UI_W as any)[v.UI];
  const c  = (CIA_W as any)[v.C];
  const i  = (CIA_W as any)[v.I];
  const a  = (CIA_W as any)[v.A];
  if (av == null || ac == null || pr == null || ui == null
      || c == null || i == null || a == null) return 0;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = v.S === "C"
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = v.S === "C"
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp(raw);
}

/** Build a canonical vector string from a CvssVector. */
export function vectorToString(v: CvssVector): string {
  return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`;
}

/**
 * Parse a CVSS v3.x vector string. Tolerant of stray whitespace and case;
 * returns null if any required metric is missing. Ignores Temporal/
 * Environmental modifiers if present.
 */
export function parseVector(s: string): CvssVector | null {
  const cleaned = s.trim().replace(/^CVSS:3\.[01]\//, "");
  const out: Partial<CvssVector> = {};
  for (const segment of cleaned.split("/")) {
    const [k, val] = segment.split(":");
    if (!k || !val) continue;
    if (["AV", "AC", "PR", "UI", "S", "C", "I", "A"].includes(k)) {
      (out as any)[k] = val.toUpperCase();
    }
    // Silently ignore Temporal (E/RL/RC) and Environmental (CR/IR/AR/MAV/...)
  }
  const required: Metric[] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  for (const m of required) {
    if (!(m in out)) return null;
  }
  return out as CvssVector;
}
