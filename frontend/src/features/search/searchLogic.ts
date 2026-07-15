/**
 * F1 — Engagement-wide search: PURE logic (no network, no React).
 *
 * Everything here operates on arrays the panel has ALREADY fetched through the
 * read-only model API (shell/model.ts). Keeping the fuzzy match + grouping pure
 * makes it unit-testable (searchLogic.test.ts passes in fixtures — no backend)
 * and keeps the panel a thin fetch-and-render shell.
 *
 * A SearchRow is self-describing: it carries the display fields AND a `select`
 * descriptor that tells the panel exactly which canonical selection event to
 * publish when the row is clicked. The panel never re-derives that mapping.
 *
 * SECURITY: any text that may carry tool output / evidence / run output is run
 * through `redactSecrets` before it reaches a row's `snippet`, so a rendered
 * result can never leak an `Authorization:` header, cookie, token, or api key
 * (contract security invariant T5).
 */
import {
  toFindingRef, toAssetRef,
  type PairingFinding, type PairingRun, type Asset, type Step, type ConfLevel,
  type FindingRef, type AssetRef,
} from "../../shell/model";

// ── The five result groups ───────────────────────────────────────────────────

export type SearchGroupKind =
  | "findings" | "assets" | "evidence" | "output" | "code";

/** A code hit as returned by POST /codescan (already narrowed to what we show). */
export type CodeHit = {
  file: string;
  line: number;
  title: string;
  type: string;
  severity: string;
  snippet: string;
};

/** What publishing a row does — resolved by the panel into a bus emit. */
export type SearchSelect =
  | { kind: "finding"; ref: FindingRef }
  | { kind: "asset"; ref: AssetRef }
  | { kind: "step"; findingId: string; stepId: string }
  | { kind: "anchor"; file: string; line: number };

/** One clickable result. `score` drives intra-group ranking (higher = better). */
export type SearchRow = {
  id: string;            // stable within a render (group + underlying id)
  group: SearchGroupKind;
  title: string;         // primary line (already redacted where relevant)
  subtitle?: string;     // secondary line (tool / target / kind — redacted)
  snippet?: string;      // matched context (ALWAYS redacted)
  badge?: string;        // severity / status / kind chip
  conf?: ConfLevel;      // findings only — never upgrade suspected→confirmed
  score: number;
  select: SearchSelect;
};

export type SearchGroup = {
  kind: SearchGroupKind;
  label: string;
  rows: SearchRow[];
};

/** Already-fetched inputs. Each field is optional so a caller can omit a group
 *  it couldn't source (e.g. Code when the engagement has no source_root). */
export type SearchInputs = {
  findings?: PairingFinding[];
  /** Assets already resolved across the engagement's armed sub-targets. */
  assets?: Asset[];
  /** Evidence steps flattened across the engagement's findings, each tagged with
   *  its owning findingId (so a click can publish selectStep). */
  evidence?: { findingId: string; step: Step }[];
  runs?: PairingRun[];
  code?: CodeHit[];
};

const GROUP_LABELS: Record<SearchGroupKind, string> = {
  findings: "Findings",
  assets: "Assets",
  evidence: "Evidence",
  output: "Output",
  code: "Code",
};

// ── Secret redaction ─────────────────────────────────────────────────────────
// Applied to any output/evidence text before it becomes visible. Conservative:
// prefer over-masking. Order matters (header/cookie rules run before the generic
// key=value rule so the whole secret is caught, not just its tail).

const REDACTIONS: { re: RegExp; replace: string }[] = [
  // Authorization: Bearer xxx  /  Authorization: Basic xxx
  { re: /(authorization\s*:\s*)(bearer|basic|digest)\s+\S+/gi, replace: "$1$2 «redacted»" },
  { re: /(authorization\s*:\s*)\S+/gi, replace: "$1«redacted»" },
  // Cookie: a=b; c=d   and   Set-Cookie: ...
  { re: /((?:set-)?cookie\s*:\s*)[^\r\n]+/gi, replace: "$1«redacted»" },
  // token / api key / secret / password = "...."  (json or kv form)
  {
    re: /("?\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd|token)\b"?\s*[:=]\s*)("?)[^"'\s,}&]+/gi,
    replace: "$1$2«redacted»",
  },
  // AWS access key id
  { re: /AKIA[0-9A-Z]{16}/g, replace: "«redacted-aws-key»" },
  // long bearer-ish opaque strings (jwt / hex / base64 >= 24 chars, standalone)
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, replace: "«redacted-jwt»" },
];

export function redactSecrets(text: string | null | undefined): string {
  if (!text) return "";
  let out = String(text);
  for (const { re, replace } of REDACTIONS) out = out.replace(re, replace);
  return out;
}

// ── Fuzzy matching ───────────────────────────────────────────────────────────
// Deterministic, cheap, dependency-free. Scoring, best-to-worst:
//   exact substring (word-boundary) > exact substring > subsequence match.
// Longer matched runs and earlier positions score higher. Returns 0 for no
// match so callers can drop the row.

export function fuzzyScore(query: string, text: string | null | undefined): number {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const t = (text ?? "").toLowerCase();
  if (!t) return 0;

  const idx = t.indexOf(q);
  if (idx >= 0) {
    // Substring hit. Base 100; bonus for word-boundary start and early position.
    const boundary = idx === 0 || /[^a-z0-9]/.test(t[idx - 1]) ? 40 : 0;
    const position = Math.max(0, 30 - idx); // earlier is better
    const whole = t.length === q.length ? 30 : 0;
    return 100 + boundary + position + whole;
  }

  // Subsequence: all query chars appear in order. Reward contiguous runs.
  let ti = 0;
  let matched = 0;
  let runs = 0;
  let inRun = false;
  for (let qi = 0; qi < q.length && ti < t.length; ) {
    if (t[ti] === q[qi]) {
      matched++;
      if (!inRun) { runs++; inRun = true; }
      qi++;
      ti++;
    } else {
      inRun = false;
      ti++;
    }
  }
  if (matched < q.length) return 0; // not all chars found → no match
  // Fewer runs = more contiguous = better. Base 20 so any subsequence ranks
  // below every substring hit.
  return 20 + Math.max(0, 12 - runs * 2);
}

/** Best score across several candidate fields (undefined/empty fields ignored). */
export function bestFieldScore(query: string, fields: (string | null | undefined)[]): number {
  let best = 0;
  for (const f of fields) {
    const s = fuzzyScore(query, f);
    if (s > best) best = s;
  }
  return best;
}

// ── Grouping ─────────────────────────────────────────────────────────────────

function confOf(status: string): ConfLevel {
  return status === "confirmed" ? "confirmed" : "suspected";
}

function firstNonEmpty(...xs: (string | undefined)[]): string | undefined {
  for (const x of xs) if (x && x.trim()) return x;
  return undefined;
}

const PER_GROUP_CAP = 50;

/**
 * Group + rank already-fetched arrays against a query. Empty/blank query yields
 * no groups (the panel shows its prompt). Each group is sorted by score desc,
 * then by a stable secondary key, and capped so a huge engagement can't produce
 * an unbounded list.
 */
export function groupSearch(query: string, inputs: SearchInputs): SearchGroup[] {
  const q = query.trim();
  if (!q) return [];

  const groups: SearchGroup[] = [];

  // 1. Findings — title / description / tool / target.
  if (inputs.findings?.length) {
    const rows: SearchRow[] = [];
    for (const f of inputs.findings) {
      const score = bestFieldScore(q, [f.title, f.description, f.tool, f.target]);
      if (score <= 0) continue;
      const ref: FindingRef = toFindingRef(f);
      rows.push({
        id: `finding:${f.id}`,
        group: "findings",
        title: f.title || "(untitled finding)",
        subtitle: firstNonEmpty(
          [f.tool, f.target].filter(Boolean).join(" · ") || undefined,
        ),
        snippet: redactSecrets(f.description).slice(0, 240) || undefined,
        badge: f.severity,
        conf: confOf(f.status),
        score,
        select: { kind: "finding", ref },
      });
    }
    pushGroup(groups, "findings", rows);
  }

  // 2. Assets — kind / key / props.
  if (inputs.assets?.length) {
    const rows: SearchRow[] = [];
    for (const a of inputs.assets) {
      const propsText = safeStringify(a.props);
      const score = bestFieldScore(q, [a.kind, a.key, propsText, a.tool]);
      if (score <= 0) continue;
      const ref: AssetRef = toAssetRef(a);
      rows.push({
        id: `asset:${a.subTargetId}:${a.assetId}`,
        group: "assets",
        title: a.key || a.assetId,
        subtitle: firstNonEmpty(a.tool || undefined),
        snippet: redactSecrets(propsText).slice(0, 240) || undefined,
        badge: a.kind,
        score,
        select: { kind: "asset", ref },
      });
    }
    pushGroup(groups, "assets", rows);
  }

  // 3. Evidence — a step's raw output / interpretation (redacted).
  if (inputs.evidence?.length) {
    const rows: SearchRow[] = [];
    for (const { findingId, step } of inputs.evidence) {
      const raw = typeof step.evidence?.raw_output === "string" ? step.evidence.raw_output : "";
      const interp = step.interpretation ?? "";
      const toolId = step.action?.tool_id ?? "";
      const score = bestFieldScore(q, [interp, raw, toolId]);
      if (score <= 0) continue;
      const snippetSource = firstNonEmpty(interp, raw) ?? "";
      rows.push({
        id: `evidence:${findingId}:${step.id}`,
        group: "evidence",
        title: firstNonEmpty(interp && interp.slice(0, 120), toolId, `step ${step.ordinal}`)!,
        subtitle: toolId ? `via ${toolId}` : undefined,
        snippet: redactSecrets(snippetSource).slice(0, 240) || undefined,
        badge: step.anchored ? "anchored" : undefined,
        score,
        select: { kind: "step", findingId, stepId: step.id },
      });
    }
    pushGroup(groups, "evidence", rows);
  }

  // 4. Output — run output / summary (redacted). A run has no selection ref of
  //    its own; we anchor to its owning finding when we can't, we still surface
  //    it read-only. Since runs aren't in the selection vocabulary, an Output
  //    row publishes the sub-target's first finding? No — keep it honest: Output
  //    rows carry a step-less anchor only when the run text has a file:line.
  if (inputs.runs?.length) {
    const rows: SearchRow[] = [];
    for (const r of inputs.runs) {
      const score = bestFieldScore(q, [r.summary, r.output, r.tool]);
      if (score <= 0) continue;
      const text = firstNonEmpty(r.summary, r.output) ?? "";
      const anchor = extractFileLine(`${r.summary ?? ""}\n${r.output ?? ""}`);
      rows.push({
        id: `run:${r.id}`,
        group: "output",
        title: firstNonEmpty(r.summary && r.summary.slice(0, 120), r.tool, `run ${r.id}`)!,
        subtitle: firstNonEmpty([r.tool, r.status].filter(Boolean).join(" · ") || undefined),
        snippet: redactSecrets(text).slice(0, 240) || undefined,
        badge: r.status,
        score,
        // Runs are not a selection primitive. If the output names a source
        // location, clicking jumps there; otherwise the row is display-only
        // (select still present but points at any file:line found).
        select: anchor
          ? { kind: "anchor", file: anchor.file, line: anchor.line }
          : { kind: "anchor", file: "", line: 0 },
      });
    }
    pushGroup(groups, "output", rows);
  }

  // 5. Code — SAST hits from POST /codescan (only present when source_root set).
  if (inputs.code?.length) {
    const rows: SearchRow[] = [];
    for (const c of inputs.code) {
      const score = bestFieldScore(q, [c.title, c.type, c.file, c.snippet]);
      if (score <= 0) continue;
      rows.push({
        id: `code:${c.file}:${c.line}:${c.title}`,
        group: "code",
        title: c.title,
        subtitle: `${c.file}:${c.line}`,
        snippet: redactSecrets(c.snippet).slice(0, 240) || undefined,
        badge: c.severity,
        score,
        select: { kind: "anchor", file: c.file, line: c.line },
      });
    }
    pushGroup(groups, "code", rows);
  }

  return groups;
}

function pushGroup(out: SearchGroup[], kind: SearchGroupKind, rows: SearchRow[]): void {
  if (!rows.length) return;
  rows.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  out.push({ kind, label: GROUP_LABELS[kind], rows: rows.slice(0, PER_GROUP_CAP) });
}

/** Total rows across all groups — the panel uses this to pick the empty state. */
export function countRows(groups: SearchGroup[]): number {
  return groups.reduce((n, g) => n + g.rows.length, 0);
}

// The file part must look like a real path (contain a `/`, or end in an allow-
// listed source extension) so a bare `host:port` token in run output isn't mis-
// read as a source location. KEEP IN SYNC with the identical regex in shell/model.ts.
const FILE_LINE_RE =
  /((?:[\w.~-]*\/[\w./~-]+)|(?:[\w.~-]+\.(?:tsx?|jsx?|mjs|cjs|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|cs|kt|swift|scala|sh|sql|html?|css|scss|less|json|ya?ml|toml|ini|cfg|conf|xml|vue|svelte|md))):(\d+)/i;

export function extractFileLine(hay: string): { file: string; line: number } | null {
  const m = FILE_LINE_RE.exec(hay);
  return m ? { file: m[1], line: Number(m[2]) } : null;
}

function safeStringify(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
