/**
 * fixdiff/diffRender — PURE before/after diff computation + secret redaction.
 *
 * No network, no React, no imports of shared state. Given the "before" (the
 * vulnerable source that a finding's root cause lived in) and "after" (the
 * source that closed it), it produces a line-oriented diff and masks any secret
 * material in the rendered lines. The FixDiffPanel does the I/O (resolving the
 * anchor, reading the lab file, pulling the recorded before-snapshot) and hands
 * the two strings here; keeping the diff/redaction logic pure makes it testable
 * with fixture strings and guarantees no secret is ever rendered raw.
 *
 * SECURITY: `redactSecrets` runs on EVERY line before it is surfaced. It masks
 * bearer/authorization headers, cookies, API keys, and inline
 * password/token/secret assignments — matching the contract's T5 invariant that
 * a view must never render stored auth/session secrets, even when they leak into
 * evidence or source. Redaction is applied to the diff text we show, not to the
 * on-disk file (we never write).
 */

/** One line in a rendered diff. `context` = unchanged, present in both sides. */
export type DiffLineKind = "context" | "added" | "removed";

export interface DiffLine {
  kind: DiffLineKind;
  /** 1-based line number on the "before" side (null for added lines). */
  beforeNo: number | null;
  /** 1-based line number on the "after" side (null for removed lines). */
  afterNo: number | null;
  /** The line text, already secret-redacted. */
  text: string;
}

export interface DiffResult {
  lines: DiffLine[];
  addedCount: number;
  removedCount: number;
  /** True when before and after are byte-identical (no change to show). */
  unchanged: boolean;
}

// ── Secret redaction ─────────────────────────────────────────────────────────
// Masks any token/cookie/key/password on a line before it reaches the diff UI.
// One shared implementation (lib/redact); re-exported so this lane's import path
// and diffRender.test stay put.
import { redactSecrets } from "../../lib/redact";
export { redactSecrets };

// ── Diff computation ─────────────────────────────────────────────────────────

/** Split into lines without a trailing empty element for a final newline. */
function toLines(s: string): string[] {
  if (s === "") return [];
  const parts = s.replace(/\r\n?/g, "\n").split("\n");
  if (parts.length > 1 && parts[parts.length - 1] === "") parts.pop();
  return parts;
}

/**
 * Longest-common-subsequence table over the two line arrays. Classic O(n*m) DP —
 * inputs here are single source files, so this is comfortably fast and, unlike a
 * greedy line-by-line compare, produces a minimal, readable added/removed set.
 */
function lcs(a: string[], b: string[]): number[][] {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  return dp;
}

/**
 * Compute a line-oriented before→after diff, with every rendered line
 * secret-redacted. `before` is the vulnerable/original source, `after` the fixed
 * source. The result preserves order and carries per-side line numbers so the
 * panel can render a gutter.
 */
export function computeDiff(before: string, after: string): DiffResult {
  const a = toLines(before);
  const b = toLines(after);

  const dp = lcs(a, b);
  const lines: DiffLine[] = [];
  let i = 0;
  let j = 0;
  let addedCount = 0;
  let removedCount = 0;

  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      lines.push({ kind: "context", beforeNo: i + 1, afterNo: j + 1, text: redactSecrets(a[i]) });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      lines.push({ kind: "removed", beforeNo: i + 1, afterNo: null, text: redactSecrets(a[i]) });
      removedCount++;
      i++;
    } else {
      lines.push({ kind: "added", beforeNo: null, afterNo: j + 1, text: redactSecrets(b[j]) });
      addedCount++;
      j++;
    }
  }
  while (i < a.length) {
    lines.push({ kind: "removed", beforeNo: i + 1, afterNo: null, text: redactSecrets(a[i]) });
    removedCount++;
    i++;
  }
  while (j < b.length) {
    lines.push({ kind: "added", beforeNo: null, afterNo: j + 1, text: redactSecrets(b[j]) });
    addedCount++;
    j++;
  }

  return {
    lines,
    addedCount,
    removedCount,
    unchanged: addedCount === 0 && removedCount === 0,
  };
}
