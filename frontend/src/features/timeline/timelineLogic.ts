/**
 * timelineLogic — pure, deterministic normalization + redaction + sort for the
 * Engagement Timeline (F6). READ-ONLY over the append-only audit/evidence ledger.
 *
 * No network, no React, no bus. Everything here operates on already-fetched
 * `AuditEntry` rows (the permissive projection from shell/model.ts) so it can be
 * unit-tested with fixtures. The panel does the reads (`listAudit`), hands the
 * raw rows here to be normalized/redacted/sorted, and renders the result.
 *
 * SECURITY INVARIANT (CONTRACT.md T5): any human-readable text that ends up on
 * screen (label, detail, target) is passed through `redactSecrets()` first —
 * tokens, keys, cookies, and `Authorization:` headers are masked. The backend
 * already redacts argv on the way in, but summary/target/error are NOT redacted
 * server-side, so we redact defensively here. This module NEVER mutates the
 * ledger and NEVER upgrades anything — it only reads, labels, masks, and orders.
 */
import type { AuditEntry } from "../../shell/model";

/** The coarse kind we classify each ledger row into, for labelling + routing. */
export type TimelineKind =
  | "run"          // a tool invocation (started/completed/error/stopped)
  | "finding"      // a finding was created / promoted
  | "arm"          // a sub-target was armed
  | "disarm"       // a sub-target was disarmed
  | "attestation"  // an attestation was recorded
  | "state"        // an engagement/sub-target state change
  | "event";       // anything else — still rendered, never dropped

/** The run/entry status, normalized to the ledger's known set (permissive). */
export type TimelineStatus =
  | "started" | "completed" | "error" | "stopped" | "refused" | "unknown";

/**
 * A normalized, render-ready timeline entry. Derived purely from an AuditEntry.
 * `ts` is the epoch-ms used for ordering (NaN-safe: unparseable → 0 so a bad row
 * sinks to the start rather than crashing the sort). `iso` is the original
 * timestamp string for display. All text fields are already redacted.
 */
export type TimelineEntry = {
  id: string;
  kind: TimelineKind;
  status: TimelineStatus;
  /** Short human label, e.g. "Finding created", "port_scanner — completed". */
  label: string;
  /** Longer redacted detail (summary/error/target), may be empty. */
  detail: string;
  /** Redacted target string, may be empty. */
  target: string;
  /** Epoch-ms for sorting. 0 when the row has no parseable timestamp. */
  ts: number;
  /** Original timestamp string for display (best available), may be empty. */
  iso: string;
  /** A finding id if this row references one (drives selectFinding). */
  findingId?: string;
  /** A sub-target id if this row references one (drives selectSubTarget). */
  subTargetId?: string;
  /** The raw row kept for the panel's expand/debug view (not rendered raw). */
  raw: AuditEntry;
};

// ── Redaction ────────────────────────────────────────────────────────────────
// The ledger's argv is already redacted server-side; this covers free-text
// fields (summary, target, error) that are NOT. One shared implementation
// (lib/redact); re-exported so this lane's import path and timelineLogic.test
// stay put.
import { redactSecrets } from "../../lib/redact";
export { redactSecrets };

// ── Timestamp parsing ────────────────────────────────────────────────────────

/**
 * The row's best display timestamp string — prefers an explicit end time
 * (`ts_end`/`ended_at`) when present, else the start (`ts_start`/`started_at`),
 * else the permissive `ts`/`iso`. Returns "" when the row has none.
 */
export function pickIso(row: AuditEntry): string {
  const cand = [
    row.ts_end, row.ended_at, row.ts_start, row.started_at, row.ts, row.iso,
  ];
  for (const c of cand) {
    if (typeof c === "string" && c.trim()) return c;
  }
  return "";
}

/** Epoch-ms for ordering; 0 (not NaN) when unparseable so sorting is total. */
export function toEpoch(iso: string): number {
  if (!iso) return 0;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
}

// ── Classification + reference extraction ─────────────────────────────────────

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/** Normalize the row status to the known set; unknown → "unknown". */
export function normalizeStatus(raw: unknown): TimelineStatus {
  switch (str(raw)) {
    case "started": return "started";
    case "completed": return "completed";
    case "error": return "error";
    case "stopped": return "stopped";
    case "refused": return "refused";
    default: return "unknown";
  }
}

/** Pull a finding id from any of the permissive field spellings, if present. */
export function extractFindingId(row: AuditEntry): string | undefined {
  const cand =
    row.finding_id ?? row.findingId ?? (row as Record<string, unknown>).finding;
  const s = str(cand);
  return s || undefined;
}

/** Pull a sub-target id from any of the permissive field spellings, if present. */
export function extractSubTargetId(row: AuditEntry): string | undefined {
  const cand = row.sub_target_id ?? row.subTargetId ?? row.subtarget_id;
  const s = str(cand);
  return s || undefined;
}

/**
 * Classify a row into a TimelineKind from its `tool`/action fields. Heuristic
 * and permissive: a row we can't classify becomes an "event" (rendered, never
 * dropped). Precedence: an explicit finding reference > tool-name keyword match.
 */
export function classify(row: AuditEntry): TimelineKind {
  const tool = str(row.tool).toLowerCase();
  const action = str((row as Record<string, unknown>).action).toLowerCase();
  const kind = str((row as Record<string, unknown>).kind).toLowerCase();
  const hay = `${tool} ${action} ${kind}`;

  if (extractFindingId(row) || /finding|promote/.test(hay)) return "finding";
  if (/\bdisarm/.test(hay)) return "disarm";
  if (/\barm\b|\barmed\b|arming/.test(hay)) return "arm";
  if (/attest/.test(hay)) return "attestation";
  if (/state|status[_-]?change|transition/.test(hay)) return "state";
  // Anything with a tool name is a tool run; otherwise a generic event.
  if (tool) return "run";
  return "event";
}

const KIND_LABEL: Record<TimelineKind, string> = {
  run: "Run",
  finding: "Finding created",
  arm: "Sub-target armed",
  disarm: "Sub-target disarmed",
  attestation: "Attestation",
  state: "State change",
  event: "Activity",
};

/** Human label for a normalized entry (redacted-safe — built from safe pieces). */
export function deriveLabel(kind: TimelineKind, tool: string, status: TimelineStatus): string {
  const base = KIND_LABEL[kind];
  if (kind === "run" && tool) {
    return status === "unknown" ? tool : `${tool} — ${status}`;
  }
  if (tool && kind !== "finding") return `${base}: ${tool}`;
  return base;
}

// ── Normalization ─────────────────────────────────────────────────────────────

/** Normalize one raw audit row into a render-ready, redacted TimelineEntry. */
export function normalizeEntry(row: AuditEntry): TimelineEntry {
  const kind = classify(row);
  const status = normalizeStatus(row.status);
  const tool = str(row.tool);
  const iso = pickIso(row);
  const target = redactSecrets(row.target);
  const summary = redactSecrets(row.summary);
  const error = redactSecrets((row as Record<string, unknown>).error);
  const detail = [summary, error].filter(Boolean).join(" · ");

  return {
    id: str(row.id) || `${tool}:${iso}:${Math.random().toString(36).slice(2, 8)}`,
    kind,
    status,
    label: redactSecrets(deriveLabel(kind, tool, status)),
    detail,
    target,
    ts: toEpoch(iso),
    iso,
    findingId: extractFindingId(row),
    subTargetId: extractSubTargetId(row),
    raw: row,
  };
}

/**
 * The one-shot pipeline the panel calls: normalize every row, redact, then sort
 * chronologically. `order` defaults to "asc" (oldest→newest, the natural reading
 * order for a timeline); pass "desc" to keep the ledger's newest-first order.
 * The sort is STABLE within equal timestamps (preserves the backend order, which
 * for equal `ts` is newest-first from the API) and total (bad timestamps → 0).
 */
export function buildTimeline(
  rows: AuditEntry[],
  order: "asc" | "desc" = "asc",
): TimelineEntry[] {
  const entries = rows.map(normalizeEntry);
  const dir = order === "asc" ? 1 : -1;
  return entries
    .map((e, i) => ({ e, i }))
    .sort((a, b) => {
      const d = (a.e.ts - b.e.ts) * dir;
      return d !== 0 ? d : a.i - b.i;
    })
    .map((x) => x.e);
}
