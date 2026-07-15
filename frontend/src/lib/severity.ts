/**
 * One home for finding-severity ordering, ranking, and the badge/text colour
 * classes. These were re-declared in four+ panels (problems, templates, scandiff,
 * search) — a byte-identical `SEV_CLASS` map in two, plus a text-only variant and
 * a `severityRank` in two more. The canonical ORDER is derived from
 * `FINDING_SEVERITIES` in lib/engagement, so adding a severity band updates every
 * consumer at once instead of silently disagreeing.
 */
import { FINDING_SEVERITIES, type FindingSeverity } from "./engagement";

/** critical → high → medium → low → info (the shared display/sort order). */
export const SEVERITY_ORDER: FindingSeverity[] = FINDING_SEVERITIES;

const RANK: Record<string, number> = Object.fromEntries(
  SEVERITY_ORDER.map((s, i) => [s, i]),
);

/** Sort rank; an unknown/malformed value sorts last (never ahead of a real one). */
export function severityRank(s: string | undefined): number {
  const r = RANK[(s ?? "").toLowerCase()];
  return r === undefined ? SEVERITY_ORDER.length : r;
}

// text + border, for a bordered badge. info/unknown falls back to muted.
const SEV_CLASS: Record<FindingSeverity, string> = {
  critical: "text-critical border-critical",
  high: "text-high border-high",
  medium: "text-medium border-medium",
  low: "text-low border-low",
  info: "text-ink-muted border-divider",
};

/** Badge classes (text + border colour) for a severity. */
export function severityClass(sev: string | undefined): string {
  return SEV_CLASS[(sev ?? "").toLowerCase() as FindingSeverity] ?? SEV_CLASS.info;
}

/** Just the text-colour class (no border), for inline severity text. */
export function severityTextClass(sev: string | undefined): string {
  return severityClass(sev).split(" ")[0];
}
