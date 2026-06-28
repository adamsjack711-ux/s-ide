// Shared severity / status / source presentation for the Findings triage view.
//
// Mirrors the design mockup's `sev` / `srcColors` / `statusColor` maps
// (~/s-ide/design/S-IDE.dc.js) but bound to the app's Tailwind tokens
// (severity `critical/high/medium/low`, accent green, ink-*).

import type { FindingSeverity, FindingStatus } from "../../lib/engagement";

/** Severity → mono PILL classes (bg tint + text + ring), matching design pillStyle. */
export const SEV_PILL: Record<FindingSeverity, string> = {
  critical: "bg-critical/[0.13] text-critical ring-1 ring-critical/30",
  high: "bg-high/[0.13] text-high ring-1 ring-high/30",
  medium: "bg-medium/[0.13] text-medium ring-1 ring-medium/30",
  low: "bg-low/[0.13] text-low ring-1 ring-low/30",
  info: "bg-bg-hover text-ink-muted ring-1 ring-divider",
};

/** Severity → the design's title-case label. */
export const SEV_LABEL: Record<FindingSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Severity → solid colour class for the facet swatch / chip fill. */
export const SEV_TEXT: Record<FindingSeverity, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-ink-muted",
};

export const SEV_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

/** Status → text colour (design: Fixed=low/blue, Triaging=accent, Open=dim). */
export const STATUS_TEXT: Record<FindingStatus, string> = {
  open: "text-ink-muted",
  confirmed: "text-accent",
  false_positive: "text-ink-dim",
  remediated: "text-low",
  // legacy
  triaged: "text-accent",
  fixed: "text-low",
  wont_fix: "text-ink-dim",
};

export function statusLabel(s: FindingStatus): string {
  return s.replace(/_/g, " ");
}

/** Map a tool name to a stable swatch colour, keyed like the design's srcColors. */
export function sourceSwatch(tool: string): string {
  const t = (tool || "").toLowerCase();
  if (/secret|trufflehog|gitleaks/.test(t)) return "bg-critical";
  if (/dep|npm|osv|sca|grype|trivy/.test(t)) return "bg-low";
  if (/cloud|aws|s3|prowler|scout/.test(t)) return "bg-accent";
  if (/nmap|recon|amass|subfinder|masscan/.test(t)) return "bg-high";
  if (/sast|semgrep|bandit|codeql/.test(t)) return "bg-medium";
  return "bg-ink-dim";
}
