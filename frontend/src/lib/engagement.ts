// Active-engagement state.
//
// "Active engagement" is a per-window choice (persisted to localStorage)
// that drives auto-recording of scan results. When set, every successful
// api() call AND every useAttackWS done-event POSTs to
// /engagements/{id}/results.
//
// The engagement *list* itself lives on the backend (SQLite). This module
// only stores which one is currently focused.

import { useEffect, useState } from "react";
import { authFetch, BACKEND_URL, parseError } from "../api";
import { getMode } from "./mode";
import { emit } from "../shell/bus";

export type EngagementStatus = "active" | "completed" | "archived";

// What the engagement hooks onto. `generic` is the legacy/untyped value used
// by the quick-create paths; the typed-create flow sets local-app / web-app.
// `host` is reserved for a future third type.
export type EngagementType = "generic" | "local-app" | "web-app" | "host";

// Provenance drives the safety mode (owned/lab = full, external = gated).
export type EngagementProvenance = "lab" | "owned" | "external";

export type Engagement = {
  id: string;
  name: string;
  scope: string[];
  exclusions: string[];
  notes: string;
  status: EngagementStatus;
  type: EngagementType;
  provenance: EngagementProvenance;
  source_root: string;
  primary_target: string;
  created_at: string;
  updated_at: string;
};

// ── Engagement auth (web-app, optional) ─────────────────────────────────────
// Secret material travels OUT to the backend on create / PUT only; it is
// encrypted server-side and never returned. Reads come back as a redacted
// reference (kind + a non-secret hint), never the secret itself.

export type AuthKind = "none" | "cookie" | "bearer" | "credentials";

export type EngagementAuthInput = {
  kind: AuthKind;
  cookie?: string;    // kind=cookie: Cookie header to replay
  token?: string;     // kind=bearer: bearer token to replay
  username?: string;  // kind=credentials
  password?: string;  // kind=credentials
  login_url?: string; // kind=credentials: login form URL
};

// Redacted reference returned by the backend — never carries secret material.
export type EngagementAuthMeta = {
  kind: AuthKind;
  has_secret: boolean;
  last4?: string;     // bearer / cookie
  username?: string;  // credentials (identity, shown)
  login_url?: string; // credentials
};

// Canonical Findings Tracker statuses + the legacy set so older DBs keep
// loading. New writes from the tracker emit only the canonical values.
export type FindingStatus =
  | "open" | "confirmed" | "false_positive" | "remediated"
  | "triaged" | "fixed" | "wont_fix";

export const FINDING_STATUSES: FindingStatus[] = [
  "open", "confirmed", "false_positive", "remediated",
];

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export const FINDING_SEVERITIES: FindingSeverity[] = [
  "critical", "high", "medium", "low", "info",
];

export type Finding = {
  id: string;
  engagement_id: string;
  ts: string;
  updated_at: string;
  title: string;
  severity: FindingSeverity;
  cvss: number | null;
  cvss_vector: string | null;
  tool: string;
  target: string;
  description: string;
  evidence: string;
  ai_summary: string;
  linked_result_id: string | null;
  status: FindingStatus;
};

export type ScanResult = {
  id: string;
  ts: string;
  tool: string;
  target: string;
  summary: string;
};

// ── Active engagement state ─────────────────────────────────────────────────

const ACTIVE_KEY = "mhp:active-engagement:v1";

let activeId: string | null = null;
try { activeId = localStorage.getItem(ACTIVE_KEY); } catch { /* ignore */ }

const listeners = new Set<() => void>();
function notify() { for (const l of listeners) l(); }

export function getActiveEngagementId(): string | null {
  return activeId;
}

/**
 * True if an engagement belongs to the Labs/training surface, not the real
 * engagement workspace. Lab attaches now tag provenance "lab", but older
 * auto-created ones (named "Lab: <name>") predate that, so we catch both.
 * Used to keep labs OUT of every engagement list (Learning is their home).
 */
export function isLabEngagement(e: { provenance?: string; name?: string }): boolean {
  return e.provenance === "lab" || /^lab:\s/i.test(e.name ?? "");
}

export function setActiveEngagementId(id: string | null): void {
  if (id === activeId) return; // no-op: don't churn listeners / the bus
  activeId = id;
  try {
    if (id) localStorage.setItem(ACTIVE_KEY, id);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch { /* quota */ }
  notify();
  // Broadcast so non-hook subscribers (the spine surfaces, the StatusBar, the
  // Workbench) re-scope to the new engagement. Hook consumers re-render via
  // notify() above; the bus event covers everything else.
  emit("activeEngagementChanged", { engagementId: id });
}

export function useActiveEngagementId(): string | null {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((n) => n + 1);
    listeners.add(fn);
    return () => { listeners.delete(fn); };
  }, []);
  return activeId;
}

// ── Auto-record ─────────────────────────────────────────────────────────────

const RECORD_SKIP = [
  /^\/health/, /^\/chat\//, /^\/settings\//, /^\/system\//,
  /^\/engagements/,
];

/**
 * Best-effort fire-and-forget POST of a scan result to the active engagement.
 * Returns silently on any failure (network / 404 / 5xx) — auto-recording must
 * never block the actual scan flow.
 *
 * Lab mode suppresses auto-record even when an engagement is active, so
 * ad-hoc experiments don't pollute an authorized engagement's timeline.
 */
export async function recordResultIfActive(
  toolPath: string, target: string, summary: string, raw: unknown,
): Promise<void> {
  if (getMode() !== "engagement") return;
  const eid = activeId;
  if (!eid) return;
  if (RECORD_SKIP.some((re) => re.test(toolPath))) return;
  try {
    await authFetch(`/engagements/${eid}/results`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tool: toolPath,
        target: target.slice(0, 500),
        summary: summary.slice(0, 4000),
        raw,
      }),
    });
  } catch {
    /* best-effort */
  }
}

// ── CRUD helpers (light wrappers — pages use these directly) ────────────────

export async function listEngagements(includeArchived = false): Promise<Engagement[]> {
  const r = await authFetch(`/engagements?include_archived=${includeArchived}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = (await r.json()) as { engagements: Engagement[] };
  return body.engagements;
}

export type CreateEngagementInput = {
  name: string;
  scope?: string[];
  exclusions?: string[];
  notes?: string;
  type?: EngagementType;
  provenance?: EngagementProvenance;
  source_root?: string;        // local-app
  targets?: string[];          // web-app (first = primary target)
  auth?: EngagementAuthInput;  // web-app, optional
};

// The create response is the engagement plus two create-time extras: the id of
// the registered primary target (so the caller can pin it active) and the
// redacted auth reference (never the secret).
export type CreatedEngagement = Engagement & {
  primary_target_id: string | null;
  auth: EngagementAuthMeta | null;
};

export async function createEngagement(
  payload: CreateEngagementInput,
): Promise<CreatedEngagement> {
  const r = await authFetch(`/engagements`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scope: [],
      exclusions: [],
      notes: "",
      ...payload,
    }),
  });
  if (!r.ok) throw new Error(await parseError(r));
  const created: CreatedEngagement = await r.json();
  // Signal the model so any engagement snapshot re-reads (the list changed).
  emit("modelChanged", { entity: "engagement", id: created.id, op: "create" });
  return created;
}

// ── Engagement auth (redacted reads + writes) ───────────────────────────────

export async function getEngagementAuth(
  eid: string,
): Promise<EngagementAuthMeta | null> {
  const r = await authFetch(`/engagements/${eid}/auth`);
  if (!r.ok) throw new Error(await parseError(r));
  return (await r.json()).auth ?? null;
}

export async function setEngagementAuth(
  eid: string, auth: EngagementAuthInput,
): Promise<EngagementAuthMeta | null> {
  const r = await authFetch(`/engagements/${eid}/auth`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(auth),
  });
  if (!r.ok) throw new Error(await parseError(r));
  return (await r.json()).auth ?? null;
}

export async function deleteEngagementAuth(eid: string): Promise<void> {
  const r = await authFetch(`/engagements/${eid}/auth`, { method: "DELETE" });
  if (!r.ok) throw new Error(await parseError(r));
}

export async function updateEngagement(
  id: string, patch: Partial<Engagement>,
): Promise<Engagement> {
  const r = await authFetch(`/engagements/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const updated: Engagement = await r.json();
  emit("modelChanged", { entity: "engagement", id, op: "update" });
  return updated;
}

export async function deleteEngagement(id: string): Promise<void> {
  const r = await authFetch(`/engagements/${id}`, { method: "DELETE" });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  emit("modelChanged", { entity: "engagement", id, op: "delete" });
}

export async function listFindings(eid: string): Promise<Finding[]> {
  // Prefer the standalone /findings tracker endpoint so list shape and
  // statuses stay consistent with promote-flow writes. Falls back to the
  // per-engagement nested endpoint if the tracker isn't registered yet.
  try {
    const r = await authFetch(`/findings?engagement_id=${encodeURIComponent(eid)}`);
    if (r.ok) {
      const body = (await r.json()) as { findings: Finding[] };
      return body.findings;
    }
  } catch {
    /* fall through */
  }
  const r = await authFetch(`/engagements/${eid}/findings`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = (await r.json()) as { findings: Finding[] };
  return body.findings;
}

// ── Findings Tracker (standalone /findings endpoint) ────────────────────────
//
// Every write here is audited server-side. Promote-from-result flows on
// tool pages should call promoteToFinding(...) rather than the per-engagement
// createFinding(...) so the tracker stays the single ingress for new
// evidence.

export type PromoteFindingInput = {
  engagement_id: string;
  title: string;
  severity: FindingSeverity;
  description?: string;
  tool?: string;
  target?: string;
  evidence?: string;
  cvss?: number | null;
  cvss_vector?: string | null;
  linked_result_id?: string | null;
  status?: FindingStatus;
};

export async function promoteToFinding(input: PromoteFindingInput): Promise<Finding> {
  const r = await authFetch(`/findings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!r.ok) throw new Error(await parseError(r));
  const f = (await r.json()) as Finding;
  // Unified refresh signal for every feature view (see shell/model.ts). The
  // legacy findingsChanged stays for existing panels.
  emit("modelChanged", { entity: "finding", id: f.id, op: "create" });
  emit("findingsChanged", {});
  return f;
}

export async function patchTrackedFinding(
  fid: string, patch: Partial<Finding>,
): Promise<Finding> {
  const r = await authFetch(`/findings/${fid}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!r.ok) throw new Error(await parseError(r));
  const f = (await r.json()) as Finding;
  emit("modelChanged", { entity: "finding", id: f.id, op: "update" });
  emit("findingsChanged", {});
  return f;
}

export async function deleteTrackedFinding(fid: string): Promise<void> {
  const r = await authFetch(`/findings/${fid}`, { method: "DELETE" });
  if (!r.ok) throw new Error(await parseError(r));
  emit("modelChanged", { entity: "finding", id: fid, op: "delete" });
  emit("findingsChanged", {});
}

// ── Evidence (multi-item, per-finding) ──────────────────────────────────────

export const EVIDENCE_TYPES = [
  "scan_output", "request_response", "screenshot_ref", "note", "command",
] as const;

export type EvidenceType = typeof EVIDENCE_TYPES[number];

export type Evidence = {
  id: string;
  finding_id: string;
  type: EvidenceType;
  content: string;
  source_tool: string | null;
  captured_at: string;   // observation time
  created_at: string;    // write time
};

export type EvidenceCreate = {
  type: EvidenceType;
  content?: string;
  source_tool?: string | null;
  captured_at?: string | null;
};

export async function listEvidence(fid: string): Promise<Evidence[]> {
  const r = await authFetch(`/findings/${fid}/evidence`);
  if (!r.ok) throw new Error(await parseError(r));
  const body = (await r.json()) as { items: Evidence[] };
  return body.items;
}

export async function addEvidence(
  fid: string, payload: EvidenceCreate,
): Promise<Evidence> {
  const r = await authFetch(`/findings/${fid}/evidence`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(await parseError(r));
  return r.json();
}

export async function deleteEvidence(
  fid: string, eid: string,
): Promise<void> {
  const r = await authFetch(`/findings/${fid}/evidence/${eid}`, {
    method: "DELETE",
  });
  if (!r.ok) throw new Error(await parseError(r));
}

// ── CVSS scoring ────────────────────────────────────────────────────────────

export type CvssCalculated = {
  base_score: number;
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  vector: string;
};

/**
 * Server-side CVSS v3.1 verification. The calculator does its own client-side
 * math for live feedback; this helper is for the save path to confirm the
 * formula matches the backend before persistence (and to canonicalise the
 * vector string from a partial input).
 */
export async function cvssCalculate(vector: string): Promise<CvssCalculated> {
  const r = await authFetch(`/cvss/calculate?vector=${encodeURIComponent(vector)}`);
  if (!r.ok) throw new Error(await parseError(r));
  return r.json();
}

/**
 * Apply a CVSS v3.1 score to a finding. Persists `cvss` + `cvss_vector` and
 * bumps the finding's severity to match the band — the CVSS band is the
 * single source of truth for the badge once a finding is scored.
 */
export async function scoreFindingCvss(
  fid: string, vector: string,
): Promise<Finding> {
  const r = await authFetch(`/findings/${fid}/cvss`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vector }),
  });
  if (!r.ok) throw new Error(await parseError(r));
  const f = (await r.json()) as Finding;
  emit("modelChanged", { entity: "finding", id: f.id, op: "update" });
  emit("findingsChanged", {});
  return f;
}

/**
 * Generate an AI summary of the finding's evidence and persist it to
 * `ai_summary` on the finding row. Returns the updated finding.
 *
 * Synchronous on the backend — the call usually takes a few seconds while
 * Claude responds. PromoteToFindingButton calls this fire-and-forget after
 * a successful promote; the Findings detail page calls it explicitly when
 * the user clicks "Generate AI summary" on a finding that doesn't have one.
 */
export async function summarizeFinding(fid: string): Promise<Finding> {
  const r = await authFetch(`/findings/${fid}/ai-summary`, { method: "POST" });
  if (!r.ok) throw new Error(await parseError(r));
  return r.json();
}

export async function createFinding(eid: string, payload: {
  title: string; severity: Finding["severity"]; description?: string;
  evidence?: string; cvss?: number | null; linked_result_id?: string | null;
}): Promise<Finding> {
  const r = await authFetch(`/engagements/${eid}/findings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(await parseError(r));
  return r.json();
}

export async function updateFinding(
  eid: string, fid: string, patch: Partial<Finding>,
): Promise<Finding> {
  const r = await authFetch(`/engagements/${eid}/findings/${fid}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function deleteFinding(eid: string, fid: string): Promise<void> {
  const r = await authFetch(`/engagements/${eid}/findings/${fid}`, {
    method: "DELETE",
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
}

export async function listResults(eid: string, limit = 200): Promise<ScanResult[]> {
  const r = await authFetch(`/engagements/${eid}/results?limit=${limit}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = (await r.json()) as { results: ScanResult[] };
  return body.results;
}

export async function fetchSuggestions(): Promise<
  { category: string; label: string; description: string }[]
> {
  const r = await authFetch(`/engagements/_catalog/suggestions`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = (await r.json()) as { suggestions: { category: string; label: string; description: string }[] };
  return body.suggestions;
}

// Report links — short-lived one-shot URLs for the system browser.
//
// We used to embed the long-lived per-launch auth token directly in
// `?token=…` so an `<a target="_blank">` could open the report in the OS
// browser. That leaked the token into browser history, Referer headers,
// and DevTools panels — and the same token authorises /terminal/exec.
//
// Instead, we POST to backend to mint a 30-second, path-bound, single-use
// nonce. The renderer then `window.open()`s the returned URL. Even if the
// nonce lands in browser history it's burned and expired within seconds.

async function _mintLink(path: string): Promise<string> {
  const r = await authFetch(path, { method: "POST" });
  if (!r.ok) throw new Error(await parseError(r));
  const body = (await r.json()) as { url: string };
  return `${BACKEND_URL}${body.url}`;
}

export function requestReportLink(eid: string, format: "html" | "md"): Promise<string> {
  return _mintLink(`/engagements/${eid}/report-link?format=${format}`);
}

// ── Report snapshots ────────────────────────────────────────────────────────

export type ReportSnapshotMeta = {
  id: string;
  ts: string;
  rollup_preview: string;
  html_bytes: number;
  md_bytes: number;
};

export function requestSnapshotLink(
  eid: string, sid: string, format: "html" | "md",
): Promise<string> {
  return _mintLink(
    `/engagements/${eid}/report-link` +
    `?format=${format}&snapshot_id=${encodeURIComponent(sid)}`,
  );
}

export async function listReportSnapshots(
  eid: string,
): Promise<ReportSnapshotMeta[]> {
  const r = await authFetch(`/engagements/${eid}/reports`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = (await r.json()) as { snapshots: ReportSnapshotMeta[] };
  return body.snapshots ?? [];
}

export async function generateReportSnapshot(
  eid: string,
): Promise<ReportSnapshotMeta> {
  const r = await authFetch(`/engagements/${eid}/report/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!r.ok) {
    let detail = `HTTP ${r.status}`;
    try { detail = (await parseError(r)) || detail; } catch { /* ignore */ }
    throw new Error(detail);
  }
  return (await r.json()) as ReportSnapshotMeta;
}

export async function deleteReportSnapshot(
  eid: string, sid: string,
): Promise<void> {
  const r = await authFetch(`/engagements/${eid}/reports/${sid}`,
    { method: "DELETE" });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
}

// ── Engagement report exporter (markdown + PDF + preview) ───────────────────
//
// Distinct from the legacy snapshot/rollup flow above. The new exporter
// renders directly from findings + CVSS + evidence; the executive summary
// is template-based so reports work without an API key. Backend routes
// live under /reports/engagement/{eid}.

export type EngagementReportFinding = {
  id: string;
  title: string;
  severity: FindingSeverity;
  status: string;
  tool: string;
  target: string;
  description: string;
  cvss: number | null;
  cvss_vector: string | null;
  ai_summary: string;
  captured_at: string;
  evidence: Evidence[];
};

export type EngagementReport = {
  header: {
    engagement_id: string;
    engagement_name: string;
    scope: string[];
    exclusions: string[];
    notes: string;
    status: string;
    date_from: string;
    date_to: string;
    operator: string;
    generated_at: string;
  };
  exec_summary: {
    counts: Record<string, number>;
    total: number;
    summary: string;
  };
  findings: EngagementReportFinding[];
  methodology: string;
  disclaimer: string;
};

export async function fetchReportPreview(eid: string): Promise<EngagementReport> {
  const r = await authFetch(`/reports/engagement/${eid}/preview`);
  if (!r.ok) throw new Error(await parseError(r));
  return r.json();
}

export function requestExportLink(
  eid: string, format: "markdown" | "pdf",
): Promise<string> {
  return _mintLink(`/reports/engagement/${eid}/link?format=${format}`);
}

// ── Coverage matrix ─────────────────────────────────────────────────────────
// "What's been checked for this engagement" — a read-only projection the
// backend derives from the audit log, results timeline, and findings. See
// backend/lib/coverage.py.

export type CoverageArea = {
  key: string;
  label: string;
  description: string;
  covered: boolean;
  runs: number;
  last_ts: string | null;
  last_tool: string | null;
  last_target: string | null;
  tools_seen: string[];
};

export type EngagementCoverage = {
  engagement_id: string;
  areas: CoverageArea[];
  covered_count: number;
  total: number;
};

export async function fetchCoverage(eid: string): Promise<EngagementCoverage> {
  const r = await authFetch(`/engagements/${eid}/coverage`);
  if (!r.ok) throw new Error(await parseError(r));
  return r.json();
}
