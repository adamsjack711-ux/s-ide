import { useCallback, useEffect, useMemo, useState } from "react";
import { authFetch } from "../api";
import {
  generateReportSnapshot,
  listReportSnapshots,
  listFindings,
  requestReportLink,
  requestSnapshotLink,
  useActiveEngagementId,
  FINDING_SEVERITIES,
  type Finding,
  type FindingSeverity,
  type EngagementCoverage,
  type ReportSnapshotMeta,
} from "../lib/engagement";

/**
 * Reports view.
 *
 * Top half: a reporting DASHBOARD modelled on the design mockup's REPORTING
 * section — metric cards, a severity donut (hand-built SVG, no deps), a
 * per-severity counts legend, a "tools used" horizontal bar list, and a
 * report outline. Every number is computed from REAL engagement data:
 *   - listFindings(eid)           → severity counts (donut + cards) + tools
 *   - /engagements/{eid}/coverage → coverage % + which areas are covered
 * Cards the design fabricates (MTTR over time, LOC) are computed as a real
 * proxy where one exists, or omitted entirely rather than faked.
 *
 * Bottom half: the existing snapshot / export wiring, unchanged in behaviour.
 */

// Severity → token colour. Backend severities are critical/high/medium/low/info;
// the design's donut covers crit/high/med/low and folds info into the low band.
const SEV_COLOR: Record<FindingSeverity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--text-muted)",
};
const SEV_LABEL: Record<FindingSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

// "open" findings = anything not resolved. Mirrors the tracker's terminal states.
const RESOLVED = new Set(["false_positive", "remediated", "fixed", "wont_fix"]);

function dayKey(iso: string): string {
  return (iso || "").slice(0, 10);
}

/** Mean age (days) of open findings — a real, non-fabricated proxy for MTTR. */
function meanOpenAgeDays(findings: Finding[]): number | null {
  const open = findings.filter((f) => !RESOLVED.has(f.status));
  if (open.length === 0) return null;
  const now = Date.now();
  let sum = 0;
  let n = 0;
  for (const f of open) {
    const t = Date.parse(f.ts);
    if (!Number.isNaN(t)) {
      sum += (now - t) / 86_400_000;
      n += 1;
    }
  }
  if (n === 0) return null;
  return sum / n;
}

type Metric = { label: string; value: string; delta?: string; color: string };

export default function ReportsView() {
  const eid = useActiveEngagementId();

  // ── dashboard data ────────────────────────────────────────────────────────
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverage, setCoverage] = useState<EngagementCoverage | null>(null);
  const [activeSection, setActiveSection] = useState("Description");

  // ── snapshot / export (unchanged) ─────────────────────────────────────────
  const [snaps, setSnaps] = useState<ReportSnapshotMeta[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const refresh = useCallback(() => {
    if (!eid) {
      setSnaps([]);
      setFindings([]);
      setCoverage(null);
      return;
    }
    listReportSnapshots(eid).then(setSnaps).catch(() => setSnaps([]));
    listFindings(eid).then(setFindings).catch(() => setFindings([]));
    authFetch(`/engagements/${eid}/coverage`)
      .then((r) => (r.ok ? r.json() : null))
      .then((c: EngagementCoverage | null) => setCoverage(c))
      .catch(() => setCoverage(null));
  }, [eid]);
  useEffect(refresh, [refresh]);

  async function open(linkPromise: Promise<string>) {
    try {
      window.open(await linkPromise, "_blank");
    } catch (e: any) {
      setErr(e?.message || "could not open report");
    }
  }

  async function generate() {
    if (!eid) return;
    setBusy(true);
    setErr("");
    try {
      await generateReportSnapshot(eid);
      refresh();
    } catch (e: any) {
      setErr(e?.message || "generate failed");
    } finally {
      setBusy(false);
    }
  }

  // ── derived dashboard values ──────────────────────────────────────────────
  const counts = useMemo(() => {
    const c: Record<FindingSeverity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const f of findings) {
      const sev = (f.severity in c ? f.severity : "info") as FindingSeverity;
      c[sev] += 1;
    }
    return c;
  }, [findings]);

  const openFindings = useMemo(
    () => findings.filter((f) => !RESOLVED.has(f.status)).length,
    [findings],
  );

  // Tools used: real run counts (per distinct day a tool produced a finding is
  // a noisy signal, so we count findings per tool) + findings-per-tool.
  const toolsUsed = useMemo(() => {
    const byTool = new Map<string, { findings: number; days: Set<string> }>();
    for (const f of findings) {
      const name = f.tool || "—";
      const e = byTool.get(name) ?? { findings: 0, days: new Set<string>() };
      e.findings += 1;
      e.days.add(dayKey(f.ts));
      byTool.set(name, e);
    }
    const rows = [...byTool.entries()].map(([name, e]) => ({
      name,
      findings: e.findings,
      runs: e.days.size, // distinct active days as a proxy for run sessions
    }));
    rows.sort((a, b) => b.findings - a.findings || b.runs - a.runs);
    return rows.slice(0, 8);
  }, [findings]);
  const maxToolFindings = Math.max(1, ...toolsUsed.map((t) => t.findings));

  const total = findings.length;
  const mttr = meanOpenAgeDays(findings);
  const coveragePct = coverage && coverage.total > 0
    ? Math.round((coverage.covered_count / coverage.total) * 100)
    : null;

  // Metric cards — only emit a card when its value is real.
  const metrics: Metric[] = [];
  metrics.push({
    label: "Open Findings",
    value: String(openFindings),
    delta: `${total} total`,
    color: "var(--text-primary)",
  });
  metrics.push({
    label: "Critical",
    value: String(counts.critical),
    delta: counts.high > 0 ? `+${counts.high} high` : "no high-severity",
    color: "var(--critical)",
  });
  if (mttr != null) {
    metrics.push({
      label: "Mean Open-Finding Age",
      value: `${mttr.toFixed(1)}d`,
      delta: "avg age of unresolved",
      color: "var(--text-primary)",
    });
  }
  if (coveragePct != null) {
    metrics.push({
      label: "Scan Coverage",
      value: `${coveragePct}%`,
      delta: `${coverage!.covered_count}/${coverage!.total} areas`,
      color: "var(--text-primary)",
    });
  }

  const OUTLINE = ["Description", "Data Flow", "Vulnerable Code", "Remediation", "History"];

  if (!eid) {
    return (
      <div className="p-3 text-sm text-ink-dim">
        Select an engagement to view reporting and export reports.
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-base text-sm">
      {/* ── Report document ─────────────────────────────────────────────────── */}
      <div className="mx-auto flex w-full max-w-4xl items-end justify-between px-6 pb-3 pt-6">
        <div className="text-[calc(22px_*_var(--text-scale))] font-bold tracking-tight text-ink-primary">Reporting</div>
        <button
          onClick={() => open(requestReportLink(eid, "html"))}
          className="flex h-8 items-center rounded-lg border border-divider bg-bg-card px-3 text-xs font-medium text-ink-muted hover:border-borderBright hover:text-ink-primary"
        >
          Export report
        </button>
      </div>

      {/* summary strip — a slim inline line, not KPI dashboard cards */}
      <div className="mx-auto w-full max-w-4xl border-b border-divider px-6 pb-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5">
          {metrics.map((m) => (
            <span key={m.label} className="flex items-baseline gap-1.5 text-[calc(12.5px_*_var(--text-scale))]">
              <span className="text-ink-muted">{m.label}</span>
              <span className="data font-semibold" style={{ color: m.color }}>{m.value}</span>
              {m.delta && <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">({m.delta})</span>}
            </span>
          ))}
        </div>
      </div>

      {/* Document body — stacked sections, read top-to-bottom like a report. */}
      <div className="mx-auto w-full max-w-4xl space-y-7 px-6 py-6">
        {/* Report outline — the document's table of contents (primary). */}
        <section>
          <h2 className="mb-2 text-[calc(13px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">Report Outline</h2>
          <div className="flex flex-col">
            {OUTLINE.map((label) => {
              const active = label === activeSection;
              return (
                <div
                  key={label}
                  onClick={() => setActiveSection(label)}
                  className="cursor-pointer border-l-2 px-3 py-2 text-[calc(13.5px_*_var(--text-scale))]"
                  style={{
                    color: active ? "var(--text-primary)" : "var(--text-secondary)",
                    background: active ? "var(--accent-dim)" : "transparent",
                    borderColor: active ? "var(--accent)" : "var(--border)",
                  }}
                >
                  {label}
                </div>
              );
            })}
          </div>
        </section>

        {/* Findings by severity — compact inline breakdown (no chart). */}
        <section>
          <h2 className="mb-2 text-[calc(13px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">Findings by Severity</h2>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            {FINDING_SEVERITIES.map((sev) => (
              <span key={sev} className="flex items-center gap-2 text-[calc(13px_*_var(--text-scale))]">
                <span className="h-[10px] w-[10px] rounded-[3px]" style={{ background: SEV_COLOR[sev] }} />
                <span className="text-ink-muted">{SEV_LABEL[sev]}</span>
                <span className="data font-semibold text-ink-primary">{counts[sev]}</span>
              </span>
            ))}
            <span className="text-[calc(12px_*_var(--text-scale))] text-ink-dim">· {openFindings} open</span>
          </div>
        </section>

        {/* Coverage. */}
        <section>
          <h2 className="mb-2 flex items-center gap-2 text-[calc(13px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">
            Coverage
            {coveragePct != null && <span className="data normal-case text-ink-muted">· {coveragePct}%</span>}
          </h2>
          {coverage == null ? (
            <div className="text-xs text-ink-dim">Coverage data unavailable.</div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {coverage.areas.map((a) => (
                <span
                  key={a.key}
                  title={a.covered ? `${a.runs} run(s) · last: ${a.last_tool ?? "—"}` : a.description}
                  className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[calc(11.5px_*_var(--text-scale))]"
                  style={{
                    color: a.covered ? "var(--accent)" : "var(--text-muted)",
                    borderColor: a.covered ? "var(--accent-dim)" : "var(--border)",
                    background: a.covered ? "var(--accent-dim)" : "transparent",
                  }}
                >
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: a.covered ? "var(--accent)" : "var(--text-muted)" }} />
                  {a.label}
                </span>
              ))}
            </div>
          )}
        </section>

        {/* Tools used — compact ranked list. */}
        <section>
          <h2 className="mb-2 text-[calc(13px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">Tools Used</h2>
          {toolsUsed.length === 0 ? (
            <div className="text-xs text-ink-dim">No tool activity recorded yet.</div>
          ) : (
            <div className="flex flex-col gap-1.5">
              {toolsUsed.map((t) => {
                const findColor =
                  t.findings >= 3 ? "var(--critical)" : t.findings >= 1 ? "var(--high)" : "var(--text-muted)";
                return (
                  <div key={t.name} className="flex items-center gap-3 text-[calc(12.5px_*_var(--text-scale))]">
                    <span className="w-40 truncate font-medium text-ink-primary">{t.name}</span>
                    <div className="h-[6px] flex-1 overflow-hidden rounded bg-bg-surface">
                      <div className="h-full rounded" style={{ width: `${Math.round((t.findings / maxToolFindings) * 100)}%`, background: "var(--accent-dim)" }} />
                    </div>
                    <span className="data w-16 text-right font-semibold" style={{ color: findColor }}>
                      {t.findings} {t.findings === 1 ? "find" : "finds"}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {/* ── Export / snapshots (existing wiring) ───────────────────────────── */}
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-2 border-t border-divider px-6 py-3">
        <div className="text-xs uppercase tracking-wide text-ink-dim">Live report</div>
        <div className="flex gap-2">
          <button onClick={() => open(requestReportLink(eid, "md"))} className="rounded bg-bg-card px-2 py-1 text-xs ring-1 ring-divider hover:bg-bg-hover">Markdown ↗</button>
          <button onClick={() => open(requestReportLink(eid, "html"))} className="rounded bg-bg-card px-2 py-1 text-xs ring-1 ring-divider hover:bg-bg-hover">HTML ↗</button>
          <button onClick={generate} disabled={busy} className="ml-auto rounded bg-accent px-2 py-1 text-xs text-bg-base disabled:opacity-50">
            {busy ? "Generating…" : "Snapshot"}
          </button>
        </div>
        {err && <div className="text-xs text-danger">{err}</div>}
      </div>

      <div className="mx-auto w-full max-w-4xl px-6 py-2 text-xs uppercase tracking-wide text-ink-dim">Snapshots</div>
      {snaps.length === 0 ? (
        <div className="mx-auto w-full max-w-4xl px-6 pb-4 text-xs text-ink-dim">No snapshots yet.</div>
      ) : (
        snaps.map((s) => (
          <div key={s.id} className="mx-auto w-full max-w-4xl border-b border-divider px-6 py-2">
            <div className="text-xs text-ink-muted">{new Date(s.ts).toLocaleString()}</div>
            <div className="mt-0.5 line-clamp-2 text-xs text-ink-dim">{s.rollup_preview}</div>
            <div className="mt-1 flex gap-2">
              <button onClick={() => open(requestSnapshotLink(eid, s.id, "md"))} className="text-[calc(11px_*_var(--text-scale))] text-accent hover:underline">md ↗</button>
              <button onClick={() => open(requestSnapshotLink(eid, s.id, "html"))} className="text-[calc(11px_*_var(--text-scale))] text-accent hover:underline">html ↗</button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
