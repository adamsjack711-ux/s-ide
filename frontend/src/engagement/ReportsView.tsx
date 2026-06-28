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

  // Donut: cumulative arc segments over the four primary severities (+info).
  const donutSegments = useMemo(() => {
    const order: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
    const circ = 2 * Math.PI * 54; // r = 54
    let offset = 0;
    const segs: { color: string; dash: number; gap: number; off: number }[] = [];
    for (const sev of order) {
      const n = counts[sev];
      if (n === 0) continue;
      const frac = total > 0 ? n / total : 0;
      const dash = frac * circ;
      segs.push({ color: SEV_COLOR[sev], dash, gap: circ - dash, off: -offset });
      offset += dash;
    }
    return { segs, circ };
  }, [counts, total]);

  const OUTLINE = ["Description", "Data Flow", "Vulnerable Code", "Remediation", "History"];

  if (!eid) {
    return (
      <div className="p-3 text-sm text-ink-dim">
        Select an engagement to view reporting and export reports.
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-sidebar text-sm">
      {/* ── Dashboard ──────────────────────────────────────────────────────── */}
      <div className="flex items-end justify-between px-6 pb-4 pt-6">
        <div>
          <div className="text-[22px] font-bold tracking-tight text-ink-primary">Reporting</div>
          <div className="mt-1 text-[13px] text-ink-muted">
            Aggregated findings, severity mix &amp; tools used for this engagement
          </div>
        </div>
        <button
          onClick={() => open(requestReportLink(eid, "html"))}
          className="flex h-8 items-center rounded-lg border border-divider bg-bg-card px-3 text-xs font-medium text-ink-muted hover:border-borderBright hover:text-ink-primary"
        >
          Export report
        </button>
      </div>

      {/* metric cards */}
      <div
        className="grid gap-3.5 px-6 pb-3.5"
        style={{ gridTemplateColumns: `repeat(${Math.max(metrics.length, 1)}, 1fr)` }}
      >
        {metrics.map((m) => (
          <div key={m.label} className="rounded-[13px] border border-divider bg-bg-card p-4">
            <div className="mb-3 text-[11.5px] font-medium text-ink-muted">{m.label}</div>
            <div className="data leading-none" style={{ fontSize: 30, fontWeight: 700, color: m.color }}>
              {m.value}
            </div>
            {m.delta && (
              <div className="mt-2 text-[11.5px] font-medium" style={{ color: m.color === "var(--critical)" ? "var(--critical)" : "var(--text-muted)" }}>
                {m.delta}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* donut + tools used */}
      <div className="grid gap-3.5 px-6 pb-3.5" style={{ gridTemplateColumns: "1fr 1.25fr" }}>
        {/* Findings by Severity */}
        <div className="rounded-[13px] border border-divider bg-bg-card p-[18px]">
          <div className="mb-4 text-[13px] font-semibold text-ink-primary">Findings by Severity</div>
          <div className="flex items-center gap-[22px]">
            <div className="relative" style={{ width: 128, height: 128, flex: "0 0 128px" }}>
              <svg width={128} height={128} viewBox="0 0 128 128">
                {/* track */}
                <circle
                  cx={64} cy={64} r={54} fill="none"
                  stroke="var(--bg-base)" strokeWidth={17}
                />
                {total > 0 ? (
                  donutSegments.segs.map((s, i) => (
                    <circle
                      key={i}
                      cx={64} cy={64} r={54} fill="none"
                      stroke={s.color}
                      strokeWidth={17}
                      strokeDasharray={`${s.dash} ${s.gap}`}
                      strokeDashoffset={s.off}
                      transform="rotate(-90 64 64)"
                    />
                  ))
                ) : null}
              </svg>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <div className="data" style={{ fontSize: 26, fontWeight: 700, color: "var(--text-primary)" }}>
                  {openFindings}
                </div>
                <div className="text-[10px] font-medium tracking-wider text-ink-dim">OPEN</div>
              </div>
            </div>
            <div className="flex flex-1 flex-col gap-[9px]">
              {FINDING_SEVERITIES.map((sev) => (
                <div key={sev} className="flex items-center gap-[9px] text-[12.5px]">
                  <span
                    className="h-[9px] w-[9px] rounded-[3px]"
                    style={{ background: SEV_COLOR[sev] }}
                  />
                  <span className="flex-1 text-ink-muted">{SEV_LABEL[sev]}</span>
                  <span className="data font-semibold text-ink-primary">{counts[sev]}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Tools Used */}
        <div className="rounded-[13px] border border-divider bg-bg-card p-[18px]">
          <div className="mb-4 text-[13px] font-semibold text-ink-primary">Tools Used</div>
          {toolsUsed.length === 0 ? (
            <div className="text-xs text-ink-dim">No tool activity recorded yet.</div>
          ) : (
            toolsUsed.map((t) => {
              const findColor =
                t.findings >= 3 ? "var(--critical)" : t.findings >= 1 ? "var(--high)" : "var(--text-muted)";
              return (
                <div key={t.name} className="mb-[13px]">
                  <div className="mb-1.5 flex items-center gap-2">
                    <span className="flex-1 truncate text-[12.5px] font-medium text-ink-primary">{t.name}</span>
                    <span className="text-[11px] text-ink-dim">{t.runs} {t.runs === 1 ? "day" : "days"}</span>
                    <span className="data w-[64px] text-right font-semibold" style={{ color: findColor, fontSize: "11.5px" }}>
                      {t.findings} {t.findings === 1 ? "find" : "finds"}
                    </span>
                  </div>
                  <div className="h-[7px] overflow-hidden rounded bg-bg-base">
                    <div
                      className="h-full rounded"
                      style={{
                        width: `${Math.round((t.findings / maxToolFindings) * 100)}%`,
                        background: "var(--accent-dim)",
                      }}
                    />
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* report outline + coverage areas */}
      <div className="grid gap-3.5 px-6 pb-5" style={{ gridTemplateColumns: "1fr 1.4fr" }}>
        <div className="rounded-[13px] border border-divider bg-bg-card p-[18px]">
          <div className="mb-3 text-[13px] font-semibold text-ink-primary">Report Outline</div>
          <div className="flex flex-col gap-1">
            {OUTLINE.map((label) => {
              const active = label === activeSection;
              return (
                <div
                  key={label}
                  onClick={() => setActiveSection(label)}
                  className="cursor-pointer rounded-[7px] px-2.5 py-[7px] text-[12.5px]"
                  style={{
                    color: active ? "var(--text-primary)" : "var(--text-secondary)",
                    background: active ? "var(--accent-dim)" : "transparent",
                    borderLeft: `2px solid ${active ? "var(--accent)" : "transparent"}`,
                  }}
                >
                  {label}
                </div>
              );
            })}
          </div>
        </div>

        <div className="rounded-[13px] border border-divider bg-bg-card p-[18px]">
          <div className="mb-3 flex items-center justify-between">
            <div className="text-[13px] font-semibold text-ink-primary">Coverage Areas</div>
            {coveragePct != null && (
              <div className="data text-[11px] text-ink-muted">{coveragePct}% covered</div>
            )}
          </div>
          {coverage == null ? (
            <div className="text-xs text-ink-dim">Coverage data unavailable.</div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {coverage.areas.map((a) => (
                <span
                  key={a.key}
                  title={a.covered ? `${a.runs} run(s) · last: ${a.last_tool ?? "—"}` : a.description}
                  className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11.5px]"
                  style={{
                    color: a.covered ? "var(--accent)" : "var(--text-muted)",
                    borderColor: a.covered ? "var(--accent-dim)" : "var(--border)",
                    background: a.covered ? "var(--accent-dim)" : "transparent",
                  }}
                >
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ background: a.covered ? "var(--accent)" : "var(--text-muted)" }}
                  />
                  {a.label}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Export / snapshots (existing wiring) ───────────────────────────── */}
      <div className="flex flex-col gap-2 border-t border-divider px-6 py-3">
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

      <div className="px-6 py-2 text-xs uppercase tracking-wide text-ink-dim">Snapshots</div>
      {snaps.length === 0 ? (
        <div className="px-6 pb-4 text-xs text-ink-dim">No snapshots yet.</div>
      ) : (
        snaps.map((s) => (
          <div key={s.id} className="border-b border-divider px-6 py-2">
            <div className="text-xs text-ink-muted">{new Date(s.ts).toLocaleString()}</div>
            <div className="mt-0.5 line-clamp-2 text-xs text-ink-dim">{s.rollup_preview}</div>
            <div className="mt-1 flex gap-2">
              <button onClick={() => open(requestSnapshotLink(eid, s.id, "md"))} className="text-[11px] text-accent hover:underline">md ↗</button>
              <button onClick={() => open(requestSnapshotLink(eid, s.id, "html"))} className="text-[11px] text-accent hover:underline">html ↗</button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
