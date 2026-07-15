/**
 * F4 — Scan-over-scan diff.
 *
 * Compares TWO runs of the SAME sub-target and buckets their findings into
 * new / fixed / regressed / unchanged. Read-only: it never triggers a run; it
 * only reads runs + findings through the model API and diffs them client-side.
 *
 * Self-contained per the feature contract:
 *   - reads shared state ONLY through ../../shell/model (listRuns / listFindings)
 *   - refreshes on `modelChanged` (finding/run) + `activeEngagementChanged`
 *   - cross-links by PUBLISHING `selectFinding` on the bus — never imports another
 *     feature/panel
 *   - registers its own view + command at import time
 *   - has loading / empty / error / no-engagement states
 *
 * The pure classification lives in ./diffLogic (unit-tested, no I/O); this file
 * is the I/O + presentation shell. Run output/summary shown anywhere is passed
 * through ./redact first (defence-in-depth on secret leakage).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import { useActiveEngagementId } from "../../lib/engagement";
import {
  listRuns, listFindings, toFindingRef, confLevel,
  type PairingRun, type PairingFinding,
} from "../../shell/model";
import {
  diffFindingSets, attributeFindingsToRun,
  type DiffResult, type DiffRow, type DiffRun, type DiffFinding, type DiffSeverity,
} from "./diffLogic";
import { redactSecrets } from "./redact";

const SOURCE = "scandiff";

// ── small presentation helpers ───────────────────────────────────────────────

const SEV_TEXT: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-ink-muted",
};

const BUCKET_META: Record<
  DiffRow["bucket"],
  { label: string; dot: string; hint: string }
> = {
  new: { label: "New", dot: "bg-high", hint: "in latest, not baseline" },
  regressed: { label: "Regressed", dot: "bg-critical", hint: "severity worsened" },
  fixed: { label: "Fixed", dot: "bg-success", hint: "in baseline, not latest" },
  unchanged: { label: "Unchanged", dot: "bg-ink-dim", hint: "present in both" },
};

function fmtTime(ts: string | null): string {
  if (!ts) return "—";
  const n = Date.parse(ts);
  if (Number.isNaN(n)) return ts;
  return new Date(n).toLocaleString();
}

/** Label a run for the picker: tool + started time + status. */
function runLabel(r: PairingRun): string {
  return `${r.tool || "run"} · ${fmtTime(r.started_at)} · ${r.status}`;
}

/** Project a model finding to the pure-diff shape (only the fields we diff on). */
function toDiffFinding(f: PairingFinding): DiffFinding {
  return {
    id: f.id,
    sub_target_id: f.sub_target_id,
    title: f.title,
    tool: f.tool,
    target: f.target,
    severity: (f.severity as DiffSeverity) ?? "info",
    status: f.status,
    ts: f.ts,
  };
}

function toDiffRun(r: PairingRun): DiffRun {
  return {
    id: r.id,
    sub_target_id: r.sub_target_id,
    started_at: r.started_at,
    ended_at: r.ended_at,
  };
}

// ── panel ─────────────────────────────────────────────────────────────────────

type LoadState = "idle" | "loading" | "ready" | "error";

function ScanDiffPanel(_props: { params: ViewParams }) {
  const activeId = useActiveEngagementId();

  const [state, setState] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);

  const [runs, setRuns] = useState<PairingRun[]>([]);
  const [findings, setFindings] = useState<PairingFinding[]>([]);

  // Selection: which sub-target, and which two runs to compare.
  const [subTargetId, setSubTargetId] = useState<string | null>(null);
  const [earlierRunId, setEarlierRunId] = useState<string | null>(null);
  const [laterRunId, setLaterRunId] = useState<string | null>(null);

  // ── load runs + findings for the active engagement ────────────────────────
  const load = useCallback(async () => {
    if (!activeId) {
      setState("idle");
      setRuns([]);
      setFindings([]);
      return;
    }
    setState("loading");
    setError(null);
    try {
      const [r, fs] = await Promise.all([
        listRuns(activeId),
        listFindings(activeId),
      ]);
      setRuns(r);
      setFindings(fs);
      setState("ready");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setState("error");
    }
  }, [activeId]);

  useEffect(() => {
    void load();
  }, [load]);

  // Refresh on the unified model signal (only for entities we care about) and on
  // engagement switch. No private cache of shared state — we always re-read.
  useBus("modelChanged", (p) => {
    if (p.entity === "finding" || p.entity === "run") void load();
  });
  useBus("activeEngagementChanged", () => void load());

  // ── derive sub-targets that actually have runs ────────────────────────────
  const subTargets = useMemo(() => {
    const ids = new Set<string>();
    for (const r of runs) ids.add(r.sub_target_id);
    return [...ids];
  }, [runs]);

  // Auto-pick a sub-target when none chosen (or the chosen one vanished).
  useEffect(() => {
    if (subTargets.length === 0) {
      if (subTargetId !== null) setSubTargetId(null);
      return;
    }
    if (!subTargetId || !subTargets.includes(subTargetId)) {
      setSubTargetId(subTargets[0]);
    }
  }, [subTargets, subTargetId]);

  // Runs for the chosen sub-target, newest last (chronological by started_at).
  const subRuns = useMemo(() => {
    if (!subTargetId) return [];
    return runs
      .filter((r) => r.sub_target_id === subTargetId)
      .slice()
      .sort((a, b) => Date.parse(a.started_at) - Date.parse(b.started_at));
  }, [runs, subTargetId]);

  // Default run selection: baseline = first, latest = last (when ≥2 runs).
  useEffect(() => {
    if (subRuns.length === 0) {
      setEarlierRunId(null);
      setLaterRunId(null);
      return;
    }
    const ids = subRuns.map((r) => r.id);
    setLaterRunId((cur) => (cur && ids.includes(cur) ? cur : subRuns[subRuns.length - 1].id));
    setEarlierRunId((cur) =>
      cur && ids.includes(cur)
        ? cur
        : subRuns.length >= 2
          ? subRuns[0].id
          : null,
    );
    // subRuns identity changes when sub-target/runs change; that's the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subTargetId, subRuns.length]);

  const earlierRun = subRuns.find((r) => r.id === earlierRunId) ?? null;
  const laterRun = subRuns.find((r) => r.id === laterRunId) ?? null;

  // ── compute the diff (pure) ───────────────────────────────────────────────
  const diff: DiffResult | null = useMemo(() => {
    if (!subTargetId || !laterRun) return null;
    const pool = findings
      .filter((f) => f.sub_target_id === subTargetId)
      .map(toDiffFinding);
    const others = subRuns.map(toDiffRun);

    const laterAttr = attributeFindingsToRun(toDiffRun(laterRun), pool, others);
    if (!earlierRun) {
      // FIRST run (only one run for this sub-target) — nothing to diff against.
      return diffFindingSets([], laterAttr, /* earlierRunPresent */ false);
    }
    const earlierAttr = attributeFindingsToRun(toDiffRun(earlierRun), pool, others);
    return diffFindingSets(earlierAttr, laterAttr, true);
  }, [subTargetId, earlierRun, laterRun, subRuns, findings]);

  const findingById = useMemo(() => {
    const m = new Map<string, PairingFinding>();
    for (const f of findings) m.set(f.id, f);
    return m;
  }, [findings]);

  const onRowClick = useCallback(
    (row: DiffRow) => {
      const full = findingById.get(row.finding.id);
      if (!full) return; // fixed rows off the baseline may be a stale copy; only click resolvable ones
      emit("selectFinding", { ref: toFindingRef(full), source: SOURCE });
    },
    [findingById],
  );

  // ── render states ─────────────────────────────────────────────────────────
  if (!activeId) {
    return (
      <Shell>
        <Center>
          <Empty
            title="No active engagement"
            body="Pin an engagement to compare its scan runs. Scan-over-scan diff is scoped to the active engagement."
          />
        </Center>
      </Shell>
    );
  }

  if (state === "loading" || state === "idle") {
    return (
      <Shell>
        <Center>
          <div className="flex items-center gap-2 text-ink-dim text-[calc(13px_*_var(--text-scale))]">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
            Loading runs…
          </div>
        </Center>
      </Shell>
    );
  }

  if (state === "error") {
    return (
      <Shell>
        <Center>
          <Empty
            title="Couldn't load scan runs"
            body={error ?? "Unknown error."}
            tone="danger"
          />
          <button
            onClick={() => void load()}
            className="mt-3 rounded border border-divider bg-bg-card px-3 py-1.5 text-[calc(12px_*_var(--text-scale))] text-ink-primary hover:border-accent"
          >
            Retry
          </button>
        </Center>
      </Shell>
    );
  }

  if (subTargets.length === 0) {
    return (
      <Shell>
        <Center>
          <Empty
            title="No scan runs yet"
            body="This engagement has no pairing runs to compare. Runs appear here once a sub-target has been scanned in the Workbench."
          />
        </Center>
      </Shell>
    );
  }

  return (
    <Shell>
      {/* Controls */}
      <div className="flex flex-wrap items-end gap-4 border-b border-divider bg-bg-card px-4 py-3">
        <Field label="Sub-target">
          <select
            value={subTargetId ?? ""}
            onChange={(e) => setSubTargetId(e.target.value)}
            className="min-w-[180px] rounded border border-divider bg-bg-base px-2 py-1 font-mono text-[calc(12px_*_var(--text-scale))] text-ink-primary"
          >
            {subTargets.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Baseline (earlier)">
          <select
            value={earlierRunId ?? ""}
            onChange={(e) => setEarlierRunId(e.target.value || null)}
            disabled={subRuns.length < 2}
            className="min-w-[240px] rounded border border-divider bg-bg-base px-2 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary disabled:opacity-50"
          >
            {subRuns.length < 2 && <option value="">— no prior scan —</option>}
            {subRuns.map((r) => (
              <option key={r.id} value={r.id} disabled={r.id === laterRunId}>
                {runLabel(r)}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Latest (later)">
          <select
            value={laterRunId ?? ""}
            onChange={(e) => setLaterRunId(e.target.value || null)}
            className="min-w-[240px] rounded border border-divider bg-bg-base px-2 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary"
          >
            {subRuns.map((r) => (
              <option key={r.id} value={r.id} disabled={r.id === earlierRunId}>
                {runLabel(r)}
              </option>
            ))}
          </select>
        </Field>

        <div className="ml-auto text-[calc(11px_*_var(--text-scale))] text-ink-dim max-w-[280px] leading-relaxed">
          Findings attributed to a run by timestamp window
          <span className="text-ink-muted"> [started_at, ended_at]</span> on the
          same sub-target — a heuristic, not ground truth.
        </div>
      </div>

      {/* First-run banner */}
      {diff?.isFirstRun && (
        <div className="border-b border-divider bg-bg-card/60 px-4 py-2 text-[calc(12px_*_var(--text-scale))] text-ink-muted">
          No prior scan to compare — this is the first run for{" "}
          <span className="font-mono text-ink-primary">{subTargetId}</span>.
          Showing every finding as a baseline (“new”).
        </div>
      )}

      {/* Summary counts */}
      {diff && (
        <div className="flex flex-wrap gap-2 border-b border-divider px-4 py-2">
          {(["regressed", "new", "fixed", "unchanged"] as const).map((b) => (
            <span
              key={b}
              className="inline-flex items-center gap-1.5 rounded-full border border-divider bg-bg-card px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-muted"
            >
              <span className={`h-1.5 w-1.5 rounded-full ${BUCKET_META[b].dot}`} />
              {BUCKET_META[b].label}
              <span className="font-mono text-ink-primary">{diff.counts[b]}</span>
            </span>
          ))}
        </div>
      )}

      {/* Buckets */}
      <div className="min-h-0 flex-1 overflow-auto px-4 py-3">
        {diff && (
          <div className="flex flex-col gap-4">
            <Bucket bucket="regressed" rows={diff.regressed} onRow={onRowClick} findingById={findingById} />
            <Bucket bucket="new" rows={diff.new} onRow={onRowClick} findingById={findingById} />
            <Bucket bucket="fixed" rows={diff.fixed} onRow={onRowClick} findingById={findingById} />
            <Bucket bucket="unchanged" rows={diff.unchanged} onRow={onRowClick} findingById={findingById} />
            {diff.counts.new + diff.counts.fixed + diff.counts.regressed + diff.counts.unchanged === 0 && (
              <div className="py-8 text-center text-[calc(13px_*_var(--text-scale))] text-ink-dim">
                No findings attributed to the selected run
                {earlierRun ? "s" : ""}.
              </div>
            )}
          </div>
        )}
      </div>
    </Shell>
  );
}

// ── bucket + row ──────────────────────────────────────────────────────────────

function Bucket(props: {
  bucket: DiffRow["bucket"];
  rows: DiffRow[];
  onRow: (r: DiffRow) => void;
  findingById: Map<string, PairingFinding>;
}) {
  const { bucket, rows, onRow, findingById } = props;
  if (rows.length === 0) return null;
  const meta = BUCKET_META[bucket];
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-2 text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
        <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
        {meta.label}
        <span className="text-ink-muted normal-case">· {meta.hint}</span>
        <span className="font-mono text-ink-primary">{rows.length}</span>
      </div>
      <div className="flex flex-col divide-y divide-divider overflow-hidden rounded border border-divider bg-bg-card">
        {rows.map((row) => (
          <Row key={bucket + ":" + row.key} row={row} onRow={onRow} full={findingById.get(row.finding.id)} />
        ))}
      </div>
    </div>
  );
}

function Row(props: {
  row: DiffRow;
  onRow: (r: DiffRow) => void;
  full?: PairingFinding;
}) {
  const { row, onRow, full } = props;
  const clickable = !!full; // only rows whose finding is resolvable emit selection
  const later = row.laterSeverity;
  const earlier = row.earlierSeverity;
  const suspected = full ? confLevel(full) === "suspected" : true;

  return (
    <button
      type="button"
      disabled={!clickable}
      onClick={() => clickable && onRow(row)}
      className={`flex w-full items-center gap-3 px-3 py-2 text-left transition-colors ${
        clickable ? "hover:bg-bg-base cursor-pointer" : "cursor-default opacity-80"
      }`}
    >
      {/* severity chip(s) */}
      <span className="flex shrink-0 items-center gap-1 font-mono text-[calc(11px_*_var(--text-scale))]">
        {earlier && row.bucket !== "new" && (
          <span className={SEV_TEXT[earlier] ?? "text-ink-muted"}>{earlier}</span>
        )}
        {earlier && later && row.bucket === "regressed" && (
          <span className="text-ink-dim">→</span>
        )}
        {later && row.bucket !== "fixed" && (
          <span className={`${SEV_TEXT[later] ?? "text-ink-muted"} ${row.bucket === "regressed" ? "font-semibold" : ""}`}>
            {later}
          </span>
        )}
        {row.bucket === "fixed" && earlier && (
          <span className={`${SEV_TEXT[earlier] ?? "text-ink-muted"} line-through opacity-70`}>{earlier}</span>
        )}
      </span>

      <span className="min-w-0 flex-1 truncate text-[calc(13px_*_var(--text-scale))] text-ink-primary">
        {redactSecrets(row.finding.title)}
      </span>

      {/* confidence marker — suspected is visually distinct (contract T5) */}
      <span
        className={`shrink-0 rounded px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] ${
          suspected
            ? "border border-medium/40 text-medium"
            : "border border-success/40 text-success"
        }`}
      >
        {suspected ? "suspected" : "confirmed"}
      </span>

      <span className="hidden shrink-0 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-dim sm:inline">
        {redactSecrets(row.finding.tool)}
      </span>
    </button>
  );
}

// ── layout atoms ──────────────────────────────────────────────────────────────

function Shell(props: { children: React.ReactNode }) {
  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base text-ink-primary">
      <div className="flex items-center gap-2 border-b border-divider px-4 py-2.5">
        <span className="text-[calc(13px_*_var(--text-scale))] font-medium text-ink-primary">
          Scan-over-scan diff
        </span>
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          compare two runs of a sub-target · read-only
        </span>
      </div>
      {props.children}
    </div>
  );
}

function Center(props: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col items-center justify-center p-8 text-center">
      {props.children}
    </div>
  );
}

function Empty(props: { title: string; body: string; tone?: "danger" }) {
  return (
    <div className="max-w-md">
      <div
        className={`text-[calc(15px_*_var(--text-scale))] ${
          props.tone === "danger" ? "text-danger" : "text-ink-primary"
        }`}
      >
        {props.title}
      </div>
      <p className="mt-2 text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-dim">
        {props.body}
      </p>
    </div>
  );
}

function Field(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
        {props.label}
      </span>
      {props.children}
    </label>
  );
}

// ── Registration (runs at import) ─────────────────────────────────────────────
registerView({ id: "scandiff", component: ScanDiffPanel });
registerCommand({
  id: "scandiff.open",
  title: "Scan diff: compare two runs",
  keywords: ["diff", "scan", "compare", "runs"],
  context: "View",
  run: () => emit("openView", { view: "scandiff" }),
});
