/**
 * F2 — Findings-as-Problems panel (an IDE "Problems" pane for an engagement).
 *
 * A live, aggregated, SEVERITY-SORTED list of every finding across the active
 * engagement's sub-targets. Each row shows the finding's title, a severity
 * badge, its fix-STATE (open→fixed→verified, read from the evidence chain's
 * method envelope), and its ConfLevel. It is READ-ONLY and holds no private
 * cache of shared state: it re-reads through the model API on `modelChanged`
 * (entity==="finding") and on `activeEngagementChanged`.
 *
 * DECOUPLING: it cross-links ONLY by publishing `selectFinding` on the bus
 * (source "problems") — it never imports another feature/panel. It registers
 * its own view + command at import time.
 *
 * SECURITY:
 *   - Confidence is derived ONLY via confLevel() from shell/model — a
 *     `suspected` finding is NEVER rendered as `confirmed`, and is made visually
 *     distinct (dashed border + a "suspected" chip).
 *   - No tools are ever run; no secrets are shown (this panel renders only
 *     title / severity / state / confidence — no evidence snippets).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import { useActiveEngagementId } from "../../lib/engagement";
import {
  listFindings, getEvidenceChain, confLevel, toFindingRef,
  type PairingFinding, type FindingSeverity, type ConfLevel,
} from "../../shell/model";
import {
  buildProblemView, countBySeverity, subTargetIds, normalizeFixState,
  SEVERITY_ORDER, FIX_STATES,
  type ProblemRow, type FixState, type ProblemFilters,
} from "./problemsLogic";

const SOURCE = "problems";
const CONF_LEVELS: ConfLevel[] = ["confirmed", "suspected"];

type LoadState = "loading" | "ready" | "error";

// ── Load: findings + per-finding fix-state, enriched into ProblemRows ─────────

/**
 * Read every finding for the engagement, then resolve each one's fix-state from
 * its evidence chain (method?.state, default "open"). Confidence is derived via
 * confLevel() — never upgraded. Chain reads that fail default the row to "open"
 * rather than dropping the finding.
 */
async function loadRows(engagementId: string): Promise<ProblemRow[]> {
  const findings = await listFindings(engagementId);
  const rows = await Promise.all(
    findings.map(async (f: PairingFinding): Promise<ProblemRow> => {
      let fixState: FixState = "open";
      try {
        const chain = await getEvidenceChain(f.id);
        fixState = normalizeFixState(chain.method?.state);
      } catch {
        fixState = "open";
      }
      return { finding: f, fixState, conf: confLevel(f) };
    }),
  );
  return rows;
}

// ── Small presentational atoms ───────────────────────────────────────────────

const SEV_CLASS: Record<FindingSeverity, string> = {
  critical: "text-critical border-critical",
  high: "text-high border-high",
  medium: "text-medium border-medium",
  low: "text-low border-low",
  info: "text-ink-muted border-divider",
};

function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <span
      className={
        "inline-flex items-center rounded border px-1.5 py-0.5 " +
        "text-[calc(10px_*_var(--text-scale))] font-medium uppercase tracking-wide " +
        (SEV_CLASS[severity] ?? SEV_CLASS.info)
      }
    >
      {severity}
    </span>
  );
}

const STATE_LABEL: Record<FixState, string> = {
  open: "open",
  fixed: "fixed",
  verified: "verified",
};

function StateChip({ state }: { state: FixState }) {
  const tone =
    state === "verified"
      ? "text-success border-success"
      : state === "fixed"
        ? "text-accent border-accent"
        : "text-ink-muted border-divider";
  return (
    <span
      className={
        "inline-flex items-center rounded border px-1.5 py-0.5 " +
        "text-[calc(10px_*_var(--text-scale))] " + tone
      }
    >
      {STATE_LABEL[state]}
    </span>
  );
}

/** A tiny multi-select chip group. */
function ChipFilter<T extends string>(props: {
  label: string;
  options: readonly T[];
  selected: T[];
  onToggle: (v: T) => void;
  renderLabel?: (v: T) => string;
}) {
  const { label, options, selected, onToggle, renderLabel } = props;
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
        {label}
      </span>
      {options.map((o) => {
        const on = selected.includes(o);
        return (
          <button
            key={o}
            type="button"
            onClick={() => onToggle(o)}
            className={
              "rounded border px-1.5 py-0.5 text-[calc(11px_*_var(--text-scale))] " +
              (on
                ? "border-accent bg-accent/15 text-ink-primary"
                : "border-divider text-ink-muted hover:text-ink-primary")
            }
          >
            {renderLabel ? renderLabel(o) : o}
          </button>
        );
      })}
    </div>
  );
}

// ── Panel ─────────────────────────────────────────────────────────────────────

function ProblemsPanel(_props: { params: ViewParams }) {
  const activeId = useActiveEngagementId();

  const [rows, setRows] = useState<ProblemRow[]>([]);
  const [load, setLoad] = useState<LoadState>("loading");
  const [error, setError] = useState<string | null>(null);

  // Filters (client-side over the fetched list).
  const [sevFilter, setSevFilter] = useState<FindingSeverity[]>([]);
  const [stateFilter, setStateFilter] = useState<FixState[]>([]);
  const [confFilter, setConfFilter] = useState<ConfLevel[]>([]);
  const [subFilter, setSubFilter] = useState<string | null>(null);

  // Guards against out-of-order async loads writing stale state.
  const loadSeq = useRef(0);

  const refresh = useCallback(async () => {
    const eid = activeId;
    const my = ++loadSeq.current;
    if (!eid) {
      setRows([]);
      setLoad("ready");
      setError(null);
      return;
    }
    setLoad("loading");
    setError(null);
    try {
      const next = await loadRows(eid);
      if (my !== loadSeq.current) return; // superseded
      setRows(next);
      setLoad("ready");
    } catch (e) {
      if (my !== loadSeq.current) return;
      setError(e instanceof Error ? e.message : "Failed to load findings");
      setLoad("error");
    }
  }, [activeId]);

  // Initial + re-scope on active engagement change (hook re-renders → refresh).
  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Re-read on model finding mutations (no private cache — always via the model).
  useBus("modelChanged", (p) => {
    if (p.entity === "finding") void refresh();
  });
  // Re-scope on the bus signal too (covers non-hook publishers).
  useBus("activeEngagementChanged", () => {
    void refresh();
  });

  // Derived, per render, from the last read — no cache beyond `rows`.
  const filters: ProblemFilters = useMemo(
    () => ({
      severity: sevFilter,
      fixState: stateFilter,
      confidence: confFilter,
      subTargetId: subFilter,
    }),
    [sevFilter, stateFilter, confFilter, subFilter],
  );

  const visible = useMemo(() => buildProblemView(rows, filters), [rows, filters]);
  // Badges/sub-target list reflect the TRUE totals (unfiltered).
  const counts = useMemo(() => countBySeverity(rows), [rows]);
  const subs = useMemo(() => subTargetIds(rows), [rows]);

  const toggle = <T,>(set: React.Dispatch<React.SetStateAction<T[]>>) => (v: T) =>
    set((cur) => (cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]));

  const onRowClick = useCallback((f: PairingFinding) => {
    emit("selectFinding", { ref: toFindingRef(f), source: SOURCE });
  }, []);

  // ── Empty / no-engagement / error / loading shells ───────────────────────
  if (!activeId) {
    return (
      <Centered>
        <div className="text-[calc(14px_*_var(--text-scale))] text-ink-primary">
          No active engagement
        </div>
        <p className="mt-1 max-w-sm text-center text-[calc(12px_*_var(--text-scale))] text-ink-dim">
          Select an engagement to see its findings as problems.
        </p>
      </Centered>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base text-ink-primary">
      {/* Header: title + per-severity count badges */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-divider px-4 py-2">
        <span className="text-[calc(12px_*_var(--text-scale))] font-medium uppercase tracking-wide text-ink-muted">
          Problems
        </span>
        <div className="flex flex-wrap items-center gap-2">
          {SEVERITY_ORDER.map((s, i) => (
            <span
              key={s}
              className={
                "text-[calc(11px_*_var(--text-scale))] " +
                (counts[s] > 0 ? (SEV_CLASS[s].split(" ")[0]) : "text-ink-dim")
              }
            >
              {counts[s]} {s}
              {i < SEVERITY_ORDER.length - 1 ? " ·" : ""}
            </span>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-divider px-4 py-2">
        <ChipFilter
          label="severity"
          options={SEVERITY_ORDER}
          selected={sevFilter}
          onToggle={toggle(setSevFilter)}
        />
        <ChipFilter
          label="state"
          options={FIX_STATES}
          selected={stateFilter}
          onToggle={toggle(setStateFilter)}
        />
        <ChipFilter
          label="confidence"
          options={CONF_LEVELS}
          selected={confFilter}
          onToggle={toggle(setConfFilter)}
        />
        {subs.length > 0 && (
          <label className="flex items-center gap-1.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
            sub-target
            <select
              value={subFilter ?? ""}
              onChange={(e) => setSubFilter(e.target.value || null)}
              className="rounded border border-divider bg-bg-card px-1.5 py-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-primary"
            >
              <option value="">all</option>
              {subs.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      {/* Body */}
      <div className="min-h-0 flex-1 overflow-auto">
        {load === "loading" && (
          <Centered>
            <span className="text-[calc(12px_*_var(--text-scale))] text-ink-dim">
              Loading findings…
            </span>
          </Centered>
        )}
        {load === "error" && (
          <Centered>
            <div className="text-[calc(13px_*_var(--text-scale))] text-critical">
              Couldn’t load findings
            </div>
            <p className="mt-1 max-w-sm text-center text-[calc(11px_*_var(--text-scale))] text-ink-dim break-all">
              {error}
            </p>
            <button
              type="button"
              onClick={() => void refresh()}
              className="mt-3 rounded border border-divider px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-muted hover:text-ink-primary"
            >
              Retry
            </button>
          </Centered>
        )}
        {load === "ready" && rows.length === 0 && (
          <Centered>
            <span className="text-[calc(13px_*_var(--text-scale))] text-ink-muted">
              No findings yet
            </span>
          </Centered>
        )}
        {load === "ready" && rows.length > 0 && visible.length === 0 && (
          <Centered>
            <span className="text-[calc(12px_*_var(--text-scale))] text-ink-dim">
              No findings match the current filters
            </span>
          </Centered>
        )}
        {load === "ready" && visible.length > 0 && (
          <ul className="divide-y divide-divider">
            {visible.map((r) => (
              <ProblemRowItem key={r.finding.id} row={r} onClick={onRowClick} />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function ProblemRowItem({
  row,
  onClick,
}: {
  row: ProblemRow;
  onClick: (f: PairingFinding) => void;
}) {
  const { finding, fixState, conf } = row;
  const suspected = conf === "suspected";
  return (
    <li>
      <button
        type="button"
        onClick={() => onClick(finding)}
        className={
          "flex w-full items-center gap-3 px-4 py-2 text-left hover:bg-bg-card " +
          // suspected is visually distinct: dashed left accent border.
          (suspected ? "border-l-2 border-dashed border-medium" : "border-l-2 border-transparent")
        }
      >
        <SeverityBadge severity={finding.severity} />
        <span className="min-w-0 flex-1 truncate text-[calc(13px_*_var(--text-scale))] text-ink-primary">
          {finding.title}
        </span>
        {suspected ? (
          <span className="rounded border border-dashed border-medium px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-medium">
            suspected
          </span>
        ) : (
          <span className="rounded border border-success px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-success">
            confirmed
          </span>
        )}
        <StateChip state={fixState} />
      </button>
    </li>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center gap-1 p-8">
      {children}
    </div>
  );
}

// ── Registration (runs at import) ─────────────────────────────────────────────
registerView({ id: "problems", component: ProblemsPanel });
registerCommand({
  id: "problems.open",
  title: "Open Problems (findings)",
  keywords: ["problems", "findings", "issues"],
  context: "View",
  run: () => emit("openView", { view: "problems" }),
});
