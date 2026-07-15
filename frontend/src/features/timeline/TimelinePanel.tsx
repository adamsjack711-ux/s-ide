/**
 * F6 — Engagement timeline / history.
 *
 * A navigable, chronological, READ-ONLY view over the existing append-only
 * audit/evidence ledger for the ACTIVE engagement. It NEVER mutates history and
 * NEVER runs a tool — it only reads (`listAudit`), normalizes + redacts + sorts
 * (timelineLogic), renders, and cross-links by PUBLISHING selection events.
 *
 * Contract compliance:
 *   - reads shared state only through the model API (../../shell/model),
 *   - refreshes on `modelChanged` (any entity) + `activeEngagementChanged`,
 *   - cross-links by publishing bus events (selectFinding / selectSubTarget) —
 *     never imports or calls another feature,
 *   - registers its own view + command at import time,
 *   - has loading / empty / error / no-active-engagement states.
 *
 * Selecting an entry resolves the best selection event it can:
 *   - a finding row → `selectFinding` with the full provenance triple. If the
 *     ledger row lacks sub_target_id/target_id we resolve them via
 *     getFinding(findingId) + toFindingRef; if that fails, we select nothing.
 *   - a run/output row that maps to a sub-target → `selectSubTarget`.
 *   - otherwise, nothing (gracefully — a disabled row, no broken event).
 */
import { useCallback, useEffect, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import { useActiveEngagementId } from "../../lib/engagement";
import {
  listAudit, getFinding, toFindingRef, type AuditEntry,
} from "../../shell/model";
import {
  buildTimeline, type TimelineEntry, type TimelineKind, type TimelineStatus,
} from "./timelineLogic";

const SOURCE = "timeline";
const LIMIT = 500;

type LoadState =
  | { phase: "no-engagement" }
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "ready"; entries: TimelineEntry[] };

// ── Presentation helpers ─────────────────────────────────────────────────────

const KIND_ACCENT: Record<TimelineKind, string> = {
  run: "bg-accent",
  finding: "bg-high",
  arm: "bg-success",
  disarm: "bg-medium",
  attestation: "bg-accent",
  state: "bg-low",
  event: "bg-ink-dim",
};

const STATUS_TEXT: Record<TimelineStatus, string> = {
  started: "text-ink-muted",
  completed: "text-success",
  error: "text-critical",
  stopped: "text-medium",
  refused: "text-high",
  unknown: "text-ink-dim",
};

function formatWhen(iso: string): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  try {
    return new Date(t).toLocaleString();
  } catch {
    return iso;
  }
}

/** True iff selecting this entry can resolve to a broadcastable selection. */
function isSelectable(e: TimelineEntry): boolean {
  return Boolean(e.findingId || e.subTargetId);
}

// ── Panel ─────────────────────────────────────────────────────────────────────

function TimelinePanel(_props: { params: ViewParams }) {
  const activeId = useActiveEngagementId();
  const [state, setState] = useState<LoadState>({ phase: "loading" });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Bump to force a reload from the bus without duplicating shared state.
  const [nonce, setNonce] = useState(0);

  // Load (or reload) the ledger for the active engagement. Read-only.
  useEffect(() => {
    let alive = true;
    if (!activeId) {
      setState({ phase: "no-engagement" });
      return;
    }
    setState((s) => (s.phase === "ready" ? s : { phase: "loading" }));
    (async () => {
      try {
        const rows: AuditEntry[] = await listAudit(activeId, { limit: LIMIT });
        if (!alive) return;
        setState({ phase: "ready", entries: buildTimeline(rows, "asc") });
      } catch (err) {
        if (!alive) return;
        setState({
          phase: "error",
          message: err instanceof Error ? err.message : "Failed to load timeline.",
        });
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeId, nonce]);

  // Refresh on ANY model change or active-engagement change (no private cache).
  const refresh = useCallback(() => setNonce((n) => n + 1), []);
  useBus("modelChanged", refresh);
  useBus("activeEngagementChanged", refresh);
  // Attestations sign/revoke through their own event, not `modelChanged`, but
  // they land in the audit ledger this timeline renders — so listen directly.
  useBus("attestationsChanged", refresh);

  // Selecting an entry publishes the best selection event we can resolve.
  const onSelect = useCallback((e: TimelineEntry) => {
    setSelectedId(e.id);
    if (e.findingId) {
      // Prefer the row's own triple; else resolve via the model. Never fabricate.
      const st = e.subTargetId ?? (typeof e.raw.sub_target_id === "string" ? e.raw.sub_target_id : "");
      const tgt = typeof e.raw.target_id === "string" ? e.raw.target_id : "";
      if (st && tgt) {
        emit("selectFinding", { ref: { findingId: e.findingId, subTargetId: st, targetId: tgt }, source: SOURCE });
        return;
      }
      (async () => {
        try {
          const f = await getFinding(e.findingId!);
          if (f) emit("selectFinding", { ref: toFindingRef(f), source: SOURCE });
          // else: unresolvable — select nothing gracefully.
        } catch {
          /* unresolvable — select nothing */
        }
      })();
      return;
    }
    if (e.subTargetId) {
      const tgt = typeof e.raw.target_id === "string" ? e.raw.target_id : "";
      emit("selectSubTarget", { ref: { subTargetId: e.subTargetId, targetId: tgt }, source: SOURCE });
      return;
    }
    // Nothing resolvable — no event. Selection highlight only.
  }, []);

  // ── State screens ───────────────────────────────────────────────────────────

  if (state.phase === "no-engagement") {
    return (
      <Centered>
        <div className="text-[calc(13px_*_var(--text-scale))] text-ink-muted">
          No active engagement. Pin an engagement to see its timeline.
        </div>
      </Centered>
    );
  }
  if (state.phase === "loading") {
    return (
      <Centered>
        <div className="flex items-center gap-2 text-[calc(13px_*_var(--text-scale))] text-ink-dim">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
          Loading engagement timeline…
        </div>
      </Centered>
    );
  }
  if (state.phase === "error") {
    return (
      <Centered>
        <div className="max-w-md rounded-lg border border-divider bg-bg-card p-6 text-center">
          <div className="text-[calc(12px_*_var(--text-scale))] uppercase tracking-wide text-critical">
            Couldn’t load the timeline
          </div>
          <div className="mt-2 font-mono text-[calc(12px_*_var(--text-scale))] text-ink-muted break-all">
            {state.message}
          </div>
          <button
            onClick={refresh}
            className="mt-4 rounded border border-divider px-3 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary hover:bg-bg-base"
          >
            Retry
          </button>
        </div>
      </Centered>
    );
  }
  if (state.entries.length === 0) {
    return (
      <Centered>
        <div className="text-[calc(13px_*_var(--text-scale))] text-ink-muted">
          No activity yet.
        </div>
      </Centered>
    );
  }

  // ── Ready: chronological (oldest → newest) timeline ─────────────────────────
  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      <header className="flex items-center justify-between border-b border-divider px-4 py-2">
        <div className="text-[calc(13px_*_var(--text-scale))] text-ink-primary">
          Engagement timeline
        </div>
        <div className="flex items-center gap-3 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          <span>{state.entries.length} entries · oldest → newest</span>
          <span className="rounded border border-divider px-1.5 py-0.5 uppercase tracking-wide">
            read-only
          </span>
        </div>
      </header>

      <ol className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {state.entries.map((e) => {
          const selectable = isSelectable(e);
          const selected = e.id === selectedId;
          return (
            <li key={e.id} className="relative flex gap-3 pb-3 pl-1">
              {/* rail + node */}
              <div className="relative flex w-3 flex-none justify-center">
                <span className="absolute top-1.5 bottom-[-0.75rem] w-px bg-divider" />
                <span className={`relative z-10 mt-1 h-2.5 w-2.5 rounded-full ${KIND_ACCENT[e.kind]}`} />
              </div>

              <button
                type="button"
                disabled={!selectable}
                onClick={() => selectable && onSelect(e)}
                title={
                  selectable
                    ? e.findingId
                      ? "Select this finding"
                      : "Focus this sub-target"
                    : "No linked object"
                }
                className={[
                  "flex-1 rounded-md border px-3 py-2 text-left transition-colors",
                  selected ? "border-accent bg-bg-card" : "border-divider bg-bg-card",
                  selectable ? "hover:border-accent cursor-pointer" : "cursor-default opacity-90",
                ].join(" ")}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[calc(12px_*_var(--text-scale))] text-ink-primary break-all">
                    {e.label}
                  </span>
                  <span className={`flex-none text-[calc(11px_*_var(--text-scale))] ${STATUS_TEXT[e.status]}`}>
                    {e.status}
                  </span>
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
                  <span className="font-mono">{formatWhen(e.iso)}</span>
                  {e.target && <span className="font-mono text-ink-muted break-all">{e.target}</span>}
                  {e.findingId && <span className="rounded bg-bg-base px-1 text-high">finding</span>}
                  {!e.findingId && e.subTargetId && (
                    <span className="rounded bg-bg-base px-1 text-ink-muted">sub-target</span>
                  )}
                </div>
                {e.detail && (
                  <div className="mt-1 text-[calc(11px_*_var(--text-scale))] text-ink-muted break-all">
                    {e.detail}
                  </div>
                )}
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center gap-3 bg-bg-base p-8">
      {children}
    </div>
  );
}

// ── Registration (runs at import) ─────────────────────────────────────────────
registerView({ id: "timeline", component: TimelinePanel });
registerCommand({
  id: "timeline.open",
  title: "Open Engagement Timeline",
  keywords: ["timeline", "history", "audit", "activity"],
  context: "View",
  run: () => emit("openView", { view: "timeline" }),
});
