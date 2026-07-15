/**
 * F7 — Inline suggestions (IntelliSense analog) for configuring/running a tool.
 *
 * A SELF-CONTAINED, self-registered contextual panel that docks beside the
 * Workbench (it registers as a normal view reachable via command + openView; it
 * is NOT a global side rail and does not touch the Workbench/ToolPanel). It
 * reacts to the operator's current context on the bus and offers ADVISORY
 * suggestions:
 *
 *   - PARAM suggestions — from known assets of the in-context sub-target
 *     (listAssets({ subTargetId })): each host/service/endpoint becomes a
 *     suggested target to open a tool pre-filled with.
 *   - NEXT-STEP suggestions — from coverage gaps (getCoverage): each area whose
 *     `covered` is false becomes a suggestion to run the check that closes it
 *     (labels/tone reuse lib/coverageView).
 *
 * CONTEXT: subscribes to `selectSubTarget` and `activeEngagementChanged` (via
 * useBus) to know which sub-target/engagement the operator is in; suggestions
 * re-scope on those and on `modelChanged`.
 *
 * SECURITY (the whole point of F7 being read-only):
 *   - ADVISORY ONLY: nothing here ever runs a tool. Every suggestion is
 *     DISMISSIBLE, and "Apply" emits at most `openTool` — it NAVIGATES to the
 *     tool with context, it never executes.
 *   - The arm gate + scope filter live in suggestLogic.deriveSuggestions: an
 *     un-armed sub-target and out-of-scope targets produce NO suggestion.
 *   - Reads only through the model API; no writes, no runs.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import { getActiveEngagementId } from "../../lib/engagement";
import { getTarget } from "../../lib/spine";
import {
  getCoverage, getEngagement, listAssets,
  type Asset, type EngagementCoverage,
} from "../../shell/model";
import type { SubTarget } from "../../lib/spine";
import type { SubTargetRef } from "../../shell/refs";
import { deriveSuggestions, type Suggestion } from "./suggestLogic";

const SOURCE = "suggestions";

type Load = "idle" | "loading" | "ready" | "error";

function SuggestionsPanel(_props: { params: ViewParams }) {
  // ── Context (from the bus / active-engagement pin) ──────────────────────────
  const [engagementId, setEngagementId] = useState<string | null>(getActiveEngagementId());
  const [subRef, setSubRef] = useState<SubTargetRef | null>(null);

  // ── Derived data + lifecycle ────────────────────────────────────────────────
  const [load, setLoad] = useState<Load>("idle");
  const [error, setError] = useState<string | null>(null);
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const reqId = useRef(0);

  // React to the operator focusing a sub-target somewhere else in the shell.
  useBus("selectSubTarget", useCallback((p: { ref: SubTargetRef; source: string }) => {
    if (p.source === SOURCE) return; // ignore our own echo
    setSubRef(p.ref);
  }, []));

  // Re-scope when the active engagement changes. A new engagement invalidates
  // the current sub-target context (it belongs to the prior engagement's tree).
  useBus("activeEngagementChanged", useCallback((p: { engagementId: string | null }) => {
    setEngagementId(p.engagementId);
    setSubRef(null);
  }, []));

  // Any model mutation (asset discovered, run, finding) may change coverage or
  // assets — re-derive on the unified signal.
  const [modelTick, setModelTick] = useState(0);
  useBus("modelChanged", useCallback(() => setModelTick((n) => n + 1), []));
  useBus("assetDiscovered", useCallback(() => setModelTick((n) => n + 1), []));

  // ── Fetch + derive whenever context or the model changes ────────────────────
  useEffect(() => {
    const eid = engagementId;
    if (!eid) {
      setLoad("ready");
      setSuggestions([]);
      setError(null);
      return;
    }
    const myReq = ++reqId.current;
    setLoad("loading");
    setError(null);
    (async () => {
      try {
        const subTargetId = subRef?.subTargetId ?? null;
        const targetId = subRef?.targetId ?? null;

        // The sub-target records (with the live `armed` flag) come from the
        // parent target. Without a sub-target in context we still surface
        // coverage next-steps, so this is best-effort.
        let subTargets: SubTarget[] = [];
        if (targetId) {
          try {
            const t = await getTarget(targetId);
            subTargets = t.sub_targets ?? [];
          } catch {
            subTargets = [];
          }
        }

        const [assets, coverage, engagement] = await Promise.all([
          subTargetId
            ? listAssets({ subTargetId }).catch(() => [] as Asset[])
            : Promise.resolve([] as Asset[]),
          getCoverage(eid).catch(() => null as EngagementCoverage | null),
          getEngagement(eid).catch(() => null),
        ]);

        if (myReq !== reqId.current) return; // superseded by a newer context

        const next = deriveSuggestions({
          engagementId: eid,
          activeSubTargetId: subTargetId,
          subTargets,
          assets,
          coverage,
          scope: engagement?.scope ?? [],
        });
        setSuggestions(next);
        setLoad("ready");
      } catch (e) {
        if (myReq !== reqId.current) return;
        setError(e instanceof Error ? e.message : "Failed to derive suggestions");
        setLoad("error");
      }
    })();
  }, [engagementId, subRef, modelTick]);

  // ── Actions (advisory only) ─────────────────────────────────────────────────
  const dismiss = useCallback((id: string) => {
    setDismissed((prev) => {
      const next = new Set(prev);
      next.add(id);
      return next;
    });
  }, []);

  // Apply NAVIGATES — it opens the tool panel, it NEVER runs anything. The
  // pre-fill value rides via the tool's own context; here we only open it.
  const apply = useCallback((s: Suggestion) => {
    emit("openTool", { toolId: s.toolId });
  }, []);

  const visible = suggestions.filter((s) => !dismissed.has(s.id));
  const params = visible.filter((s) => s.kind === "param");
  const steps = visible.filter((s) => s.kind === "next-step");

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      <Header engagementId={engagementId} subRef={subRef} count={visible.length} />
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        <Body
          load={load}
          error={error}
          engagementId={engagementId}
          total={suggestions.length}
          visibleCount={visible.length}
          params={params}
          steps={steps}
          onApply={apply}
          onDismiss={dismiss}
        />
      </div>
    </div>
  );
}

// ── Presentation ──────────────────────────────────────────────────────────────

function Header(props: {
  engagementId: string | null;
  subRef: SubTargetRef | null;
  count: number;
}) {
  return (
    <div className="flex items-center justify-between border-b border-divider bg-bg-card px-3 py-2">
      <div className="flex items-center gap-2">
        <span className="text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
          Suggestions
        </span>
        <span className="rounded bg-bg-base px-1.5 py-0.5 font-mono text-[calc(10px_*_var(--text-scale))] text-ink-muted">
          {props.count}
        </span>
      </div>
      <div className="font-mono text-[calc(10px_*_var(--text-scale))] text-ink-dim">
        {props.engagementId
          ? props.subRef
            ? `sub ${props.subRef.subTargetId}`
            : "engagement scope"
          : "no engagement"}
      </div>
    </div>
  );
}

function Body(props: {
  load: Load;
  error: string | null;
  engagementId: string | null;
  total: number;
  visibleCount: number;
  params: Suggestion[];
  steps: Suggestion[];
  onApply: (s: Suggestion) => void;
  onDismiss: (id: string) => void;
}) {
  if (!props.engagementId) {
    return (
      <Empty
        title="No active engagement"
        detail="Pin an engagement to see parameter and next-step suggestions scoped to it."
      />
    );
  }
  if (props.load === "loading" || props.load === "idle") {
    return <Empty title="Loading suggestions…" detail="Reading assets and coverage for the current context." muted />;
  }
  if (props.load === "error") {
    return (
      <div className="rounded-lg border border-critical/40 bg-critical/10 p-4 text-[calc(12px_*_var(--text-scale))] text-critical">
        Couldn't build suggestions: {props.error ?? "unknown error"}
      </div>
    );
  }
  if (props.visibleCount === 0) {
    return (
      <Empty
        title={props.total > 0 ? "All caught up" : "No suggestions"}
        detail={
          props.total > 0
            ? "You've dismissed the current suggestions."
            : "Coverage looks complete and no actionable assets are in scope yet."
        }
      />
    );
  }
  return (
    <div className="flex flex-col gap-4">
      {props.params.length > 0 && (
        <Section label="Parameters from known assets">
          {props.params.map((s) => (
            <Row key={s.id} s={s} onApply={props.onApply} onDismiss={props.onDismiss} />
          ))}
        </Section>
      )}
      {props.steps.length > 0 && (
        <Section label="Next steps from coverage gaps">
          {props.steps.map((s) => (
            <Row key={s.id} s={s} onApply={props.onApply} onDismiss={props.onDismiss} />
          ))}
        </Section>
      )}
    </div>
  );
}

function Section(props: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
        {props.label}
      </div>
      <div className="flex flex-col gap-2">{props.children}</div>
    </div>
  );
}

function Row(props: { s: Suggestion; onApply: (s: Suggestion) => void; onDismiss: (id: string) => void }) {
  const { s } = props;
  return (
    <div className={`rounded-lg border ${s.tone.border} bg-bg-card p-3`}>
      <div className="flex items-start gap-2">
        <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${s.tone.dot}`} />
        <div className="min-w-0 flex-1">
          <div className="text-[calc(13px_*_var(--text-scale))] text-ink-primary break-words">
            {s.title}
          </div>
          <div className="mt-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-muted break-words">
            {s.detail}
          </div>
          <div className="mt-2 flex items-center gap-2">
            {/* Apply NAVIGATES to the tool — it never runs anything. */}
            <button
              type="button"
              onClick={() => props.onApply(s)}
              className="rounded border border-accent/50 bg-accent/10 px-2 py-0.5 text-[calc(11px_*_var(--text-scale))] text-accent hover:bg-accent/20"
              title={`Open ${s.toolId} (does not run)`}
            >
              Open {s.toolId}
            </button>
            <button
              type="button"
              onClick={() => props.onDismiss(s.id)}
              className="rounded border border-divider px-2 py-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim hover:text-ink-muted"
            >
              Dismiss
            </button>
            <span className="ml-auto font-mono text-[calc(10px_*_var(--text-scale))] text-ink-dim">
              advisory
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function Empty(props: { title: string; detail: string; muted?: boolean }) {
  return (
    <div className="flex h-full min-h-[8rem] flex-col items-center justify-center gap-1 text-center">
      <div className={`text-[calc(13px_*_var(--text-scale))] ${props.muted ? "text-ink-muted" : "text-ink-primary"}`}>
        {props.title}
      </div>
      <div className="max-w-sm text-[calc(11px_*_var(--text-scale))] text-ink-dim">{props.detail}</div>
    </div>
  );
}

// ── Registration (runs at import) ─────────────────────────────────────────────
registerView({ id: "suggestions", component: SuggestionsPanel });
registerCommand({
  id: "suggestions.open",
  title: "Show inline suggestions",
  keywords: ["suggest", "intellisense", "next", "hints"],
  context: "View",
  run: () => emit("openView", { view: "suggestions" }),
});
