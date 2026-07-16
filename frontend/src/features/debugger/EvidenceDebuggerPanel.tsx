/**
 * F9 — Evidence Debugger: a step-by-step "debugger" for a finding's reasoning.
 *
 * WHAT IT IS: a READ-ONLY replay of a finding's captured evidence chain. It
 * subscribes to `selectFinding` (so it becomes the reactor whenever ANY panel
 * focuses a finding), loads that finding's chain via `getEvidenceChain`, and
 * lets the operator step forward / back / reset through it like a debugger — one
 * step at a time. Per step it shows the ACTION (tool + params), the captured
 * evidence (request/response state / raw_output), the INTERPRETATION, and the
 * anchored-vs-inferred status. A "BREAK" control jumps to the trigger step — the
 * one that established the vulnerability.
 *
 * WHAT IT IS NOT: it never re-fires a live tool. Replay is of already-captured
 * evidence only. A "Retest" affordance is shown but DISABLED — a retest is an
 * explicit, arm-gated user action (the gated path is `runPairing` in lib/spine,
 * which the backend refuses with 403 SUBTARGET_UNARMED for un-armed scope). We
 * do not wire it to auto-run under any circumstance.
 *
 * SECURITY: every string rendered (evidence, params, interpretation) goes
 * through the redactor in stepLogic (masks tokens/keys/cookies/Authorization).
 * An INFERRED step (unanchored) is labelled as a guess — never presented as fact.
 *
 * CROSS-LINK (bus only; never a direct import of another panel):
 *   - IN : `selectFinding` → load chain, reset to step 0.
 *   - OUT: `selectStep`   → on every step move ({ findingId, stepId }).
 *          `selectAnchor` → when the current step resolves to a code/route
 *          location (its own file params, else the finding's root-cause anchor),
 *          so a code view can follow along.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import {
  getEvidenceChain,
  resolveAnchor,
  type EvidenceChain,
  type Step,
  type FindingRef,
  type Anchor,
} from "../../shell/model";
import {
  clampIndex,
  stepForward,
  stepBack,
  atStart,
  atEnd,
  findTriggerIndex,
  redactStep,
  type RedactedStep,
} from "./stepLogic";

const SOURCE = "debugger";

type LoadState =
  | { kind: "empty" } // no finding selected yet
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; chain: EvidenceChain };

function EvidenceDebuggerPanel(_props: { params: ViewParams }) {
  const [ref, setRef] = useState<FindingRef | null>(null);
  const [state, setState] = useState<LoadState>({ kind: "empty" });
  const [index, setIndex] = useState(0);
  // Guards against stale async loads clobbering a newer selection.
  const loadSeq = useRef(0);

  // ── Subscribe: any panel selecting a finding drives this debugger. ──────────
  useBus("selectFinding", (p) => {
    if (p.source === SOURCE) return; // ignore our own echo (defensive)
    setRef(p.ref);
  });

  // ── Load the chain for the selected finding; reset to step 0. ───────────────
  useEffect(() => {
    if (!ref) {
      setState({ kind: "empty" });
      return;
    }
    const seq = ++loadSeq.current;
    setState({ kind: "loading" });
    setIndex(0);
    (async () => {
      try {
        const chain = await getEvidenceChain(ref.findingId);
        if (loadSeq.current !== seq) return; // superseded
        setState({ kind: "ready", chain });
        setIndex(0);
      } catch (e: any) {
        if (loadSeq.current !== seq) return;
        setState({ kind: "error", message: e?.message || "failed to load evidence chain" });
      }
    })();
  }, [ref]);

  const steps: Step[] = state.kind === "ready" ? state.chain.steps : [];
  const method = state.kind === "ready" ? state.chain.method : null;
  const current: Step | undefined = steps[clampIndex(index, steps)];
  const triggerIdx = findTriggerIndex(steps, method);

  // ── On each step move, broadcast selectStep, and follow with selectAnchor
  //    when the step resolves to a location. Fires only for real steps. ────────
  useEffect(() => {
    if (!ref || !current) return;
    emit("selectStep", { ref: { findingId: ref.findingId, stepId: current.id }, source: SOURCE });

    // Prefer the step's own file params (no network). Else best-effort resolve
    // the finding's root-cause anchor. Never fabricates a location.
    const p = current.action?.params as Record<string, unknown> | undefined;
    const file = typeof p?.file === "string" ? p.file : undefined;
    if (file) {
      const anchor: Anchor = {
        kind: "file",
        file,
        line: typeof p?.line === "number" ? p.line : undefined,
        labId: typeof p?.labId === "string" ? p.labId : undefined,
      };
      emit("selectAnchor", { ref: anchor, findingId: ref.findingId, source: SOURCE });
      return;
    }
    // Only the trigger step reaches out for the finding-level anchor — that's the
    // step that "is" the finding; other steps stay quiet to avoid anchor churn.
    if (triggerIdx != null && steps[triggerIdx]?.id === current.id) {
      let alive = true;
      resolveAnchor(ref.findingId)
        .then((anchor) => {
          if (alive && anchor) {
            emit("selectAnchor", { ref: anchor, findingId: ref.findingId, source: SOURCE });
          }
        })
        .catch(() => {});
      return () => {
        alive = false;
      };
    }
  }, [ref, current?.id, triggerIdx, steps]);

  const goForward = useCallback(() => setIndex((i) => stepForward(i, steps)), [steps]);
  const goBack = useCallback(() => setIndex((i) => stepBack(i, steps)), [steps]);
  const doReset = useCallback(() => setIndex(0), []);
  const doBreak = useCallback(() => {
    if (triggerIdx != null) setIndex(triggerIdx);
  }, [triggerIdx]);

  // ── Render ──────────────────────────────────────────────────────────────────
  if (state.kind === "empty") {
    return (
      <Shell>
        <EmptyState
          title="No finding selected"
          body="Select a finding anywhere in the workspace to replay its evidence chain, step by step."
        />
      </Shell>
    );
  }
  if (state.kind === "loading") {
    return (
      <Shell>
        <EmptyState title="Loading evidence chain…" body={ref?.findingId ?? ""} muted />
      </Shell>
    );
  }
  if (state.kind === "error") {
    return (
      <Shell>
        <div className="flex h-full items-center justify-center p-8">
          <div className="max-w-md rounded-lg border border-danger/40 bg-danger/[0.06] p-5 text-center">
            <div className="text-[calc(12px_*_var(--text-scale))] font-semibold text-danger">
              Could not load evidence chain
            </div>
            <div className="mt-1.5 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-muted break-all">
              {state.message}
            </div>
          </div>
        </div>
      </Shell>
    );
  }

  // ready
  if (steps.length === 0) {
    return (
      <Shell findingId={ref?.findingId}>
        <EmptyState
          title="No steps captured"
          body="This finding has no recorded evidence chain to replay yet."
        />
      </Shell>
    );
  }

  const clamped = clampIndex(index, steps);
  const view = current ? redactStep(current) : null;
  const isTrigger = triggerIdx != null && clamped === triggerIdx;

  return (
    <Shell findingId={ref?.findingId} method={method}>
      <Controls
        index={clamped}
        total={steps.length}
        atStart={atStart(clamped, steps)}
        atEnd={atEnd(clamped, steps)}
        hasTrigger={triggerIdx != null}
        onBack={goBack}
        onForward={goForward}
        onReset={doReset}
        onBreak={doBreak}
      />
      {view && <StepCard view={view} isTrigger={isTrigger} />}
    </Shell>
  );
}

// ── Shell / chrome ───────────────────────────────────────────────────────────

function Shell({
  children,
  findingId,
  method,
}: {
  children: React.ReactNode;
  findingId?: string;
  method?: EvidenceChain["method"];
}) {
  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      <header className="flex items-center gap-2 border-b border-divider px-4 py-2.5">
        <span className="font-mono text-[calc(12px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">
          Evidence Debugger
        </span>
        <span className="rounded bg-accent/15 px-1.5 py-px font-mono text-[calc(9.5px_*_var(--text-scale))] uppercase tracking-wide text-accent ring-1 ring-accent/30">
          read-only replay
        </span>
        {findingId && (
          <span className="ml-auto font-mono text-[calc(11px_*_var(--text-scale))] text-ink-muted break-all">
            {findingId}
          </span>
        )}
        {method?.state && (
          <span className="rounded px-1 py-px text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim ring-1 ring-divider">
            {method.state}
          </span>
        )}
      </header>
      <div className="min-h-0 flex-1 overflow-auto">{children}</div>
    </div>
  );
}

function EmptyState({ title, body, muted }: { title: string; body?: string; muted?: boolean }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 p-8 text-center">
      <div className="text-[calc(14px_*_var(--text-scale))] text-ink-primary">{title}</div>
      {body && (
        <div
          className={`max-w-md text-[calc(12px_*_var(--text-scale))] leading-relaxed ${
            muted ? "font-mono text-ink-muted break-all" : "text-ink-dim"
          }`}
        >
          {body}
        </div>
      )}
    </div>
  );
}

// ── Debugger controls (forward / back / reset / break) ───────────────────────

function Controls({
  index,
  total,
  atStart: isStart,
  atEnd: isEnd,
  hasTrigger,
  onBack,
  onForward,
  onReset,
  onBreak,
}: {
  index: number;
  total: number;
  atStart: boolean;
  atEnd: boolean;
  hasTrigger: boolean;
  onBack: () => void;
  onForward: () => void;
  onReset: () => void;
  onBreak: () => void;
}) {
  return (
    <div className="sticky top-0 z-10 flex flex-wrap items-center gap-2 border-b border-divider bg-bg-base/95 px-4 py-2.5 backdrop-blur">
      <CtrlButton onClick={onReset} title="Reset to first step">
        ⏮ reset
      </CtrlButton>
      <CtrlButton onClick={onBack} disabled={isStart} title="Step back">
        ◀ back
      </CtrlButton>
      <CtrlButton onClick={onForward} disabled={isEnd} title="Step forward">
        step ▶
      </CtrlButton>
      <CtrlButton
        onClick={onBreak}
        disabled={!hasTrigger}
        title="Break at the step that established the vulnerability"
        tone="danger"
      >
        ⦿ break
      </CtrlButton>
      <div className="ml-2 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-muted">
        step {index + 1} / {total}
      </div>
      {/* Retest — explicit, arm-gated, and intentionally DISABLED. Replay never
          runs a live tool; a real retest is a deliberate user action through the
          arm gate (runPairing → backend 403 SUBTARGET_UNARMED if un-armed). */}
      <button
        type="button"
        disabled
        title="Retest re-runs the tool through the arm gate — disabled here; replay is read-only"
        className="ml-auto cursor-not-allowed rounded-md border border-divider px-2.5 py-1 text-[calc(10.5px_*_var(--text-scale))] text-ink-dim opacity-60"
      >
        ⟳ retest (gated · disabled)
      </button>
    </div>
  );
}

function CtrlButton({
  children,
  onClick,
  disabled,
  title,
  tone,
}: {
  children: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
  title?: string;
  tone?: "danger";
}) {
  const toneCls =
    tone === "danger"
      ? "border-danger/40 text-danger hover:bg-danger/10"
      : "border-divider text-ink-primary hover:bg-bg-card";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`rounded-md border px-2.5 py-1 font-mono text-[calc(11px_*_var(--text-scale))] transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${toneCls}`}
    >
      {children}
    </button>
  );
}

// ── The current step, rendered ───────────────────────────────────────────────

function StepCard({ view, isTrigger }: { view: RedactedStep; isTrigger: boolean }) {
  const paramKeys = Object.keys(view.params);
  return (
    <div className="p-4">
      <div
        className={`overflow-hidden rounded-xl border bg-bg-card ${
          isTrigger ? "border-danger/50 ring-1 ring-danger/30" : "border-divider"
        }`}
      >
        {/* Header: ordinal, tool, anchored/inferred, trigger flag. */}
        <div className="flex flex-wrap items-center gap-2 border-b border-divider px-4 py-2.5">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-divider bg-bg-base font-mono text-[calc(11px_*_var(--text-scale))] font-semibold text-ink-primary">
            {view.ordinal}
          </span>
          <span className="truncate font-mono text-[calc(12px_*_var(--text-scale))] text-ink-primary">
            {view.toolId}
          </span>
          {isTrigger && (
            <span className="rounded bg-danger/[0.14] px-1.5 py-px font-mono text-[calc(9.5px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-danger ring-1 ring-danger/30">
              ⦿ trigger — established the vulnerability
            </span>
          )}
          <span className="ml-auto shrink-0">
            {view.inferred ? (
              <span
                className="rounded bg-amber/10 px-1.5 py-px text-[calc(10px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-amber ring-1 ring-amber/30"
                title="This step's rationale is not grounded in a prior result — treat as a guess, not fact."
              >
                inferred
              </span>
            ) : (
              <span className="rounded bg-success/10 px-1.5 py-px text-[calc(10px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-success ring-1 ring-success/30">
                anchored
              </span>
            )}
          </span>
        </div>

        {/* LAYER 1 — ACTION (tool + params), a FACT from the log. */}
        <Section label="action" tone="fact">
          <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-md bg-bg-base/60 p-2.5 font-mono text-[calc(10.5px_*_var(--text-scale))] text-ink-muted">
            {view.toolId}
            {paramKeys.length > 0 ? "  " + JSON.stringify(view.params, null, 2) : ""}
          </pre>
        </Section>

        {/* LAYER 2 — EVIDENCE (request/response state / raw_output), redacted. */}
        <Section label="evidence · request / response" tone="fact">
          {view.rawOutput ? (
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md bg-bg-base/60 p-2.5 font-mono text-[calc(10.5px_*_var(--text-scale))] text-ink-muted">
              {view.rawOutput}
            </pre>
          ) : (
            <div className="text-[calc(11px_*_var(--text-scale))] italic text-ink-dim">
              (no raw output captured)
            </div>
          )}
          <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[calc(10px_*_var(--text-scale))] text-ink-dim">
            {view.hash && (
              <span className="font-mono">sha256:{String(view.hash).slice(0, 12)}…</span>
            )}
            {view.timestamp != null && (
              <span className="font-mono">{String(view.timestamp)}</span>
            )}
          </div>
        </Section>

        {/* LAYER 3 — INTERPRETATION (the "why"), flagged inferred when unanchored. */}
        <Section
          label={view.inferred ? "interpretation · inferred" : "interpretation"}
          tone="inference"
        >
          {view.hasInterpretation && view.interpretation ? (
            <>
              <p className="whitespace-pre-wrap text-[calc(11.5px_*_var(--text-scale))] leading-snug text-ink-muted">
                {view.interpretation}
              </p>
              {view.inferred && (
                <div className="mt-2 rounded-md bg-amber/10 px-2 py-1.5 text-[calc(10.5px_*_var(--text-scale))] text-amber ring-1 ring-amber/30">
                  ⚠ inferred — this rationale isn't grounded in a prior step; treat as a guess,
                  not established fact.
                </div>
              )}
            </>
          ) : (
            <div className="rounded-md bg-amber/10 px-2 py-1.5 text-[calc(11px_*_var(--text-scale))] text-amber ring-1 ring-amber/30">
              ⚠ no rationale recorded — nothing inferred (we never invent a "why").
            </div>
          )}
        </Section>
      </div>
    </div>
  );
}

function Section({
  label,
  tone,
  children,
}: {
  label: string;
  tone: "fact" | "inference";
  children: React.ReactNode;
}) {
  const spine = tone === "fact" ? "border-l-success/40" : "border-l-amber/40";
  const tag =
    tone === "fact"
      ? "text-success ring-success/30 bg-success/[0.12]"
      : "text-amber ring-amber/30 bg-amber/[0.12]";
  return (
    <div className={`border-t border-divider border-l-2 px-4 py-2.5 ${spine}`}>
      <span
        className={`inline-block rounded px-1.5 py-0.5 font-mono text-[calc(9.5px_*_var(--text-scale))] font-semibold uppercase tracking-[0.06em] ring-1 ${tag}`}
      >
        {label}
      </span>
      <div className="mt-2">{children}</div>
    </div>
  );
}

// ── Registration (runs at import) ────────────────────────────────────────────
registerView({ id: "debugger", component: EvidenceDebuggerPanel });
registerCommand({
  id: "debugger.open",
  title: "Open Evidence Debugger (step a finding's chain)",
  keywords: ["debug", "evidence", "chain", "steps", "replay"],
  context: "View",
  run: () => emit("openView", { view: "debugger" }),
});
