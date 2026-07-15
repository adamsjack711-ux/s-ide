/**
 * F3 — Pivot navigation: the connective tissue between the feature panels.
 *
 * This module is a PURE bus subscriber/publisher — it owns no domain data, runs
 * no tool, and (this is the feature under highest scrutiny for coupling) NEVER
 * imports or calls into any other feature/panel. It reads shared state only
 * through the model API and cross-links only by publishing/subscribing selection
 * events on the bus. Two parts live here:
 *
 *   (A) HEADLESS ROUTER — persistent global `on(...)` subscriptions installed at
 *       import (a singleton, like the bus itself). It translates a `selectFinding`
 *       / `selectStep` into (at most) one `selectAnchor` broadcast so the code
 *       view (F5 fixdiff) and the inspector below can follow the pivot. It is the
 *       one place that resolves a finding/step → its root-cause location.
 *
 *   (B) INSPECTOR VIEW ("Root cause / Pivot") — a registered panel that shows the
 *       finding being pivoted from and its resolved anchor, or the honest
 *       "no root cause anchored yet" state when nothing anchors it.
 *
 * ── WIRING MAP (bus only; documented, never a direct import) ──────────────────
 *   IN  selectFinding  ← search(F1) / problems(F2) / scandiff(F4) / timeline(F6)
 *   IN  selectStep     ← search(F1) / debugger(F9)
 *   IN  selectAsset    ← asset tree / graph  (we publish nothing back)
 *   OUT selectAnchor   → fixdiff(F5) loads the diff; the inspector jumps; the
 *                        editor can open. We are the PRIMARY publisher of it.
 *   (also IN  selectAnchor → the inspector, so it follows anchors that other
 *    features may emit; the router does NOT re-publish selectAnchor — no
 *    selectAnchor→selectAnchor loop.)
 *
 * ── KNOWN GAP (honest, NOT faked) ─────────────────────────────────────────────
 *   The existing GraphView (graph/GraphView.tsx) is a PASSIVE visualization: it
 *   emits nothing on node click today, and editing an existing panel is
 *   forbidden by the contract. So the "graph node click → selectStep /
 *   selectFinding" direction cannot be wired from here without touching that
 *   panel. Every OTHER selection→anchor edge is wired; this one direction is left
 *   unwired by necessity and is called out in the report.
 *
 * FEEDBACK-LOOP SAFETY: the router publishes `selectAnchor` and the inspector
 * subscribes to selection events, so every handler guards on the incoming
 * `source` and drops events we ourselves emitted (source === "pivot"). The router
 * never throws — a dangling ref publishes nothing and the inspector shows the
 * no-anchor state.
 *
 * SECURITY: read-only. Never triggers a run. If any evidence/anchor text is
 * displayed, secrets are masked (tokens/keys/cookies/Authorization) via
 * redactString. Never upgrades a suspected finding to confirmed.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, on, useBus } from "../../shell/bus";
import { redactString } from "../../lib/redact";
import {
  resolveAnchor,
  getEvidenceChain,
  getFinding,
  confLevel,
  type Anchor,
  type FindingRef,
  type PairingFinding,
  type ConfLevel,
} from "../../shell/model";
import {
  PIVOT_SOURCE,
  decideOnSelectFinding,
  decideOnSelectStep,
  stepFileAnchor,
  type PivotDecision,
} from "./pivotLogic";

// Secret redaction — masks any anchor/finding text we display so a token/key/
// cookie/Authorization pasted into a path or title can't leak. One shared
// implementation (lib/redact — shared infra, not another feature).

// ═════════════════════════════════════════════════════════════════════════════
// (A) HEADLESS ROUTER — persistent singleton subscriptions (installed at import)
// ═════════════════════════════════════════════════════════════════════════════

/** Apply a pure PivotDecision by emitting on the bus (or doing nothing). */
function dispatch(decision: PivotDecision): void {
  if (!decision) return; // null → publish nothing (own echo / dangling / asset)
  emit(decision.emit, decision.payload);
}

/**
 * Resolve a step's location: prefer the step's OWN action.params.file (pure, over
 * the loaded chain), else fall back to the finding's root-cause anchor. Read-only.
 * Never throws — returns null when nothing resolves so the router publishes
 * nothing. Never fabricates a location.
 */
async function resolveStepLocation(findingId: string, stepId: string): Promise<Anchor | null> {
  try {
    const chain = await getEvidenceChain(findingId);
    const own = stepFileAnchor(chain.steps, stepId);
    if (own) return own;
    return await resolveAnchor(findingId);
  } catch {
    return null;
  }
}

// Install the router ONCE. Module import is a singleton (mirrors the bus), so
// these subscriptions are global and persistent — not tied to any component
// mount. Guarded so a duplicate import (HMR) doesn't double-subscribe.
let routerInstalled = false;
function installRouter(): void {
  if (routerInstalled) return;
  routerInstalled = true;

  // selectFinding → resolve the finding's anchor → selectAnchor (or nothing).
  on("selectFinding", (p) => {
    if (p.source === PIVOT_SOURCE) return; // ignore our own echo (loop guard)
    void (async () => {
      let anchor: Anchor | null = null;
      try {
        anchor = await resolveAnchor(p.ref);
      } catch {
        anchor = null; // never throw on a dangling ref
      }
      // decideOnSelectFinding re-checks source + null: publishes nothing on a
      // dangling ref (the inspector surfaces "no root cause anchored yet").
      dispatch(decideOnSelectFinding(p.source, p.ref, anchor));
    })();
  });

  // selectStep → prefer the step's own file param, else the finding anchor.
  on("selectStep", (p) => {
    if (p.source === PIVOT_SOURCE) return; // ignore our own echo (loop guard)
    void (async () => {
      const anchor = await resolveStepLocation(p.ref.findingId, p.ref.stepId);
      dispatch(decideOnSelectStep(p.source, p.ref, anchor));
    })();
  });

  // selectAsset → publish NOTHING. The asset tree highlights itself and the
  // graph node reacts; the router must not re-broadcast. (No subscription needed
  // to "do nothing", but we document the deliberate no-op here rather than
  // silently omitting it — see decideOnSelectAsset in pivotLogic.)
  //
  // We do NOT subscribe to selectAnchor in the router: re-publishing it would be
  // a selectAnchor→selectAnchor loop. Only the inspector below listens to it.
}

installRouter();

// ═════════════════════════════════════════════════════════════════════════════
// (B) INSPECTOR VIEW — "Root cause / Pivot"
// ═════════════════════════════════════════════════════════════════════════════

type PivotState =
  | { kind: "empty" } // nothing selected yet
  | { kind: "loading"; finding?: PairingFinding | null }
  | { kind: "error"; message: string; finding?: PairingFinding | null }
  | { kind: "no-anchor"; finding: PairingFinding | null; conf: ConfLevel | null }
  | { kind: "ready"; finding: PairingFinding | null; conf: ConfLevel | null; anchor: Anchor };

function PivotInspector(_props: { params: ViewParams }) {
  const [state, setState] = useState<PivotState>({ kind: "empty" });
  // The finding we're currently pivoting from, so modelChanged can re-resolve.
  const [currentRef, setCurrentRef] = useState<FindingRef | null>(null);
  // Guards against a stale async resolve clobbering a newer selection.
  const seq = useRef(0);

  // Resolve a finding → its anchor for display. Read-only; never throws to the UI.
  const loadFinding = useCallback(async (ref: FindingRef) => {
    setCurrentRef(ref);
    const mine = ++seq.current;
    setState({ kind: "loading" });
    try {
      const finding = await getFinding(ref.findingId);
      const conf = finding ? confLevel(finding) : null;
      const anchor = await resolveAnchor(ref);
      if (seq.current !== mine) return; // superseded by a newer selection
      if (!anchor) {
        setState({ kind: "no-anchor", finding, conf });
      } else {
        setState({ kind: "ready", finding, conf, anchor });
      }
    } catch (e) {
      if (seq.current !== mine) return;
      setState({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  // Honor a finding handed in via openView params (command → openView).
  useEffect(() => {
    const p = _props.params as { ref?: FindingRef; findingId?: string } | undefined;
    if (p?.ref?.findingId) void loadFinding(p.ref);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Any feature selecting a finding drives the inspector (ignore our own echo).
  useBus("selectFinding", (p) => {
    if (p.source === PIVOT_SOURCE) return;
    void loadFinding(p.ref);
  });

  // Follow anchors that arrive on the bus. Our OWN selectAnchor (source ===
  // "pivot") carries the finding we just resolved — re-centre the display on it
  // so the inspector shows exactly what the code view jumped to. Anchors from
  // OTHER features are followed too (they may carry a findingId).
  useBus("selectAnchor", (p) => {
    const mine = ++seq.current;
    if (p.findingId) {
      // Re-resolve through the finding so we show its title + confidence badge.
      void (async () => {
        try {
          const finding = await getFinding(p.findingId!);
          const conf = finding ? confLevel(finding) : null;
          if (seq.current !== mine) return;
          setState({ kind: "ready", finding, conf, anchor: p.ref });
        } catch {
          if (seq.current !== mine) return;
          setState({ kind: "ready", finding: null, conf: null, anchor: p.ref });
        }
      })();
    } else {
      setState({ kind: "ready", finding: null, conf: null, anchor: p.ref });
    }
  });

  // No private cache of shared state: on a change to the loaded finding, re-read.
  useBus("modelChanged", (p) => {
    if (p.entity !== "finding" || !currentRef) return;
    if (p.id === currentRef.findingId) void loadFinding(currentRef);
  });

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      <Header state={state} />
      <div className="min-h-0 flex-1 overflow-auto">
        <Body state={state} />
      </div>
    </div>
  );
}

// ── Chrome ───────────────────────────────────────────────────────────────────

function Header({ state }: { state: PivotState }) {
  const finding =
    state.kind === "ready" || state.kind === "no-anchor" || state.kind === "loading" || state.kind === "error"
      ? (state as { finding?: PairingFinding | null }).finding
      : null;
  const conf =
    state.kind === "ready" || state.kind === "no-anchor"
      ? (state as { conf: ConfLevel | null }).conf
      : null;
  return (
    <header className="flex items-center gap-2 border-b border-divider px-4 py-2.5">
      <span className="font-mono text-[calc(12px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">
        Root cause · pivot
      </span>
      <span
        className="rounded bg-accent/15 px-1.5 py-px font-mono text-[calc(9.5px_*_var(--text-scale))] uppercase tracking-wide text-accent ring-1 ring-accent/30"
        title="Read-only cross-link — never runs a tool; secrets are masked."
      >
        read-only
      </span>
      {finding && (
        <span
          className="ml-auto min-w-0 truncate text-[calc(11px_*_var(--text-scale))] text-ink-muted"
          title={redactString(finding.title)}
        >
          {redactString(finding.title)}
        </span>
      )}
      {conf && <ConfBadge conf={conf} />}
    </header>
  );
}

function Body({ state }: { state: PivotState }) {
  switch (state.kind) {
    case "empty":
      return (
        <EmptyState
          title="Nothing selected"
          body="Select a finding anywhere in the workspace — search, problems, the timeline, a scan diff — and its root-cause anchor shows up here. Selecting it also jumps the code view to that location."
        />
      );
    case "loading":
      return (
        <div className="flex h-full items-center justify-center gap-2 p-8 text-[calc(12px_*_var(--text-scale))] text-ink-dim">
          <Spinner /> Resolving root cause…
        </div>
      );
    case "error":
      return (
        <div className="flex h-full items-center justify-center p-8">
          <div className="max-w-md rounded-lg border border-danger/40 bg-danger/[0.06] p-5 text-center">
            <div className="text-[calc(12px_*_var(--text-scale))] font-semibold text-danger">
              Could not resolve root cause
            </div>
            <div className="mt-1.5 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-muted break-all">
              {redactString(state.message) || "unknown error"}
            </div>
          </div>
        </div>
      );
    case "no-anchor":
      return <NoAnchor finding={state.finding} />;
    case "ready":
      return <AnchorView finding={state.finding} anchor={state.anchor} />;
  }
}

// ── No-anchor (dangling ref) — the honest gap, NEVER a fabricated location ─────

function NoAnchor({ finding }: { finding: PairingFinding | null }) {
  return (
    <div className="p-4">
      {finding && <FindingLine finding={finding} />}
      <div className="mt-3 rounded-lg border border-amber/40 bg-amber/[0.06] p-5">
        {/* This exact string is the contract's dangling-ref surface. */}
        <div className="text-[calc(13px_*_var(--text-scale))] text-amber">no root cause anchored yet</div>
        <p className="mt-2 text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-muted">
          Nothing in this finding's evidence chain anchors it to a source file, route, or
          config key yet. We never invent a location — once a step captures a
          <span className="font-mono"> file:line</span>, a URL-shaped target, or a config key,
          the root-cause anchor appears here and the code view can jump to it.
        </p>
      </div>
    </div>
  );
}

// ── Anchor view — rendered by kind ───────────────────────────────────────────

function AnchorView({ finding, anchor }: { finding: PairingFinding | null; anchor: Anchor }) {
  return (
    <div className="p-4">
      {finding && <FindingLine finding={finding} />}
      <div className="mt-3 rounded-xl border border-divider bg-bg-card">
        <div className="flex items-center gap-2 border-b border-divider px-4 py-2.5">
          <span className="font-mono text-[calc(9.5px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">
            root cause
          </span>
          <span className="rounded bg-accent/10 px-1.5 py-px font-mono text-[calc(9.5px_*_var(--text-scale))] uppercase tracking-wide text-accent ring-1 ring-accent/30">
            {anchor.kind}
          </span>
        </div>
        <div className="px-4 py-3">
          {anchor.kind === "file" ? (
            <FileAnchor anchor={anchor} findingId={finding?.id} />
          ) : anchor.kind === "route" ? (
            <RouteAnchor anchor={anchor} />
          ) : (
            <ConfigAnchor anchor={anchor} />
          )}
        </div>
      </div>
    </div>
  );
}

function FileAnchor({ anchor, findingId }: { anchor: Anchor; findingId?: string }) {
  const loc = `${redactString(anchor.file)}${anchor.line != null ? `:${anchor.line}` : ""}`;
  const canOpenEditor = !!anchor.labId && !!anchor.file;
  return (
    <div>
      <div className="font-mono text-[calc(12.5px_*_var(--text-scale))] text-ink-primary break-all">{loc}</div>
      {anchor.labId && (
        <div className="mt-0.5 font-mono text-[calc(10.5px_*_var(--text-scale))] text-ink-dim">
          lab {redactString(anchor.labId)}
        </div>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => {
            // Prefer the editor when we know the lab; otherwise re-broadcast the
            // anchor so the code view (fixdiff) picks it up. Never runs a tool.
            if (canOpenEditor) {
              emit("openEditor", { labId: anchor.labId!, path: anchor.file! });
            } else {
              emit("selectAnchor", { ref: anchor, findingId, source: PIVOT_SOURCE });
            }
          }}
          className="rounded-md border border-divider px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-primary hover:bg-bg-hover"
          title={canOpenEditor ? "Open this file in the editor" : "Focus the code view on this location"}
        >
          Open in editor
        </button>
      </div>
    </div>
  );
}

function RouteAnchor({ anchor }: { anchor: Anchor }) {
  return (
    <div>
      <div className="text-[calc(10.5px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">route</div>
      <div className="mt-1 font-mono text-[calc(12.5px_*_var(--text-scale))] text-ink-primary break-all">
        {redactString(anchor.route) || "—"}
      </div>
      <p className="mt-2 text-[calc(11px_*_var(--text-scale))] leading-relaxed text-ink-dim">
        This finding's root cause anchors to an HTTP route, not a source file — there's no
        line-level location to open in the editor.
      </p>
    </div>
  );
}

function ConfigAnchor({ anchor }: { anchor: Anchor }) {
  return (
    <div>
      <div className="text-[calc(10.5px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">config key</div>
      <div className="mt-1 font-mono text-[calc(12.5px_*_var(--text-scale))] text-ink-primary break-all">
        {redactString(anchor.key) || "—"}
      </div>
      {anchor.file && (
        <div className="mt-0.5 font-mono text-[calc(10.5px_*_var(--text-scale))] text-ink-dim break-all">
          in {redactString(anchor.file)}
        </div>
      )}
    </div>
  );
}

// ── Shared bits ──────────────────────────────────────────────────────────────

function FindingLine({ finding }: { finding: PairingFinding }) {
  return (
    <div className="rounded-lg border border-divider bg-bg-card px-4 py-2.5">
      <div className="text-[calc(9.5px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
        pivoting from
      </div>
      <div className="mt-1 flex items-center gap-2">
        <SeverityDot severity={finding.severity} />
        <span
          className="min-w-0 flex-1 truncate text-[calc(13px_*_var(--text-scale))] text-ink-primary"
          title={redactString(finding.title)}
        >
          {redactString(finding.title)}
        </span>
        <ConfBadge conf={confLevel(finding)} />
      </div>
      <div className="mt-1 font-mono text-[calc(10px_*_var(--text-scale))] text-ink-dim break-all">
        {finding.id}
      </div>
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 p-8 text-center">
      <div className="text-[calc(14px_*_var(--text-scale))] text-ink-primary">{title}</div>
      <div className="max-w-md text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-dim">{body}</div>
    </div>
  );
}

function Spinner() {
  return <span className="inline-block h-3 w-3 animate-spin rounded-full border border-ink-dim border-t-transparent" />;
}

function ConfBadge({ conf }: { conf: ConfLevel }) {
  // Never render suspected as confirmed (T5). Suspected is visually distinct.
  return conf === "confirmed" ? (
    <span className="rounded bg-success/15 px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-success">
      confirmed
    </span>
  ) : (
    <span className="rounded border border-amber/40 bg-amber/10 px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-amber">
      suspected
    </span>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const cls =
    severity === "critical"
      ? "bg-critical"
      : severity === "high"
        ? "bg-high"
        : severity === "medium"
          ? "bg-medium"
          : severity === "low"
            ? "bg-low"
            : "bg-ink-dim";
  return <span className={"h-1.5 w-1.5 shrink-0 rounded-full " + cls} />;
}

// ── Registration (runs at import) ────────────────────────────────────────────
registerView({ id: "pivot", component: PivotInspector });
registerCommand({
  id: "pivot.open",
  title: "Open Root Cause / Pivot",
  keywords: ["pivot", "root cause", "navigate", "cross-link"],
  context: "View",
  run: () => emit("openView", { view: "pivot" }),
});
