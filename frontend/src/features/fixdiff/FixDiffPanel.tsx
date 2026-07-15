/**
 * F5 — Before/after fix diff.
 *
 * For a finding whose fix-state is `fixed` or `verified`, this panel shows the
 * CODE CHANGE at its root-cause anchor (before vs after) that closed it, tied to
 * the retest result. It is a pure REACTOR on the selection bus: when any feature
 * publishes `selectFinding` (the pivot lane's cross-link), this panel resolves
 * that finding's anchor, loads the before/after, and renders the diff. It can
 * also be opened directly via the `fixdiff.open` command, which lets the operator
 * pick a fixed/verified finding.
 *
 * ── WHERE "BEFORE" AND "AFTER" COME FROM (honest, never fabricated) ───────────
 *   fix-state   : getEvidenceChain(findingId).method?.state — only "fixed" /
 *                 "verified" get a diff; anything else is the "not fixed" empty
 *                 state.
 *   anchor      : resolveAnchor(findingRef). Only a { kind:"file" } anchor can
 *                 carry a code diff; route/config/null anchors → honest explainer.
 *   after       : the CURRENT lab-container source at the anchor, read read-only
 *                 through GET /labfs/{labId}/read (the same seam EditorPanel /
 *                 retest use). This is the fixed state that closed the finding.
 *   before      : the recorded vulnerable snapshot — from the finding's method
 *                 (remediation.change / a step's captured evidence at the anchor).
 *                 We NEVER re-run a tool or reconstruct a "before" we didn't
 *                 record. If no before-snapshot was captured, we show a clear
 *                 "no before/after snapshot was captured for this finding"
 *                 explanation rather than inventing a diff.
 *   retest tie  : the retest result state is what flips a finding to verified
 *                 (lib/retest); this panel READS that state and links the diff to
 *                 it — it never fires retest (read-only replay).
 *
 * SECURITY: read-only (no tool ever re-fires); every rendered line is passed
 * through redactSecrets() (diffRender.ts) so tokens/keys/passwords/cookies in the
 * source or evidence are masked; a `suspected` finding is shown as suspected.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import { authFetch } from "../../api";
import { resolveFindingLabId } from "../../lib/retest";
import {
  getFinding,
  getEvidenceChain,
  resolveAnchor,
  confLevel,
  toFindingRef,
  listFindings,
  type FindingRef,
  type Anchor,
  type PairingFinding,
  type EvidenceChain,
  type ConfLevel,
} from "../../shell/model";
import { useActiveEngagementId } from "../../lib/engagement";
import { computeDiff, redactSecrets, type DiffResult } from "./diffRender";

const SOURCE = "fixdiff";

/** Fix-states that have a closed finding worth diffing. */
const FIXED_STATES = new Set(["fixed", "verified"]);

// ── Loaded model for a single finding's fix diff ─────────────────────────────

type Loaded = {
  finding: PairingFinding;
  conf: ConfLevel;
  state: string; // "open" | "fixed" | "verified" | ...
  anchor: Anchor | null;
  /** The current (fixed) source at the anchor, if a file anchor resolved. */
  after: string | null;
  /** The recorded vulnerable snapshot, if one was captured. */
  before: string | null;
  /** How we sourced the "before" — surfaced to keep provenance honest. */
  beforeSource: "remediation" | "evidence" | null;
  diff: DiffResult | null;
  labId: string | null;
};

type State =
  | { kind: "no-engagement" }
  | { kind: "empty" } // no finding selected
  | { kind: "loading" }
  | { kind: "not-fixed"; finding: PairingFinding; state: string; conf: ConfLevel }
  | { kind: "no-before-after"; loaded: Loaded; reason: string }
  | { kind: "ready"; loaded: Loaded }
  | { kind: "error"; message: string };

// ── "Before" snapshot extraction (read-only, from recorded data) ─────────────

/**
 * Pull a recorded vulnerable "before" snapshot for a file anchor out of the
 * finding's method/evidence chain. Returns null when nothing captured a snapshot
 * — the caller then shows the honest no-before-after state instead of inventing
 * a diff.
 *
 * Sources, in order:
 *   1. method.remediation.change — when it recorded the pre-fix source.
 *   2. A step whose action targeted this file and whose evidence.raw_output
 *      captured the file's contents at the time (a snapshot the operator took).
 */
function extractBefore(
  chain: EvidenceChain,
  anchor: Anchor,
): { before: string; source: "remediation" | "evidence" } | null {
  const wantFile = anchor.kind === "file" ? anchor.file : undefined;

  // 1. remediation.change may carry the original source that was replaced.
  const change = chain.method?.remediation?.change;
  if (typeof change === "string" && change.trim() && looksLikeSource(change)) {
    return { before: change, source: "remediation" };
  }

  // 2. a step that snapshotted this file's contents as evidence.
  for (const s of chain.steps) {
    const params = s.action?.params as Record<string, unknown> | undefined;
    const stepFile = typeof params?.file === "string" ? params.file : undefined;
    const raw = typeof s.evidence?.raw_output === "string" ? s.evidence.raw_output : "";
    if (!raw.trim()) continue;
    // Prefer a step explicitly bound to the anchor's file; otherwise skip —
    // we won't guess that arbitrary evidence is the file's before-state.
    if (wantFile && stepFile && sameFile(stepFile, wantFile)) {
      return { before: raw, source: "evidence" };
    }
  }
  return null;
}

/** Heuristic: multi-line text that plausibly is source (not a one-line note). */
function looksLikeSource(s: string): boolean {
  return s.includes("\n") || /[;{}()=]/.test(s);
}

function sameFile(a: string, b: string): boolean {
  const norm = (p: string) => p.replace(/^\.?\//, "").trim();
  return norm(a) === norm(b) || norm(a).endsWith(norm(b)) || norm(b).endsWith(norm(a));
}

// ── Load pipeline (read-only) ────────────────────────────────────────────────

async function loadFixDiff(ref: FindingRef | string): Promise<State> {
  const findingId = typeof ref === "string" ? ref : ref.findingId;
  const finding = await getFinding(findingId);
  if (!finding) return { kind: "error", message: `Finding ${findingId} not found in scope.` };
  const conf = confLevel(finding);

  const chain = await getEvidenceChain(findingId);
  const state = chain.method?.state ?? "open";
  if (!FIXED_STATES.has(state)) {
    return { kind: "not-fixed", finding, state, conf };
  }

  const anchor = await resolveAnchor(toFindingRef(finding));

  const base: Loaded = {
    finding,
    conf,
    state,
    anchor,
    after: null,
    before: null,
    beforeSource: null,
    diff: null,
    labId: null,
  };

  // Only a file anchor can carry a code diff.
  if (!anchor || anchor.kind !== "file" || !anchor.file) {
    return {
      kind: "no-before-after",
      loaded: base,
      reason: anchor
        ? `This finding's root cause anchors to a ${anchor.kind}, not a source file, so there is no line-level code diff to show.`
        : "No root-cause code location was anchored for this finding, so there is no source file to diff.",
    };
  }

  // Resolve the lab the file lives in: prefer the anchor's labId, else map the
  // finding's target back to its lab target (same resolver retest uses).
  let labId = anchor.labId ?? null;
  if (!labId) {
    try {
      labId = await resolveFindingLabId(finding);
    } catch {
      labId = null;
    }
  }
  const loaded: Loaded = { ...base, labId };

  // "AFTER" = the current (fixed) source at the anchor, read read-only.
  let after: string | null = null;
  if (labId) {
    try {
      const res = await authFetch(
        `/labfs/${encodeURIComponent(labId)}/read?path=${encodeURIComponent(anchor.file)}`,
      );
      if (res.ok) {
        const body = (await res.json()) as { path: string; content: string; rc: number };
        if (body.rc === 0) after = body.content ?? "";
      }
      // Non-ok / rc!=0 → after stays null; handled as no-before-after below.
    } catch {
      after = null;
    }
  }

  // "BEFORE" = the recorded vulnerable snapshot (never re-derived).
  const beforeHit = extractBefore(chain, anchor);

  if (after == null && !beforeHit) {
    return {
      kind: "no-before-after",
      loaded,
      reason: labId
        ? "The fixed source couldn't be read from the lab and no before-snapshot was captured for this finding."
        : "This finding isn't bound to a lab file, and no before/after snapshot was captured — nothing was recorded to diff.",
    };
  }
  if (!beforeHit) {
    return {
      kind: "no-before-after",
      loaded: { ...loaded, after },
      reason:
        "The current (fixed) source is available, but no before/after snapshot of the vulnerable version was captured for this finding, so the change that closed it can't be shown as a diff.",
    };
  }
  if (after == null) {
    return {
      kind: "no-before-after",
      loaded: { ...loaded, before: beforeHit.before, beforeSource: beforeHit.source },
      reason:
        "A recorded before-snapshot exists, but the current fixed source couldn't be read back from the lab to diff against.",
    };
  }

  const diff = computeDiff(beforeHit.before, after);
  return {
    kind: "ready",
    loaded: {
      ...loaded,
      after,
      before: beforeHit.before,
      beforeSource: beforeHit.source,
      diff,
    },
  };
}

// ── Panel ────────────────────────────────────────────────────────────────────

function FixDiffPanel(props: { params: ViewParams }) {
  const activeId = useActiveEngagementId();
  const [state, setState] = useState<State>({ kind: "empty" });
  // The finding currently loaded, so modelChanged can trigger a re-read.
  const [currentRef, setCurrentRef] = useState<FindingRef | string | null>(null);

  // Guards against a slower earlier load clobbering a newer selection: rapidly
  // picking finding A then B fires load(A) then load(B), and if A's async chain
  // (getFinding + getEvidenceChain + labfs read) resolves last it would render
  // A's diff while B is selected. Same pattern as Pivot / EvidenceDebuggerPanel.
  const loadSeq = useRef(0);
  const load = useCallback(async (ref: FindingRef | string) => {
    const seq = ++loadSeq.current;
    setCurrentRef(ref);
    setState({ kind: "loading" });
    try {
      const next = await loadFixDiff(ref);
      if (loadSeq.current !== seq) return; // superseded by a newer selection
      setState(next);
    } catch (e) {
      if (loadSeq.current !== seq) return;
      setState({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  // Honor a finding handed in via openView params (command → picker → openView).
  useEffect(() => {
    const p = props.params as { findingId?: string; ref?: FindingRef } | undefined;
    if (p?.ref?.findingId) void load(p.ref);
    else if (p?.findingId) void load(p.findingId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // REACTOR: the pivot / problems / graph publish selectFinding — load its diff.
  useBus("selectFinding", (payload) => {
    if (payload.source === SOURCE) return; // ignore our own echo
    void load(payload.ref);
  });
  // A file anchor may arrive directly (pivot re-broadcast). If it carries the
  // originating finding, reload that finding so the diff re-centres on it.
  useBus("selectAnchor", (payload) => {
    if (payload.source === SOURCE) return;
    if (payload.findingId) void load(payload.findingId);
  });

  // No private cache of shared state: on any model change to the loaded finding,
  // re-read through the model API.
  useBus("modelChanged", (payload) => {
    if (payload.entity !== "finding" || !currentRef) return;
    const id = typeof currentRef === "string" ? currentRef : currentRef.findingId;
    if (payload.id === id) void load(currentRef);
  });

  if (!activeId) return <NoEngagement />;

  switch (state.kind) {
    case "no-engagement":
      return <NoEngagement />;
    case "empty":
      return <EmptyPicker onPick={(f) => void load(toFindingRef(f))} engagementId={activeId} />;
    case "loading":
      return <Centered><Spinner /> Loading fix diff…</Centered>;
    case "error":
      return (
        <Centered tone="danger">
          <div className="max-w-md text-center">
            <div className="text-[calc(13px_*_var(--text-scale))] text-danger">Couldn't load fix diff</div>
            <div className="mt-1 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-muted break-all">
              {state.message}
            </div>
          </div>
        </Centered>
      );
    case "not-fixed":
      return <NotFixed finding={state.finding} state={state.state} conf={state.conf} onReset={() => setState({ kind: "empty" })} />;
    case "no-before-after":
      return <NoBeforeAfter loaded={state.loaded} reason={state.reason} onReset={() => setState({ kind: "empty" })} />;
    case "ready":
      return <DiffView loaded={state.loaded} onReset={() => setState({ kind: "empty" })} />;
  }
}

// ── Sub-views ────────────────────────────────────────────────────────────────

function Header({ loaded, onReset }: { loaded: Loaded; onReset: () => void }) {
  const { finding, conf, state, anchor } = loaded;
  return (
    <div className="flex items-center gap-3 border-b border-divider bg-bg-card px-3 py-2">
      <div className="min-w-0">
        <div className="truncate text-[calc(13px_*_var(--text-scale))] text-ink-primary" title={finding.title}>
          {finding.title}
        </div>
        <div className="flex items-center gap-2 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          <SeverityDot severity={finding.severity} />
          <span className="uppercase">{finding.severity}</span>
          <ConfBadge conf={conf} />
          <StateBadge state={state} />
          {anchor?.kind === "file" && anchor.file && (
            <span className="font-mono text-ink-muted truncate" title={anchor.file}>
              · {anchor.file}
              {anchor.line ? `:${anchor.line}` : ""}
            </span>
          )}
        </div>
      </div>
      <div className="ml-auto flex items-center gap-2">
        {anchor?.kind === "file" && anchor.file && loaded.labId && (
          <button
            type="button"
            onClick={() => emit("openEditor", { labId: loaded.labId!, path: anchor.file! })}
            className="rounded border border-divider px-2 py-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-muted hover:bg-bg-hover"
          >
            Open in editor
          </button>
        )}
        <button
          type="button"
          onClick={onReset}
          className="rounded border border-divider px-2 py-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-muted hover:bg-bg-hover"
        >
          Pick another
        </button>
      </div>
    </div>
  );
}

function DiffView({ loaded, onReset }: { loaded: Loaded; onReset: () => void }) {
  const diff = loaded.diff!;
  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      <Header loaded={loaded} onReset={onReset} />
      <div className="flex items-center gap-3 border-b border-divider px-3 py-1.5 text-[calc(11px_*_var(--text-scale))]">
        <span className="text-success">+{diff.addedCount} added</span>
        <span className="text-danger">−{diff.removedCount} removed</span>
        <span className="text-ink-dim">
          before via {loaded.beforeSource === "remediation" ? "recorded remediation" : "captured evidence"} · after = current lab source
        </span>
        <span className="ml-auto flex items-center gap-1 text-ink-dim" title="Read-only replay: no tool was re-run; secrets are masked.">
          <span className="h-1.5 w-1.5 rounded-full bg-accent" /> read-only · secrets masked
        </span>
      </div>
      {loaded.state === "verified" ? (
        <div className="border-b border-divider px-3 py-1 text-[calc(11px_*_var(--text-scale))] text-success">
          Retest verified this fix — the recorded exploit chain no longer reproduces.
        </div>
      ) : (
        <div className="border-b border-divider px-3 py-1 text-[calc(11px_*_var(--text-scale))] text-amber">
          Marked fixed — not yet retest-verified.
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-auto font-mono text-[calc(12px_*_var(--text-scale))] leading-relaxed">
        {diff.unchanged ? (
          <div className="p-6 text-center text-ink-dim">
            The recorded before-snapshot and the current source are identical — no line-level change to show.
          </div>
        ) : (
          <table className="w-full border-collapse">
            <tbody>
              {diff.lines.map((l, idx) => (
                <tr
                  key={idx}
                  className={
                    l.kind === "added"
                      ? "bg-success/10"
                      : l.kind === "removed"
                        ? "bg-danger/10"
                        : ""
                  }
                >
                  <td className="select-none border-r border-divider px-2 text-right align-top text-ink-dim w-12">
                    {l.beforeNo ?? ""}
                  </td>
                  <td className="select-none border-r border-divider px-2 text-right align-top text-ink-dim w-12">
                    {l.afterNo ?? ""}
                  </td>
                  <td
                    className={
                      "select-none px-1 text-center align-top w-5 " +
                      (l.kind === "added" ? "text-success" : l.kind === "removed" ? "text-danger" : "text-ink-dim")
                    }
                  >
                    {l.kind === "added" ? "+" : l.kind === "removed" ? "−" : ""}
                  </td>
                  <td
                    className={
                      "whitespace-pre-wrap break-all px-2 align-top " +
                      (l.kind === "added"
                        ? "text-success"
                        : l.kind === "removed"
                          ? "text-danger"
                          : "text-ink-primary")
                    }
                  >
                    {l.text || " "}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function NoBeforeAfter({
  loaded,
  reason,
  onReset,
}: {
  loaded: Loaded;
  reason: string;
  onReset: () => void;
}) {
  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      <Header loaded={loaded} onReset={onReset} />
      <div className="flex flex-1 items-center justify-center p-8">
        <div className="max-w-lg rounded-lg border border-divider bg-bg-card p-6 text-center">
          <div className="text-[calc(13px_*_var(--text-scale))] text-amber">No before/after snapshot to diff</div>
          <p className="mt-2 text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-muted">{reason}</p>
          <p className="mt-3 text-[calc(11px_*_var(--text-scale))] leading-relaxed text-ink-dim">
            A diff is only shown when both the vulnerable version (recorded in the finding's
            remediation or captured as step evidence) and the current fixed source are
            available. Nothing here is fabricated — no diff is invented from a missing side.
          </p>
          {/* If we do have one side, offer it as read-only context, secret-masked. */}
          {loaded.after != null && (
            <SingleSideBlock title="Current (fixed) source" body={loaded.after} tone="success" />
          )}
          {loaded.before != null && (
            <SingleSideBlock title="Recorded before-snapshot" body={loaded.before} tone="danger" />
          )}
        </div>
      </div>
    </div>
  );
}

function SingleSideBlock({ title, body, tone }: { title: string; body: string; tone: "success" | "danger" }) {
  const masked = body.split("\n").map(redactSecrets).join("\n");
  return (
    <div className="mt-4 text-left">
      <div className={"text-[calc(11px_*_var(--text-scale))] " + (tone === "success" ? "text-success" : "text-danger")}>
        {title}
      </div>
      <pre className="mt-1 max-h-48 overflow-auto rounded border border-divider bg-bg-base p-2 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-primary whitespace-pre-wrap break-all">
        {masked || " "}
      </pre>
    </div>
  );
}

function NotFixed({
  finding,
  state,
  conf,
  onReset,
}: {
  finding: PairingFinding;
  state: string;
  conf: ConfLevel;
  onReset: () => void;
}) {
  return (
    <Centered>
      <div className="max-w-md rounded-lg border border-divider bg-bg-card p-6 text-center">
        <div className="truncate text-[calc(13px_*_var(--text-scale))] text-ink-primary" title={finding.title}>
          {finding.title}
        </div>
        <div className="mt-1 flex items-center justify-center gap-2 text-[calc(11px_*_var(--text-scale))]">
          <ConfBadge conf={conf} />
          <StateBadge state={state} />
        </div>
        <p className="mt-3 text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-muted">
          This finding isn't in a <span className="text-ink-primary">fixed</span> or{" "}
          <span className="text-ink-primary">verified</span> state yet (currently{" "}
          <span className="font-mono">{state}</span>), so there's no closing code change to
          diff. Fix it and retest to see the before/after here.
        </p>
        <button
          type="button"
          onClick={onReset}
          className="mt-4 rounded border border-divider px-3 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-muted hover:bg-bg-hover"
        >
          Pick another finding
        </button>
      </div>
    </Centered>
  );
}

function EmptyPicker({
  engagementId,
  onPick,
}: {
  engagementId: string;
  onPick: (f: PairingFinding) => void;
}) {
  const [items, setItems] = useState<PairingFinding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setErr(null);
    setItems(null);
    try {
      // All findings in scope; we mark which are fixed/verified via their chain.
      const all = await listFindings(engagementId);
      const withState = await Promise.all(
        all.map(async (f) => {
          try {
            const chain = await getEvidenceChain(f.id);
            return { f, state: chain.method?.state ?? "open" };
          } catch {
            return { f, state: "open" };
          }
        }),
      );
      // Fixed/verified first; keep the rest so the operator sees why they're greyed.
      const fixed = withState.filter((x) => FIXED_STATES.has(x.state)).map((x) => x.f);
      setItems(fixed);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [engagementId]);

  useEffect(() => { void reload(); }, [reload]);
  useBus("modelChanged", (p) => { if (p.entity === "finding") void reload(); });

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      <div className="border-b border-divider px-4 py-3">
        <div className="text-[calc(13px_*_var(--text-scale))] text-ink-primary">Fix diff — before/after</div>
        <div className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          Pick a fixed or verified finding to see the code change that closed it. Or select a
          finding anywhere in the workspace and it'll load here automatically.
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {err ? (
          <div className="text-[calc(12px_*_var(--text-scale))] text-danger">{err}</div>
        ) : items == null ? (
          <div className="flex items-center gap-2 text-[calc(12px_*_var(--text-scale))] text-ink-dim">
            <Spinner /> Loading findings…
          </div>
        ) : items.length === 0 ? (
          <div className="rounded-lg border border-divider bg-bg-card p-6 text-center text-[calc(12px_*_var(--text-scale))] text-ink-muted">
            No fixed or verified findings in this engagement yet. Once a finding is fixed and
            retested, its before/after diff shows up here.
          </div>
        ) : (
          <ul className="space-y-1">
            {items.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => onPick(f)}
                  className="flex w-full items-center gap-2 rounded border border-divider bg-bg-card px-3 py-2 text-left hover:bg-bg-hover"
                >
                  <SeverityDot severity={f.severity} />
                  <span className="min-w-0 flex-1 truncate text-[calc(12px_*_var(--text-scale))] text-ink-primary" title={f.title}>
                    {f.title}
                  </span>
                  <ConfBadge conf={confLevel(f)} />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function NoEngagement() {
  return (
    <Centered>
      <div className="max-w-md rounded-lg border border-divider bg-bg-card p-6 text-center">
        <div className="text-[calc(13px_*_var(--text-scale))] text-ink-primary">No active engagement</div>
        <p className="mt-2 text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-muted">
          Pin an engagement to see the before/after fix diff for its fixed findings.
        </p>
      </div>
    </Centered>
  );
}

// ── Small presentational bits ────────────────────────────────────────────────

function Centered({ children, tone }: { children: React.ReactNode; tone?: "danger" }) {
  return (
    <div
      className={
        "flex h-full min-h-0 items-center justify-center gap-2 bg-bg-base p-8 text-[calc(12px_*_var(--text-scale))] " +
        (tone === "danger" ? "text-danger" : "text-ink-dim")
      }
    >
      {children}
    </div>
  );
}

function Spinner() {
  return <span className="inline-block h-3 w-3 animate-spin rounded-full border border-ink-dim border-t-transparent" />;
}

function ConfBadge({ conf }: { conf: ConfLevel }) {
  // Never render suspected as confirmed (T5). Suspected is visually distinct.
  return conf === "confirmed" ? (
    <span className="rounded bg-success/15 px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-success">confirmed</span>
  ) : (
    <span className="rounded border border-amber/40 bg-amber/10 px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-amber">
      suspected
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  const cls = state === "verified" ? "text-success" : state === "fixed" ? "text-amber" : "text-ink-dim";
  return <span className={"font-mono uppercase " + cls}>{state}</span>;
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

registerView({ id: "fixdiff", component: FixDiffPanel });
registerCommand({
  id: "fixdiff.open",
  title: "Fix diff: before/after remediation",
  keywords: ["fix", "diff", "before", "after", "remediation"],
  context: "View",
  run: () => emit("openView", { view: "fixdiff" }),
});
