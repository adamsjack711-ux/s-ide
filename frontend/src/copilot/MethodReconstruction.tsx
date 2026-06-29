import { useEffect, useState } from "react";
import { api } from "../api";
import {
  analyzeMethod,
  gapLabel,
  type AnalyzedStep,
  type FindingMethod,
  type MethodAnalysis,
  type MethodGap,
} from "../lib/methodAnalysis";

/**
 * MethodReconstruction — renders the operator's *actual* method for a finding,
 * reconstructed from its hash-chained Step log, with FACT and INFERENCE kept in
 * two visibly separate layers.
 *
 * Contract (the integrator tests this): an unanchored step that has NO
 * interpretation must render the inference label PLUS a flagged "unverified"
 * placeholder, and MUST NOT invent any rationale text. We never synthesise a
 * "why" — if the operator didn't record one, we say so and offer "confirm why".
 *
 * Visual: a vertical FLOW — numbered, connected step nodes down a spine (the
 * investigation layout from the design), each node carrying its FACT spine and
 * INFERENCE layer; a "related steps" rollup; and a critical-fails / gaps block.
 *
 * Mount point: the Copilot rail (a tab/section beside the chat in
 * `src/copilot/CopilotRail.tsx`) or the finding-detail surface. Render it with
 * the active finding id, e.g.
 *
 *   <MethodReconstruction
 *     findingId={fid}
 *     onConfirmWhy={(stepId, why) => patchStepRationale(fid, stepId, why)}
 *   />
 *
 * `onConfirmWhy` is optional; when omitted the "confirm why" affordance is
 * still shown but is a no-op-safe local capture (the parent owns persistence).
 */
export default function MethodReconstruction({
  findingId,
  onConfirmWhy,
}: {
  findingId: string;
  onConfirmWhy?: (stepId: string, why: string) => void;
}) {
  const [method, setMethod] = useState<FindingMethod | null>(null);
  const [analysis, setAnalysis] = useState<MethodAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api<FindingMethod>(`/method/findings/${encodeURIComponent(findingId)}`)
      .then((m) => {
        if (!alive) return;
        setMethod(m);
        setAnalysis(analyzeMethod(m));
      })
      .catch((e: any) => {
        if (!alive) return;
        setError(e?.message || "failed to load method");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [findingId]);

  if (loading) {
    return <div className="p-4 text-xs text-ink-dim">Reconstructing method…</div>;
  }
  if (error) {
    return <div className="p-4 text-xs text-danger">⚠ {error}</div>;
  }
  if (!method || !analysis) return null;

  const { steps, gaps } = analysis;
  const gapsByStep = new Map<string, MethodGap[]>();
  for (const g of gaps) {
    const arr = gapsByStep.get(g.stepId) ?? [];
    arr.push(g);
    gapsByStep.set(g.stepId, arr);
  }

  // "Related" — steps that share a tool with another step in the chain (a
  // recurring technique). Derived only from the factual log, never invented.
  const byTool = new Map<string, AnalyzedStep[]>();
  for (const s of steps) {
    const t = (s.action?.tool_id as string) || "(unknown tool)";
    const arr = byTool.get(t) ?? [];
    arr.push(s);
    byTool.set(t, arr);
  }
  const related = [...byTool.entries()].filter(([, arr]) => arr.length > 1);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto bg-bg-sidebar">
      <header className="border-b border-divider px-3.5 py-3">
        <div className="font-mono text-[12px] font-semibold uppercase tracking-wide text-ink-dim">
          Investigation
        </div>
        <div className="mt-1.5 flex items-center gap-2 text-[11px] text-ink-dim">
          <span className="font-mono text-ink-muted">{method.finding_id}</span>
          <StateBadge state={method.state} />
          <span>·</span>
          <span>
            {steps.length} step{steps.length === 1 ? "" : "s"}
          </span>
          {gaps.length > 0 && (
            <span className="ml-auto rounded-md bg-danger/[0.13] px-1.5 py-px font-mono text-[10px] font-semibold text-danger">
              {gaps.length} gap{gaps.length === 1 ? "" : "s"}
            </span>
          )}
        </div>
      </header>

      {steps.length === 0 ? (
        <div className="p-4 text-xs text-ink-dim">
          No steps recorded yet.
        </div>
      ) : (
        <>
          <div className="px-3.5 pb-2 pt-3 font-mono text-[11px] font-semibold uppercase tracking-wide text-ink-dim">
            Method flow — log to interpretation
          </div>
          <ol className="px-3.5 pb-3">
            {steps.map((s, i) => (
              <FlowStep
                key={s.id}
                step={s}
                index={i}
                isLast={i === steps.length - 1}
                gaps={gapsByStep.get(s.id) ?? []}
                onConfirmWhy={onConfirmWhy}
              />
            ))}
          </ol>
        </>
      )}

      {related.length > 0 && <RelatedSection related={related} />}

      {gaps.length > 0 && <GapsSection gaps={gaps} />}
    </div>
  );
}

function StateBadge({ state }: { state: string }) {
  const tone =
    state === "verified"
      ? "text-phos ring-phos/40"
      : state === "fixed"
        ? "text-accent ring-accent/40"
        : "text-amber ring-amber/40";
  return (
    <span
      className={`rounded px-1 py-px text-[10px] uppercase tracking-wide ring-1 ${tone}`}
    >
      {state}
    </span>
  );
}

/**
 * A single node in the vertical flow: a numbered connector dot on a spine, then
 * the step's FACT spine + INFERENCE layer. The spine line connects to the next
 * node unless this is the last step.
 */
function FlowStep({
  step,
  index,
  isLast,
  gaps,
  onConfirmWhy,
}: {
  step: AnalyzedStep;
  index: number;
  isLast: boolean;
  gaps: MethodGap[];
  onConfirmWhy?: (stepId: string, why: string) => void;
}) {
  const toolId = (step.action?.tool_id as string) || "(unknown tool)";
  const params = step.action?.params;
  const rawOut =
    typeof step.evidence?.raw_output === "string"
      ? step.evidence.raw_output
      : "";
  const ts = step.evidence?.timestamp;
  const hasGap = gaps.length > 0;

  // Node ring color tracks the step's standing: a gap → danger, unanchored →
  // amber, clean anchored step → phos.
  const nodeTone = hasGap
    ? "border-danger text-danger"
    : step.anchored
      ? "border-phos text-phos"
      : "border-amber text-amber";

  return (
    <li className="relative flex gap-3">
      {/* Spine — numbered node + connecting line. */}
      <div className="flex flex-col items-center">
        <span
          className={`z-10 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border bg-bg-base font-mono text-[11px] font-semibold ${nodeTone}`}
        >
          {step.ordinal ?? index + 1}
        </span>
        {!isLast && <span className="w-px flex-1 bg-divider" />}
      </div>

      {/* Node body. */}
      <div className="min-w-0 flex-1 pb-4">
        <div className="overflow-hidden rounded-[11px] border border-divider bg-bg-card">
          <div className="flex items-center gap-2 border-b border-divider px-3 py-2">
            <span className="truncate font-mono text-xs text-ink-primary">{toolId}</span>
            <span className="ml-auto shrink-0">
              {step.anchored ? (
                <span className="rounded bg-phos/10 px-1.5 py-px text-[10px] uppercase tracking-wide text-phos ring-1 ring-phos/30">
                  anchored
                </span>
              ) : (
                <span className="rounded bg-amber/10 px-1.5 py-px text-[10px] uppercase tracking-wide text-amber ring-1 ring-amber/30">
                  unanchored
                </span>
              )}
            </span>
          </div>

          {/* ── LAYER 1: FACTUAL SPINE (action + evidence) ───────────────── */}
          <div className="border-l-2 border-phos/40 px-3 py-2.5">
            <FlowTag tone="fact">FACT · from the log</FlowTag>
            <div className="mt-2 space-y-2 text-[11px]">
              <div>
                <span className="text-ink-dim">action</span>
                <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words rounded-md bg-bg-base/60 p-2 font-mono text-[10.5px] text-ink-muted">
                  {toolId}
                  {params && Object.keys(params).length > 0
                    ? "  " + JSON.stringify(params)
                    : ""}
                </pre>
              </div>
              <div>
                <span className="text-ink-dim">evidence</span>
                {rawOut ? (
                  <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-md bg-bg-base/60 p-2 font-mono text-[10.5px] text-ink-muted">
                    {rawOut}
                  </pre>
                ) : (
                  <div className="mt-1 text-[10.5px] italic text-ink-dim">
                    (no raw output captured)
                  </div>
                )}
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-ink-dim">
                  {step.evidence?.hash && (
                    <span className="font-mono">
                      sha256:{String(step.evidence.hash).slice(0, 12)}…
                    </span>
                  )}
                  {ts != null && <span className="font-mono">{String(ts)}</span>}
                </div>
              </div>
            </div>
          </div>

          {/* ── LAYER 2: INFERRED WHY (interpretation) ───────────────────── */}
          <WhyLayer step={step} onConfirmWhy={onConfirmWhy} />

          {gaps.length > 0 && (
            <div className="border-t border-divider bg-danger/[0.06] px-3 py-2">
              {gaps.map((g, gi) => (
                <div key={gi} className="flex items-start gap-1.5 text-[10.5px] text-danger">
                  <span className="shrink-0">⚑</span>
                  <span>
                    <span className="font-semibold">{gapLabel(g.type)}</span> — {g.note}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </li>
  );
}

/**
 * The inference layer. Critical behaviour:
 *  - anchored + interpretation  → "inference", show the rationale.
 *  - unanchored + interpretation → "inference · unanchored", show rationale
 *    but flag that it isn't grounded in a prior result.
 *  - NO interpretation           → render ONLY a flagged "unverified"
 *    placeholder + "confirm why" affordance. NEVER fabricate a rationale.
 */
function WhyLayer({
  step,
  onConfirmWhy,
}: {
  step: AnalyzedStep;
  onConfirmWhy?: (stepId: string, why: string) => void;
}) {
  const [draft, setDraft] = useState("");
  const [open, setOpen] = useState(false);
  const [submitted, setSubmitted] = useState<string | null>(null);

  const label = step.anchored ? "INFERENCE" : "INFERENCE · unanchored";

  function submit() {
    const why = draft.trim();
    if (!why) return;
    onConfirmWhy?.(step.id, why);
    setSubmitted(why);
    setOpen(false);
    setDraft("");
  }

  return (
    <div className="border-t border-divider border-l-2 border-l-amber/40 px-3 py-2.5">
      <FlowTag tone="inference">{label}</FlowTag>

      {step.hasInterpretation ? (
        <p className="mt-1.5 whitespace-pre-wrap text-[11px] leading-snug text-ink-muted">
          {step.interpretation}
        </p>
      ) : submitted ? (
        <p className="mt-1.5 whitespace-pre-wrap text-[11px] leading-snug text-ink-muted">
          {submitted}
          <span className="ml-1 text-[10px] text-ink-dim">
            (you confirmed this — not yet from the log)
          </span>
        </p>
      ) : (
        <>
          {/* Flagged placeholder — NO invented rationale. */}
          <div className="mt-1.5 rounded-md bg-amber/10 px-2 py-1.5 text-[11px] text-amber ring-1 ring-amber/30">
            ⚠ unverified — no rationale recorded
          </div>
          {open ? (
            <div className="mt-2 space-y-1.5">
              <textarea
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="Why did this step follow? (you supply it — not invented)"
                rows={2}
                className="w-full resize-none rounded-md bg-bg-base px-2 py-1.5 text-[11px] text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
              />
              <div className="flex gap-1.5">
                <button
                  onClick={submit}
                  disabled={!draft.trim()}
                  className="rounded-md bg-accent px-2.5 py-1 text-[10.5px] font-semibold text-bg-base disabled:opacity-50"
                >
                  Confirm why
                </button>
                <button
                  onClick={() => {
                    setOpen(false);
                    setDraft("");
                  }}
                  className="rounded-md px-2 py-1 text-[10.5px] text-ink-muted hover:text-ink-primary"
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button
              onClick={() => setOpen(true)}
              className="mt-2 text-[10.5px] text-accent hover:underline"
            >
              + confirm why
            </button>
          )}
        </>
      )}
    </div>
  );
}

/** A flow-tag pill in the design's source-to-sink style (mono, tinted). */
function FlowTag({
  tone,
  children,
}: {
  tone: "fact" | "inference";
  children: React.ReactNode;
}) {
  const cls =
    tone === "fact"
      ? "text-phos ring-phos/30 bg-phos/[0.14]"
      : "text-amber ring-amber/30 bg-amber/[0.14]";
  return (
    <span
      className={`inline-block rounded px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[0.06em] ring-1 ${cls}`}
    >
      {children}
    </span>
  );
}

/** Recurring techniques in the chain — steps grouped by repeated tool. */
function RelatedSection({
  related,
}: {
  related: [string, AnalyzedStep[]][];
}) {
  return (
    <section className="border-t border-divider px-3.5 py-3">
      <div className="font-mono text-[11px] font-semibold uppercase tracking-wide text-ink-dim">
        Related steps
      </div>
      <ul className="mt-2 space-y-1.5">
        {related.map(([tool, arr]) => (
          <li
            key={tool}
            className="flex items-center gap-2 rounded-lg border border-divider bg-bg-card px-2.5 py-1.5 text-[11px]"
          >
            <span className="truncate font-mono text-ink-primary">{tool}</span>
            <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-dim">
              steps {arr.map((s, i) => s.ordinal ?? i + 1).join(", ")}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function GapsSection({ gaps }: { gaps: MethodGap[] }) {
  return (
    <section className="mt-auto border-t border-divider bg-danger/[0.05] px-3.5 py-3">
      <div className="flex items-center gap-2 font-mono text-[11px] font-semibold uppercase tracking-wide text-danger">
        <span className="h-[7px] w-[7px] rounded-full bg-danger" />
        Critical fails ({gaps.length})
      </div>
      <ul className="mt-2 space-y-1.5">
        {gaps.map((g, i) => (
          <li
            key={i}
            className="flex gap-1.5 rounded-lg border border-danger/30 bg-bg-card px-2.5 py-1.5 text-[11px]"
          >
            <span className="shrink-0 font-medium text-danger">
              {gapLabel(g.type)}
            </span>
            <span className="text-ink-muted">{g.note}</span>
            <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-dim">
              {g.stepId.slice(0, 8)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
