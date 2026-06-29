import { useCallback, useEffect, useState } from "react";
import SectionLabel from "../shell/SectionLabel";
import Icon from "../shell/Icon";
import LabsView from "../labs/LabsView";

import { authFetch } from "../api";
import { METHODOLOGY_IDS, methodologyLabel } from "../lib/methodology";

/**
 * The learning surface.
 *
 *  - Guided empty state: spin up a lab → reveal first hint → run your first tool.
 *  - Progressive, NO-SPOILER hints: fetched from /method/labs/{id}/learner
 *    (solution-safe serializer) and revealed one at a time. The private
 *    `solution` is NEVER fetched or shown here — only learner_view is read.
 *  - Progress: /method/progress → labs solved / vuln classes / methodology
 *    steps practiced, with counts.
 */

type LearnerView = {
  description?: string;
  objective?: string;
  hints?: string[];
};

type LearnerPayload = {
  lab_id: string;
  learner_view: LearnerView | null;
  source_anchor?: { file?: string; line?: number } | null;
};

type Progress = {
  labs_solved: string[];
  vuln_classes: string[];
  methodology_steps: string[];
};

export default function LearningView() {
  const [progress, setProgress] = useState<Progress | null>(null);
  // Labs now live inside Learn — spin up a target here, then learn against it.
  const [tab, setTab] = useState<"learn" | "labs">("learn");

  const refreshProgress = useCallback(() => {
    authFetch("/method/progress")
      .then((r) => (r.ok ? r.json() : null))
      .then((p: Progress | null) => setProgress(p))
      .catch(() => setProgress(null));
  }, []);

  useEffect(refreshProgress, [refreshProgress]);

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-sidebar text-sm">
      {/* Learn / Labs tab strip */}
      <div className="flex shrink-0 items-center gap-1 border-b border-divider px-2">
        {([
          { id: "learn", icon: "book", label: "Learn" },
          { id: "labs", icon: "flask", label: "Labs" },
        ] as const).map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 border-b-2 px-3 py-2 text-[12px] transition-colors ${
                active ? "border-accent text-ink-primary" : "border-transparent text-ink-dim hover:text-ink-primary"
              }`}
            >
              <Icon name={t.icon} size={15} />
              {t.label}
            </button>
          );
        })}
      </div>

      {tab === "labs" ? (
        <div className="min-h-0 flex-1 overflow-hidden">
          <LabsView />
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col overflow-auto">
          <div className="border-b border-divider px-3 py-3">
            <SectionLabel>Learn</SectionLabel>
            <p className="mt-2 text-xs text-ink-muted">
              A guided path through the sandbox. Spin up a lab (the Labs tab), reveal a hint
              when you're stuck, then run a tool against it. The lab's solution stays
              server-side — hints only.
            </p>
          </div>

          <GuidedSteps />
          <HintPanel />
          <ProgressPanel progress={progress} onRefresh={refreshProgress} />
        </div>
      )}
    </div>
  );
}

// ── Guided empty state ───────────────────────────────────────────────────────
function GuidedSteps() {
  const steps: { n: number; title: string; detail: string }[] = [
    { n: 1, title: "Spin up a lab", detail: "Arm a lab from the lab list so there's a safe, isolated target to probe." },
    { n: 2, title: "Reveal your first hint", detail: "Stuck on where to start? Reveal hints one at a time below — never the solution." },
    { n: 3, title: "Run your first tool", detail: "Open a tool from the Explorer and point it at the lab. Findings flow into the engagement." },
  ];
  return (
    <div className="border-b border-divider px-3 py-3">
      <div className="pb-2 text-[11px] uppercase tracking-wide text-ink-dim">Getting started</div>
      <ol className="space-y-2">
        {steps.map((s) => (
          <li key={s.n} className="flex gap-2.5">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-bg-card text-[11px] font-semibold text-accent ring-1 ring-divider">
              {s.n}
            </span>
            <div>
              <div className="font-medium text-ink-primary">{s.title}</div>
              <div className="text-xs text-ink-muted">{s.detail}</div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

// ── Progressive, no-spoiler hints ────────────────────────────────────────────
function HintPanel() {
  const [labId, setLabId] = useState("");
  const [loaded, setLoaded] = useState<LearnerPayload | null>(null);
  const [revealed, setRevealed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    const id = labId.trim();
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const r = await authFetch(`/method/labs/${encodeURIComponent(id)}/learner`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const payload = (await r.json()) as LearnerPayload;
      setLoaded(payload);
      setRevealed(0);
      if (!payload.learner_view) setError("No learner view authored for this lab yet.");
    } catch (e) {
      setLoaded(null);
      setError(e instanceof Error ? e.message : "Failed to load lab");
    } finally {
      setLoading(false);
    }
  }, [labId]);

  const view = loaded?.learner_view ?? null;
  const hints = view?.hints ?? [];
  const anchor = loaded?.source_anchor;

  return (
    <div className="border-b border-divider px-3 py-3">
      <div className="pb-2 text-[11px] uppercase tracking-wide text-ink-dim">No-spoiler hints</div>

      <div className="flex gap-1.5">
        <input
          value={labId}
          onChange={(e) => setLabId(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void load()}
          placeholder="lab id"
          className="min-w-0 flex-1 rounded bg-bg-card px-2 py-1 text-xs text-ink-primary outline-none ring-1 ring-divider placeholder:text-ink-dim"
        />
        <button
          onClick={() => void load()}
          disabled={loading || !labId.trim()}
          className="rounded bg-bg-card px-2 py-1 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary disabled:opacity-50"
        >
          {loading ? "…" : "Load"}
        </button>
      </div>

      {error && <div className="mt-2 text-xs text-amber">{error}</div>}

      {view && (
        <div className="mt-3 space-y-2">
          {view.objective && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-ink-dim">Objective</div>
              <div className="text-xs text-ink-primary">{view.objective}</div>
            </div>
          )}
          {view.description && <p className="text-xs text-ink-muted">{view.description}</p>}

          <div className="rounded ring-1 ring-divider">
            {hints.length === 0 ? (
              <div className="px-2 py-2 text-xs text-ink-dim">No hints authored.</div>
            ) : (
              hints.slice(0, revealed).map((h, i) => (
                <div key={i} className="border-b border-divider px-2 py-1.5 text-xs text-ink-primary last:border-b-0">
                  <span className="mr-1.5 text-accent">Hint {i + 1}.</span>
                  {h}
                </div>
              ))
            )}
          </div>

          <div className="flex items-center gap-2">
            {revealed < hints.length ? (
              <button
                onClick={() => setRevealed((r) => r + 1)}
                className="rounded bg-accent/15 px-2 py-1 text-xs text-accent ring-1 ring-accent/40 hover:bg-accent/25"
              >
                {revealed === 0 ? "Reveal first hint" : "Next hint"}
              </button>
            ) : (
              hints.length > 0 && <span className="text-[11px] text-ink-dim">All hints revealed</span>
            )}
            <span className="ml-auto text-[11px] text-ink-dim">
              {revealed}/{hints.length} hints
            </span>
          </div>

          {anchor?.file && (
            <div className="text-[11px] text-ink-dim">
              source: <span className="font-mono">{anchor.file}{anchor.line ? `:${anchor.line}` : ""}</span>
            </div>
          )}
          <p className="text-[11px] text-ink-dim">
            The lab solution is never sent to this view — hints only.
          </p>
        </div>
      )}
    </div>
  );
}

// ── Progress ─────────────────────────────────────────────────────────────────
function ProgressPanel({ progress, onRefresh }: { progress: Progress | null; onRefresh: () => void }) {
  const solved = progress?.labs_solved ?? [];
  const vulns = progress?.vuln_classes ?? [];
  const practiced = new Set(progress?.methodology_steps ?? []);

  return (
    <div className="px-3 py-3">
      <div className="flex items-center justify-between pb-2">
        <span className="text-[11px] uppercase tracking-wide text-ink-dim">Progress</span>
        <button onClick={onRefresh} className="text-[11px] text-ink-dim hover:text-ink-primary">
          refresh
        </button>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <Stat label="Labs solved" value={solved.length} />
        <Stat label="Vuln classes" value={vulns.length} />
        <Stat label="Methodology" value={practiced.size} />
      </div>

      {vulns.length > 0 && (
        <div className="mt-3">
          <div className="pb-1 text-[11px] uppercase tracking-wide text-ink-dim">Vuln classes seen</div>
          <div className="flex flex-wrap gap-1">
            {vulns.map((v) => (
              <span key={v} className="rounded bg-bg-card px-1.5 py-0.5 text-[11px] text-ink-muted ring-1 ring-divider">
                {v}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="mt-3">
        <div className="pb-1 text-[11px] uppercase tracking-wide text-ink-dim">
          Methodology steps practiced ({practiced.size}/{METHODOLOGY_IDS.length})
        </div>
        <div className="space-y-0.5">
          {METHODOLOGY_IDS.filter((id) => practiced.has(id)).map((id) => (
            <div key={id} className="flex items-center gap-1.5 text-[11px] text-ink-muted">
              <span className="text-success">✓</span>
              <span className="truncate" title={methodologyLabel(id)}>{methodologyLabel(id)}</span>
            </div>
          ))}
          {practiced.size === 0 && (
            <div className="text-[11px] text-ink-dim">None yet — practice a step in a lab to tick it.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded bg-bg-card px-2 py-2 text-center ring-1 ring-divider">
      <div className="text-lg font-semibold text-ink-primary">{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-ink-dim">{label}</div>
    </div>
  );
}
