import { useCallback, useEffect, useState } from "react";
import SectionLabel from "../shell/SectionLabel";

import { authFetch } from "../api";
import { emit } from "../shell/bus";
import { toolById } from "../shell/tools";
import { methodologyLabel } from "../lib/methodology";

/**
 * Playbooks surface — list saved playbooks, create new ones, and "run" one by
 * stepping through it (emitting `openTool` on the bus for each step's tool_id).
 *
 * Each step carries a tool, the expected observation, and the WSTG/PTES ids it
 * exercises (rendered via methodology.ts).
 *
 * ISOLATION HOOK: active playbooks must be gated behind the sandbox isolation
 * check. The integrator passes `isolationOk` from the StatusBar / egress probe;
 * when false, Run is disabled (a playbook can step learners into active tools,
 * which must not reach the internet from a lab).
 */

type PlaybookStep = {
  tool_id: string;
  in_map?: string | null;
  expected?: string;
  methodology_ids?: string[];
};

type Playbook = {
  id: string;
  name: string;
  steps: PlaybookStep[];
};

type Coverage = {
  required: string[];
  covered: string[];
  missing: string[];
  pct: number;
};

export default function PlaybooksView({ isolationOk = true }: { isolationOk?: boolean }) {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(() => {
    authFetch("/playbooks")
      .then((r) => (r.ok ? r.json() : { playbooks: [] }))
      .then((b: { playbooks: Playbook[] }) => setPlaybooks(b.playbooks ?? []))
      .catch(() => setPlaybooks([]));
  }, []);

  useEffect(refresh, [refresh]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-sidebar text-sm">
      <div className="border-b border-divider px-3 py-3">
        <div className="flex items-center justify-between">
          <SectionLabel>Playbooks</SectionLabel>
          <button
            onClick={() => setCreating((c) => !c)}
            className="rounded bg-bg-card px-2 py-0.5 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary"
          >
            {creating ? "Cancel" : "New"}
          </button>
        </div>
        <p className="mt-2 text-xs text-ink-muted">
          Declarative, ordered runbooks. Run steps through them one tool at a time; each step
          is tagged with the WSTG/PTES ids it exercises.
        </p>
        {!isolationOk && (
          <div className="mt-2 rounded bg-amber/10 px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-amber ring-1 ring-amber/30">
            Isolation check not passing — running active playbooks is disabled.
          </div>
        )}
      </div>

      {creating && (
        <CreateForm
          onCreated={() => {
            setCreating(false);
            refresh();
          }}
        />
      )}

      <div className="min-h-0 flex-1">
        {playbooks.length === 0 ? (
          <div className="p-3 text-xs text-ink-dim">No playbooks yet — create one above.</div>
        ) : (
          playbooks.map((p) => <PlaybookCard key={p.id} playbook={p} isolationOk={isolationOk} />)
        )}
      </div>
    </div>
  );
}

// ── One playbook ─────────────────────────────────────────────────────────────
function PlaybookCard({ playbook, isolationOk }: { playbook: Playbook; isolationOk: boolean }) {
  const [cursor, setCursor] = useState(-1); // -1 = not running
  const [coverage, setCoverage] = useState<Coverage | null>(null);

  const running = cursor >= 0;

  const loadCoverage = useCallback(() => {
    authFetch(`/playbooks/${playbook.id}/coverage`, { method: "POST" })
      .then((r) => (r.ok ? r.json() : null))
      .then((c: Coverage | null) => setCoverage(c))
      .catch(() => setCoverage(null));
  }, [playbook.id]);

  function runStep(idx: number) {
    const step = playbook.steps[idx];
    if (!step) return;
    emit("openTool", { toolId: step.tool_id });
    setCursor(idx);
  }

  return (
    <div className="border-b border-divider px-3 py-2.5">
      <div className="flex items-center gap-2">
        <span className="truncate font-medium text-ink-primary">{playbook.name}</span>
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">{playbook.steps.length} steps</span>
        <button
          onClick={() => (running ? setCursor(-1) : runStep(0))}
          disabled={!isolationOk || playbook.steps.length === 0}
          title={!isolationOk ? "Isolation check must pass to run active playbooks" : undefined}
          className={`ml-auto rounded px-2 py-0.5 text-xs ring-1 disabled:cursor-not-allowed disabled:opacity-50 ${
            running
              ? "bg-danger/15 text-danger ring-danger/40 hover:bg-danger/25"
              : "bg-accent/15 text-accent ring-accent/40 hover:bg-accent/25"
          }`}
        >
          {running ? "Stop" : "Run"}
        </button>
        <button onClick={loadCoverage} className="rounded bg-bg-card px-2 py-0.5 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary">
          Coverage
        </button>
      </div>

      {coverage && (
        <div className="mt-1 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          coverage {coverage.pct}% — <span className="text-success">{coverage.covered.length} covered</span>
          {coverage.missing.length > 0 && <span className="text-amber"> · {coverage.missing.length} missing</span>}
        </div>
      )}

      <ol className="mt-2 space-y-1.5">
        {playbook.steps.map((s, i) => {
          const tool = toolById(s.tool_id);
          const active = i === cursor;
          return (
            <li
              key={i}
              className={`rounded px-2 py-1.5 text-xs ring-1 ${active ? "bg-accent/10 ring-accent/40" : "ring-divider"}`}
            >
              <div className="flex items-center gap-2">
                <span className="text-ink-dim">{i + 1}.</span>
                <span className="font-medium text-ink-primary">{tool?.label ?? s.tool_id}</span>
                {!tool && <span className="text-[calc(10px_*_var(--text-scale))] text-amber">unknown tool</span>}
                {running && (
                  <button
                    onClick={() => runStep(i)}
                    className="ml-auto rounded bg-bg-card px-1.5 py-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-muted ring-1 ring-divider hover:text-ink-primary"
                  >
                    open
                  </button>
                )}
              </div>
              {s.in_map && <div className="mt-0.5 text-ink-dim">input: <span className="font-mono">{s.in_map}</span></div>}
              {s.expected && <div className="mt-0.5 text-ink-muted">expect: {s.expected}</div>}
              {(s.methodology_ids ?? []).length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {s.methodology_ids!.map((mid) => (
                    <span
                      key={mid}
                      title={methodologyLabel(mid)}
                      className="rounded bg-bg-card px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-ink-muted ring-1 ring-divider"
                    >
                      {mid}
                    </span>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ol>

      {running && (
        <div className="mt-2 flex items-center gap-2 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          <span>step {cursor + 1}/{playbook.steps.length}</span>
          {cursor < playbook.steps.length - 1 && (
            <button
              onClick={() => runStep(cursor + 1)}
              disabled={!isolationOk}
              className="rounded bg-accent/15 px-2 py-0.5 text-accent ring-1 ring-accent/40 hover:bg-accent/25 disabled:opacity-50"
            >
              Next step →
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ── Create form ──────────────────────────────────────────────────────────────
type DraftStep = { tool_id: string; in_map: string; expected: string; methodology_ids: string };

function CreateForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [steps, setSteps] = useState<DraftStep[]>([{ tool_id: "", in_map: "", expected: "", methodology_ids: "" }]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function patchStep(i: number, patch: Partial<DraftStep>) {
    setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));
  }
  function addStep() {
    setSteps((prev) => [...prev, { tool_id: "", in_map: "", expected: "", methodology_ids: "" }]);
  }
  function removeStep(i: number) {
    setSteps((prev) => prev.filter((_, idx) => idx !== i));
  }

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const body = {
        name: name.trim() || "Untitled playbook",
        steps: steps
          .filter((s) => s.tool_id.trim())
          .map((s) => ({
            tool_id: s.tool_id.trim(),
            in_map: s.in_map.trim() || null,
            expected: s.expected.trim(),
            methodology_ids: s.methodology_ids
              .split(/[,\s]+/)
              .map((x) => x.trim())
              .filter(Boolean),
          })),
      };
      const r = await authFetch("/playbooks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="border-b border-divider bg-bg-card/40 px-3 py-3">
      <input
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="playbook name"
        className="w-full rounded bg-bg-card px-2 py-1 text-xs text-ink-primary outline-none ring-1 ring-divider placeholder:text-ink-dim"
      />
      <div className="mt-2 space-y-2">
        {steps.map((s, i) => (
          <div key={i} className="rounded p-2 ring-1 ring-divider">
            <div className="flex items-center gap-2 pb-1">
              <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">step {i + 1}</span>
              <button onClick={() => removeStep(i)} className="ml-auto text-[calc(11px_*_var(--text-scale))] text-ink-dim hover:text-danger">
                remove
              </button>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <input
                value={s.tool_id}
                onChange={(e) => patchStep(i, { tool_id: e.target.value })}
                placeholder="tool_id (e.g. http_probe)"
                className="rounded bg-bg-card px-2 py-1 text-xs text-ink-primary outline-none ring-1 ring-divider placeholder:text-ink-dim"
              />
              <input
                value={s.in_map}
                onChange={(e) => patchStep(i, { in_map: e.target.value })}
                placeholder="in_map (optional)"
                className="rounded bg-bg-card px-2 py-1 text-xs text-ink-primary outline-none ring-1 ring-divider placeholder:text-ink-dim"
              />
              <input
                value={s.expected}
                onChange={(e) => patchStep(i, { expected: e.target.value })}
                placeholder="expected observation"
                className="col-span-2 rounded bg-bg-card px-2 py-1 text-xs text-ink-primary outline-none ring-1 ring-divider placeholder:text-ink-dim"
              />
              <input
                value={s.methodology_ids}
                onChange={(e) => patchStep(i, { methodology_ids: e.target.value })}
                placeholder="methodology ids (e.g. WSTG-INPV-01, PTES-EXPLOIT)"
                className="col-span-2 rounded bg-bg-card px-2 py-1 text-xs text-ink-primary outline-none ring-1 ring-divider placeholder:text-ink-dim"
              />
            </div>
          </div>
        ))}
      </div>
      {error && <div className="mt-2 text-xs text-danger">{error}</div>}
      <div className="mt-2 flex items-center gap-2">
        <button onClick={addStep} className="rounded bg-bg-card px-2 py-1 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary">
          + step
        </button>
        <button
          onClick={() => void save()}
          disabled={saving}
          className="ml-auto rounded bg-accent/15 px-3 py-1 text-xs text-accent ring-1 ring-accent/40 hover:bg-accent/25 disabled:opacity-50"
        >
          {saving ? "Saving…" : "Save playbook"}
        </button>
      </div>
    </div>
  );
}
