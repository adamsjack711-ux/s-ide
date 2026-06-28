// PlaybookEditor — the center-area editor tab for one playbook.
//
// Mounted (e.g. by the dockview Workspace) in response to
//   emit("openView", { view: "playbook", params: { id } })
// with `playbookId` threaded through as a prop.
//
// What it does:
//   • title input + a TARGET-LAB select (GET /labs)
//   • an ordered STEP LIST that is a DROP TARGET for tools dragged from the
//     BuildPanel palette (HTML5 DnD; the drop reads TOOL_DND_MIME → appends)
//   • each step: the tool, an "expected observation" input, a methodology-id
//     multi-picker (from methodology.ts)
//   • steps reorder by dragging within the list, and are removable
//   • Run steps through the playbook (emit openTool per step). Active playbooks
//     are isolation-gated: Run is disabled when `isolationOk` is false.
//   • Coverage calls POST /playbooks/{id}/coverage
//   • Save persists name + lab_id + steps via PUT /playbooks/{id}
//
// All backend access goes through ./playbookApi.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, EyebrowPill, GlassCard, GradientText, Sparkle, StatusDot } from "performative-ui";

import { emit } from "../shell/bus";
import { toolById, toolGroups, toolMode } from "../shell/tools";
import { METHODOLOGY, methodologyLabel } from "../lib/methodology";
import {
  TOOL_DND_MIME,
  coverage as fetchCoverage,
  createPlaybook,
  getPlaybook,
  listLabs,
  savePlaybook,
  type Coverage,
  type Lab,
  type PlaybookStep,
} from "./playbookApi";

const C_ACCENT = "rgb(var(--accent-rgb))";
const C_DIM = "rgb(var(--ink-dim-rgb))";
const C_SUCCESS = "rgb(var(--success-rgb))";

type EditStep = PlaybookStep & { tool_id: string };

export default function PlaybookEditor({
  playbookId,
  isolationOk = true,
}: {
  playbookId?: string;
  isolationOk?: boolean;
}) {
  const [id, setId] = useState<string | undefined>(playbookId);
  const [name, setName] = useState("Untitled playbook");
  const [labId, setLabId] = useState<string | null>(null);
  const [steps, setSteps] = useState<EditStep[]>([]);
  const [labs, setLabs] = useState<Lab[]>([]);

  const [loading, setLoading] = useState(!!playbookId);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [flash, setFlash] = useState("");
  const [error, setError] = useState("");

  const [cov, setCov] = useState<Coverage | null>(null);
  const [cursor, setCursor] = useState(-1); // -1 = not running
  const [dropOver, setDropOver] = useState(false);
  const dragIdx = useRef<number | null>(null);

  // ── Load ───────────────────────────────────────────────────────────────
  useEffect(() => {
    void listLabs().then(setLabs);
  }, []);

  useEffect(() => {
    setId(playbookId);
    if (!playbookId) {
      setLoading(false);
      return;
    }
    let alive = true;
    setLoading(true);
    getPlaybook(playbookId)
      .then((pb) => {
        if (!alive) return;
        setName(pb.name);
        setLabId(pb.lab_id ?? null);
        setSteps(pb.steps.map((s) => ({ ...s, tool_id: s.tool_id })));
        setDirty(false);
      })
      .catch(() => alive && setError("Could not load playbook."))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [playbookId]);

  function mut(fn: () => void) {
    fn();
    setDirty(true);
    setCov(null);
  }

  // ── Step mutations ───────────────────────────────────────────────────────
  const addTool = useCallback((toolId: string) => {
    if (!toolId) return;
    mut(() =>
      setSteps((prev) => [
        ...prev,
        { tool_id: toolId, in_map: null, expected: "", methodology_ids: [] },
      ]),
    );
  }, []);

  function patchStep(i: number, patch: Partial<EditStep>) {
    mut(() => setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s))));
  }
  function removeStep(i: number) {
    mut(() => setSteps((prev) => prev.filter((_, idx) => idx !== i)));
  }
  function toggleMethod(i: number, mid: string) {
    setSteps((prev) =>
      prev.map((s, idx) => {
        if (idx !== i) return s;
        const cur = s.methodology_ids ?? [];
        return {
          ...s,
          methodology_ids: cur.includes(mid) ? cur.filter((x) => x !== mid) : [...cur, mid],
        };
      }),
    );
    setDirty(true);
    setCov(null);
  }

  function reorder(from: number, to: number) {
    if (from === to) return;
    mut(() =>
      setSteps((prev) => {
        const next = [...prev];
        const [moved] = next.splice(from, 1);
        next.splice(to, 0, moved);
        return next;
      }),
    );
  }

  // ── Persistence ──────────────────────────────────────────────────────────
  async function save() {
    setSaving(true);
    setError("");
    try {
      const clean: PlaybookStep[] = steps
        .filter((s) => s.tool_id.trim())
        .map((s) => ({
          tool_id: s.tool_id,
          in_map: s.in_map?.trim() || null,
          expected: (s.expected ?? "").trim(),
          methodology_ids: s.methodology_ids ?? [],
        }));
      const pb = id
        ? await savePlaybook(id, name.trim() || "Untitled playbook", clean, labId)
        : await createPlaybook(name.trim() || "Untitled playbook", clean, labId);
      setId(pb.id);
      setDirty(false);
      flashMsg("Saved.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function runCoverage() {
    if (!id) {
      setError("Save the playbook before checking coverage.");
      return;
    }
    try {
      setCov(await fetchCoverage(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Coverage failed");
    }
  }

  function flashMsg(m: string) {
    setFlash(m);
    window.setTimeout(() => setFlash(""), 2000);
  }

  // ── Run (step through, isolation-gated) ──────────────────────────────────
  const hasActive = useMemo(
    () => steps.some((s) => { const t = toolById(s.tool_id); return t && toolMode(t) === "active"; }),
    [steps],
  );
  const runDisabled = steps.length === 0 || (hasActive && !isolationOk);

  function runStep(idx: number) {
    const step = steps[idx];
    if (!step) return;
    emit("openTool", { toolId: step.tool_id });
    setCursor(idx);
  }
  const running = cursor >= 0;

  if (loading) {
    return <div className="flex h-full items-center justify-center bg-bg-base text-ink-dim">Loading playbook…</div>;
  }

  return (
    <div className="h-full overflow-y-auto bg-bg-base">
      {/* Header */}
      <header className="border-b border-divider px-6 pb-4 pt-5">
        <EyebrowPill icon={false} className="text-[10px]">
          Playbook
        </EyebrowPill>
        <div className="mt-2 flex items-center gap-2">
          <input
            value={name}
            onChange={(e) => mut(() => setName(e.target.value))}
            placeholder="Playbook name"
            className="min-w-0 flex-1 bg-transparent text-2xl font-bold tracking-tight text-ink-primary outline-none placeholder:text-ink-dim"
          />
          <Sparkle />
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-[11px] text-ink-muted">
            <span className="font-bold uppercase tracking-widest text-ink-dim">Target lab</span>
            <select
              value={labId ?? ""}
              onChange={(e) => mut(() => setLabId(e.target.value || null))}
              className="rounded border border-divider bg-bg-card px-2 py-1 text-[12px] text-ink-primary outline-none focus:border-accent"
            >
              <option value="">— unbound —</option>
              {labs.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </label>

          <span className="ml-auto flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => void runCoverage()} disabled={!id}>
              Coverage
            </Button>
            <Button
              variant={running ? "ghost" : "solid"}
              size="sm"
              onClick={() => (running ? setCursor(-1) : runStep(0))}
              disabled={runDisabled}
              title={
                hasActive && !isolationOk
                  ? "Isolation check must pass to run a playbook with active tools"
                  : undefined
              }
            >
              {running ? "Stop" : "Run"}
            </Button>
            <Button variant="solid" size="sm" loading={saving} disabled={!dirty} onClick={() => void save()}>
              Save
            </Button>
          </span>
        </div>

        {hasActive && !isolationOk && (
          <div className="mt-2 rounded bg-amber/10 px-2 py-1 text-[11px] text-amber ring-1 ring-amber/30">
            This playbook includes active tools — Run is disabled until the isolation check passes.
          </div>
        )}
        {flash && (
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-success">
            <Sparkle solid /> {flash}
          </div>
        )}
        {error && <div className="mt-2 text-[11px] text-danger">⚠ {error}</div>}
        {dirty && !flash && <div className="mt-2 text-[10px] text-ink-dim">Unsaved changes</div>}
      </header>

      <div className="mx-auto max-w-3xl space-y-4 p-6">
        {cov && (
          <GlassCard className="p-3 text-[12px]">
            <div className="flex items-center gap-2">
              <StatusDot color={cov.missing.length === 0 ? C_SUCCESS : C_ACCENT} static />
              <span className="font-bold text-ink-primary">
                <GradientText static>Methodology coverage</GradientText>
              </span>
              <span className="ml-auto font-mono tabular-nums text-accent">{cov.pct}%</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {cov.covered.map((m) => (
                <span key={m} title={methodologyLabel(m)} className="rounded bg-success/15 px-1.5 py-0.5 text-[10px] text-success">
                  {m}
                </span>
              ))}
              {cov.missing.map((m) => (
                <span key={m} title={methodologyLabel(m)} className="rounded bg-amber/15 px-1.5 py-0.5 text-[10px] text-amber">
                  {m}
                </span>
              ))}
              {cov.required.length === 0 && <span className="text-ink-dim">No methodology ids tagged yet.</span>}
            </div>
          </GlassCard>
        )}

        {/* Step list — also the DROP TARGET for palette tools. */}
        <div
          onDragOver={(e) => {
            // Tool-from-palette drops (not in-list reorders, which carry no MIME).
            if (e.dataTransfer.types.includes(TOOL_DND_MIME) && dragIdx.current === null) {
              e.preventDefault();
              e.dataTransfer.dropEffect = "copy";
              setDropOver(true);
            }
          }}
          onDragLeave={() => setDropOver(false)}
          onDrop={(e) => {
            const tid = e.dataTransfer.getData(TOOL_DND_MIME);
            if (tid && dragIdx.current === null) {
              e.preventDefault();
              addTool(tid);
            }
            setDropOver(false);
          }}
          className={`rounded-lg border-2 border-dashed p-3 transition ${
            dropOver ? "border-accent bg-accent/5" : "border-divider"
          }`}
        >
          {steps.length === 0 ? (
            <div className="py-6 text-center text-[12px] text-ink-dim">
              Drag a tool from the Build palette here to add the first step.
            </div>
          ) : (
            <ol className="space-y-2">
              {steps.map((s, i) => {
                const tool = toolById(s.tool_id);
                const active = tool && toolMode(tool) === "active";
                const isCursor = i === cursor;
                return (
                  <li
                    key={i}
                    draggable
                    onDragStart={(e) => {
                      dragIdx.current = i;
                      e.dataTransfer.effectAllowed = "move";
                    }}
                    onDragEnd={() => {
                      dragIdx.current = null;
                    }}
                    onDragOver={(e) => {
                      if (dragIdx.current !== null) e.preventDefault();
                    }}
                    onDrop={(e) => {
                      if (dragIdx.current !== null && dragIdx.current !== i) {
                        e.preventDefault();
                        e.stopPropagation();
                        reorder(dragIdx.current, i);
                      }
                      dragIdx.current = null;
                    }}
                    className={`rounded-md border bg-bg-card p-2.5 ${
                      isCursor ? "border-accent ring-1 ring-accent/40" : "border-divider"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="cursor-grab text-ink-dim active:cursor-grabbing" title="Drag to reorder">
                        ⋮⋮
                      </span>
                      <span className="text-[11px] text-ink-dim">{i + 1}.</span>
                      <span className="truncate font-bold text-ink-primary">{tool?.label ?? s.tool_id}</span>
                      {!tool && <span className="text-[10px] text-amber">unknown tool</span>}
                      {active && (
                        <span className="rounded bg-amber/15 px-1 text-[9px] uppercase text-amber">active</span>
                      )}
                      {running && (
                        <button
                          onClick={() => runStep(i)}
                          className="ml-auto rounded bg-bg-base px-1.5 py-0.5 text-[11px] text-ink-muted ring-1 ring-divider hover:text-ink-primary"
                        >
                          open
                        </button>
                      )}
                      <button
                        onClick={() => removeStep(i)}
                        className={`${running ? "" : "ml-auto"} text-[11px] text-ink-dim hover:text-danger`}
                      >
                        remove
                      </button>
                    </div>

                    <input
                      value={s.expected ?? ""}
                      onChange={(e) => patchStep(i, { expected: e.target.value })}
                      placeholder="expected observation"
                      className="mt-2 w-full rounded border border-divider bg-bg-base px-2 py-1 text-[12px] text-ink-primary outline-none focus:border-accent placeholder:text-ink-dim"
                    />

                    <MethodPicker
                      selected={s.methodology_ids ?? []}
                      onToggle={(mid) => toggleMethod(i, mid)}
                    />
                  </li>
                );
              })}
            </ol>
          )}
        </div>

        {running && (
          <div className="flex items-center gap-2 text-[11px] text-ink-dim">
            <StatusDot color={C_ACCENT} static />
            <span>step {cursor + 1}/{steps.length}</span>
            {cursor < steps.length - 1 && (
              <Button variant="ghost" size="sm" onClick={() => runStep(cursor + 1)} disabled={hasActive && !isolationOk}>
                Next step →
              </Button>
            )}
          </div>
        )}

        {/* Quick-add from the palette (parity with drag, for keyboard/no-DnD). */}
        <QuickAdd onAdd={addTool} />
      </div>
    </div>
  );
}

// ── Methodology multi-picker ────────────────────────────────────────────────
function MethodPicker({ selected, onToggle }: { selected: string[]; onToggle: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-2">
      <div className="flex flex-wrap items-center gap-1">
        {selected.map((mid) => (
          <button
            key={mid}
            onClick={() => onToggle(mid)}
            title={`${methodologyLabel(mid)} — click to remove`}
            className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] text-accent ring-1 ring-accent/30 hover:bg-accent/25"
          >
            {mid} ✕
          </button>
        ))}
        <button
          onClick={() => setOpen((o) => !o)}
          className="rounded bg-bg-base px-1.5 py-0.5 text-[10px] text-ink-muted ring-1 ring-divider hover:text-ink-primary"
        >
          {open ? "done" : "+ methodology"}
        </button>
      </div>
      {open && (
        <div className="mt-1.5 max-h-44 overflow-auto rounded border border-divider bg-bg-base p-1.5">
          {METHODOLOGY.map((e) => {
            const on = selected.includes(e.id);
            return (
              <button
                key={e.id}
                onClick={() => onToggle(e.id)}
                className={`flex w-full items-center gap-1.5 rounded px-1.5 py-0.5 text-left text-[11px] ${
                  on ? "bg-accent/10 text-accent" : "text-ink-muted hover:bg-nav-hover hover:text-ink-primary"
                }`}
              >
                <StatusDot color={on ? C_ACCENT : C_DIM} static />
                <span className="font-mono">{e.id}</span>
                <span className="truncate text-ink-dim">{e.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── No-drag fallback: pick a tool from a dropdown to append ──────────────────
function QuickAdd({ onAdd }: { onAdd: (toolId: string) => void }) {
  const [val, setVal] = useState("");
  return (
    <div className="flex items-center gap-2 border-t border-divider pt-3 text-[11px] text-ink-dim">
      <span>Or add without dragging:</span>
      <select
        value={val}
        onChange={(e) => {
          const v = e.target.value;
          setVal("");
          if (v) onAdd(v);
        }}
        className="rounded border border-divider bg-bg-card px-2 py-1 text-[12px] text-ink-primary outline-none focus:border-accent"
      >
        <option value="">pick a tool…</option>
        {toolGroups().map(({ group, tools }) => (
          <optgroup key={group} label={group}>
            {tools.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
                {toolMode(t) === "active" ? " (active)" : ""}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
    </div>
  );
}
