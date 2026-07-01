// BuildPanel — the unified left-rail "Build" navigator.
//
// One surface for the two things an operator assembles a sandbox run from:
//   TOP    — the Tools palette (grouped via toolGroups). Each tool row is
//            HTML5-draggable (carries its tool id) and click-opens its panel.
//   BOTTOM — the Playbooks list (GET /playbooks). "+ New playbook" POSTs an
//            empty playbook; clicking a row opens the editor tab; DROPPING a
//            dragged tool onto a playbook row appends a step (PUT to save).
//
// Backend contracts come straight from routers/playbook_run.py; the DnD MIME
// type + step-append helper live in ./playbookApi so the editor shares them.

import { useCallback, useEffect, useState } from "react";
import { EyebrowPill, StatusDot } from "performative-ui";

import SectionLabel from "../shell/SectionLabel";
import { emit } from "../shell/bus";
import { toolGroups, toolMode } from "../shell/tools";
import {
  TOOL_DND_MIME,
  appendStep,
  createPlaybook,
  listPlaybooks,
  type Playbook,
} from "./playbookApi";

const C_ACCENT = "rgb(var(--accent-rgb))";
const C_DIM = "rgb(var(--ink-dim-rgb))";

export default function BuildPanel() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [busy, setBusy] = useState(false);
  const [dropTarget, setDropTarget] = useState<string | null>(null);

  const refresh = useCallback(() => {
    listPlaybooks()
      .then(setPlaybooks)
      .catch(() => setPlaybooks([]));
  }, []);

  useEffect(refresh, [refresh]);

  async function newPlaybook() {
    setBusy(true);
    try {
      const pb = await createPlaybook("Untitled playbook");
      refresh();
      emit("openView", { view: "playbook", params: { id: pb.id } });
    } catch {
      /* surfaced by the empty list staying put */
    } finally {
      setBusy(false);
    }
  }

  async function dropTool(pb: Playbook, toolId: string) {
    if (!toolId) return;
    setBusy(true);
    try {
      await appendStep(pb, toolId);
      refresh();
    } catch {
      /* non-fatal */
    } finally {
      setBusy(false);
      setDropTarget(null);
    }
  }

  return (
    <div className="flex h-full flex-col overflow-hidden bg-bg-sidebar text-sm">
      <header className="shrink-0 border-b border-divider px-3 pb-3 pt-3">
        <EyebrowPill icon={false} className="text-[calc(10px_*_var(--text-scale))]">
          s-ide
        </EyebrowPill>
        <p className="mt-1.5 text-[calc(11px_*_var(--text-scale))] text-ink-muted">
          Drag a tool into a playbook to add a step. Click a tool to open it.
        </p>
      </header>

      {/* ── Tools palette ─────────────────────────────────────────────── */}
      <div className="min-h-0 flex-1 overflow-auto">
        <div className="px-3 pb-1 pt-3">
          <SectionLabel>Tools</SectionLabel>
        </div>
        {toolGroups().map(({ group, tools }) => (
          <div key={group} className="pb-2">
            <div className="px-3 py-1 text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">{group}</div>
            {tools.map((t) => {
              const active = toolMode(t) === "active";
              return (
                <div
                  key={t.id}
                  draggable
                  onDragStart={(e) => {
                    e.dataTransfer.setData(TOOL_DND_MIME, t.id);
                    e.dataTransfer.setData("text/plain", t.id);
                    e.dataTransfer.effectAllowed = "copy";
                  }}
                  onClick={() => emit("openTool", { toolId: t.id })}
                  title={t.blurb}
                  className="flex cursor-grab items-center gap-1.5 px-4 py-1 text-left text-ink-muted hover:bg-nav-hover hover:text-ink-primary active:cursor-grabbing"
                >
                  <span className="truncate">{t.label}</span>
                  {active && (
                    <span className="ml-auto shrink-0 rounded bg-amber/15 px-1 text-[calc(9px_*_var(--text-scale))] uppercase text-amber">
                      active
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* ── Playbooks ─────────────────────────────────────────────────── */}
      <div className="flex max-h-[45%] min-h-0 shrink-0 flex-col border-t border-divider">
        <div className="flex items-center justify-between px-3 pb-1 pt-3">
          <SectionLabel>Playbooks</SectionLabel>
          <button
            onClick={() => void newPlaybook()}
            disabled={busy}
            className="rounded bg-bg-card px-2 py-0.5 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary disabled:opacity-50"
          >
            + New playbook
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-auto pb-2">
          {playbooks.length === 0 ? (
            <div className="px-4 py-2 text-xs text-ink-dim">
              No playbooks yet — drag tools onto a new one.
            </div>
          ) : (
            playbooks.map((pb) => {
              const over = dropTarget === pb.id;
              return (
                <div
                  key={pb.id}
                  onClick={() => emit("openView", { view: "playbook", params: { id: pb.id } })}
                  onDragOver={(e) => {
                    if (e.dataTransfer.types.includes(TOOL_DND_MIME)) {
                      e.preventDefault();
                      e.dataTransfer.dropEffect = "copy";
                      setDropTarget(pb.id);
                    }
                  }}
                  onDragLeave={() => setDropTarget((cur) => (cur === pb.id ? null : cur))}
                  onDrop={(e) => {
                    e.preventDefault();
                    const id = e.dataTransfer.getData(TOOL_DND_MIME) || e.dataTransfer.getData("text/plain");
                    void dropTool(pb, id);
                  }}
                  className={`mx-2 flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 ${
                    over ? "bg-accent/15 ring-1 ring-accent/50" : "hover:bg-nav-hover"
                  }`}
                >
                  <StatusDot color={over ? C_ACCENT : C_DIM} static={!over} />
                  <span className="truncate text-ink-primary">{pb.name}</span>
                  <span className="ml-auto shrink-0 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
                    {pb.steps.length} {pb.steps.length === 1 ? "step" : "steps"}
                  </span>
                </div>
              );
            })
          )}
        </div>
        <p className="shrink-0 px-3 pb-2 text-[calc(10px_*_var(--text-scale))] text-ink-dim">
          Drop a tool here to append a step · click to edit
        </p>
      </div>
    </div>
  );
}
