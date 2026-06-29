// WorkbenchView — the full-page Workbench (the "build" destination).
//
// Split in half:
//   LEFT  — the TOOLS palette. Every tool shows a live status dot (Active /
//           Gated / Offline) probed from the backend's registered routes, an
//           attack-mode badge, and is HTML5-draggable + click-to-open. A
//           "Test all" button re-probes reachability.
//   RIGHT — the PLAYBOOKS board, toggleable between TILE and LIST view. The
//           "+" names a new playbook inline; dropping a dragged tool onto a
//           playbook appends a step (PUT to save); clicking opens the editor.
//
// Liveness comes from ./shell/tools/liveness; playbook CRUD from ./playbookApi.

import { useCallback, useEffect, useMemo, useState } from "react";

import Icon from "../shell/Icon";
import SectionLabel from "../shell/SectionLabel";
import { emit } from "../shell/bus";
import { allToolGroups, toolMode, type ToolDescriptor } from "../shell/tools";
import { useCapabilities } from "../shell/tools/capability";
import {
  STATUS_META,
  probeTools,
  statusFor,
  useLiveness,
  type ToolStatus,
} from "../shell/tools/liveness";
import {
  TOOL_DND_MIME,
  appendStep,
  createPlaybook,
  deletePlaybook,
  listPlaybooks,
  type Playbook,
} from "./playbookApi";

const VIEW_KEY = "s-ide:wb-view";

export default function WorkbenchView() {
  const live = useLiveness();
  const caps = useCapabilities(); // re-render when a capability group is toggled
  void caps;

  // Probe reachability on mount (and let "Test all" re-run it).
  useEffect(() => {
    void probeTools();
  }, []);

  return (
    <div className="flex h-full min-h-0 bg-bg-base">
      <ToolsPane routes={live.routes} loading={live.loading} probedAt={live.probedAt} />
      <PlaybooksPane />
    </div>
  );
}

// ── Left: tools palette with liveness ────────────────────────────────────────
function statusCounts(tools: ToolDescriptor[], routes: Set<string> | null) {
  const c: Record<ToolStatus, number> = { live: 0, gated: 0, offline: 0, unknown: 0 };
  for (const t of tools) c[statusFor(t, routes)]++;
  return c;
}

function ToolsPane({
  routes,
  loading,
  probedAt,
}: {
  routes: Set<string> | null;
  loading: boolean;
  probedAt: number | null;
}) {
  const [q, setQ] = useState("");
  const groups = useMemo(() => allToolGroups(), []);
  const allTools = useMemo(() => groups.flatMap((g) => g.tools), [groups]);
  const counts = statusCounts(allTools, routes);

  const ql = q.trim().toLowerCase();
  const filtered = groups
    .map((g) => ({
      group: g.group,
      tools: g.tools.filter(
        (t) => !ql || t.label.toLowerCase().includes(ql) || t.id.includes(ql) || t.group.toLowerCase().includes(ql),
      ),
    }))
    .filter((g) => g.tools.length > 0);

  return (
    <section className="flex w-1/2 min-w-0 flex-col border-r border-divider">
      <header className="shrink-0 border-b border-divider px-4 pb-3 pt-4">
        <div className="flex items-center gap-2">
          <Icon name="wrench" size={16} />
          <span className="text-sm font-bold tracking-tight text-ink-primary">Tools</span>
          <span className="text-[11px] text-ink-dim">
            {counts.live} active · {allTools.length} total
          </span>
          <button
            onClick={() => void probeTools()}
            disabled={loading}
            className="ml-auto rounded bg-bg-card px-2 py-1 text-[11px] text-ink-muted ring-1 ring-divider hover:text-ink-primary disabled:opacity-50"
          >
            {loading ? "Testing…" : "Test all"}
          </button>
        </div>

        {/* status legend */}
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-ink-dim">
          {(["live", "gated", "offline"] as ToolStatus[]).map((s) => (
            <span key={s} className="flex items-center gap-1" title={STATUS_META[s].hint}>
              <Dot color={STATUS_META[s].color} />
              {STATUS_META[s].label} {counts[s] > 0 ? `(${counts[s]})` : ""}
            </span>
          ))}
          {probedAt && <span className="ml-auto">tested {timeAgo(probedAt)}</span>}
        </div>

        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter tools…"
          className="mt-2 w-full rounded border border-divider bg-bg-card px-2 py-1 text-[12px] text-ink-primary outline-none focus:border-accent placeholder:text-ink-dim"
        />
        <p className="mt-2 text-[11px] text-ink-muted">Drag a tool onto a playbook → · click to open it.</p>
      </header>

      <div className="min-h-0 flex-1 overflow-auto pb-4">
        {filtered.map(({ group, tools }) => (
          <div key={group} className="pt-3">
            <div className="px-4 pb-1">
              <SectionLabel>{group}</SectionLabel>
            </div>
            {tools.map((t) => (
              <ToolRow key={t.id} tool={t} status={statusFor(t, routes)} />
            ))}
          </div>
        ))}
        {filtered.length === 0 && <div className="px-4 py-6 text-[12px] text-ink-dim">No tools match “{q}”.</div>}
      </div>
    </section>
  );
}

function ToolRow({ tool, status }: { tool: ToolDescriptor; status: ToolStatus }) {
  const meta = STATUS_META[status];
  const attack = toolMode(tool) === "active";
  return (
    <div
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData(TOOL_DND_MIME, tool.id);
        e.dataTransfer.setData("text/plain", tool.id);
        e.dataTransfer.effectAllowed = "copy";
      }}
      onClick={() => emit("openTool", { toolId: tool.id })}
      title={`${tool.blurb}\n\n${meta.label}: ${meta.hint}`}
      className="group flex cursor-grab items-center gap-2 px-4 py-1.5 text-left hover:bg-nav-hover active:cursor-grabbing"
    >
      <Dot color={meta.color} pulse={status === "live"} />
      <span className="truncate text-[13px] text-ink-muted group-hover:text-ink-primary">{tool.label}</span>
      {attack && (
        <span className="shrink-0 rounded bg-danger/15 px-1 text-[9px] uppercase tracking-wide text-danger">attack</span>
      )}
      {tool.requires && (
        <span className="ml-auto truncate text-[10px] text-ink-dim" title={`Requires: ${tool.requires}`}>
          {tool.requires}
        </span>
      )}
    </div>
  );
}

// ── Right: playbooks board (tile + list) ─────────────────────────────────────
function PlaybooksPane() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [tile, setTile] = useState<boolean>(() => {
    try {
      return localStorage.getItem(VIEW_KEY) !== "list";
    } catch {
      return true;
    }
  });
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [dropTarget, setDropTarget] = useState<string | null>(null);

  const refresh = useCallback(() => {
    listPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
  }, []);
  useEffect(refresh, [refresh]);

  function setView(t: boolean) {
    setTile(t);
    try {
      localStorage.setItem(VIEW_KEY, t ? "tile" : "list");
    } catch {
      /* quota */
    }
  }

  async function create(name: string) {
    const clean = name.trim() || "Untitled playbook";
    setBusy(true);
    try {
      const pb = await createPlaybook(clean);
      setCreating(false);
      refresh();
      emit("openView", { view: "playbook", params: { id: pb.id } });
    } catch {
      /* surfaced by list staying put */
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

  async function remove(pb: Playbook) {
    // Optimistic: drop it from the list immediately, reconcile on refresh.
    setPlaybooks((cur) => cur.filter((p) => p.id !== pb.id));
    try {
      await deletePlaybook(pb.id);
    } catch {
      /* put it back by reloading the source of truth */
    } finally {
      refresh();
    }
  }

  const dropHandlers = (pb: Playbook) => ({
    onDragOver: (e: React.DragEvent) => {
      if (e.dataTransfer.types.includes(TOOL_DND_MIME)) {
        e.preventDefault();
        e.dataTransfer.dropEffect = "copy";
        setDropTarget(pb.id);
      }
    },
    onDragLeave: () => setDropTarget((cur) => (cur === pb.id ? null : cur)),
    onDrop: (e: React.DragEvent) => {
      e.preventDefault();
      const id = e.dataTransfer.getData(TOOL_DND_MIME) || e.dataTransfer.getData("text/plain");
      void dropTool(pb, id);
    },
  });

  return (
    <section className="flex flex-1 min-w-0 flex-col">
      <header className="flex shrink-0 items-center gap-2 border-b border-divider px-4 pb-3 pt-4">
        <Icon name="book" size={16} />
        <span className="text-sm font-bold tracking-tight text-ink-primary">Playbooks</span>
        <span className="text-[11px] text-ink-dim">{playbooks.length}</span>

        {/* tile / list toggle */}
        <div className="ml-auto flex items-center rounded ring-1 ring-divider">
          <ViewBtn icon="grid" on={tile} onClick={() => setView(true)} label="Tiles" />
          <ViewBtn icon="list" on={!tile} onClick={() => setView(false)} label="List" />
        </div>
        <button
          onClick={() => setCreating((c) => !c)}
          className="rounded bg-accent/15 px-2 py-1 text-[11px] font-bold text-accent ring-1 ring-accent/30 hover:bg-accent/25"
        >
          + New playbook
        </button>
      </header>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        {creating && <NewPlaybookForm busy={busy} onCreate={create} onCancel={() => setCreating(false)} />}

        {playbooks.length === 0 && !creating ? (
          <div className="mt-6 rounded-lg border border-dashed border-divider py-10 text-center text-[12px] text-ink-dim">
            No playbooks yet. Hit <span className="text-accent">+ New playbook</span>, name it, then drag tools in.
          </div>
        ) : tile ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {playbooks.map((pb) => (
              <PlaybookTile key={pb.id} pb={pb} over={dropTarget === pb.id} drop={dropHandlers(pb)} onDelete={() => remove(pb)} />
            ))}
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-divider">
            {playbooks.map((pb) => (
              <PlaybookRow key={pb.id} pb={pb} over={dropTarget === pb.id} drop={dropHandlers(pb)} onDelete={() => remove(pb)} />
            ))}
          </div>
        )}
      </div>
      <p className="shrink-0 border-t border-divider px-4 py-2 text-[10px] text-ink-dim">
        Drop a tool on a playbook to append a step · click to open the editor.
      </p>
    </section>
  );
}

function NewPlaybookForm({
  busy,
  onCreate,
  onCancel,
}: {
  busy: boolean;
  onCreate: (name: string) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onCreate(name);
      }}
      className="mb-3 flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/[0.06] p-2"
    >
      <input
        autoFocus
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => e.key === "Escape" && onCancel()}
        placeholder="Name this playbook…"
        className="min-w-0 flex-1 bg-transparent px-1 text-[13px] text-ink-primary outline-none placeholder:text-ink-dim"
      />
      <button
        type="submit"
        disabled={busy}
        className="rounded bg-accent px-2.5 py-1 text-[11px] font-bold text-bg-base disabled:opacity-50"
      >
        Create
      </button>
      <button type="button" onClick={onCancel} className="rounded px-2 py-1 text-[11px] text-ink-dim hover:text-ink-primary">
        Cancel
      </button>
    </form>
  );
}

type DropProps = {
  onDragOver: (e: React.DragEvent) => void;
  onDragLeave: () => void;
  onDrop: (e: React.DragEvent) => void;
};

function PlaybookTile({
  pb,
  over,
  drop,
  onDelete,
}: {
  pb: Playbook;
  over: boolean;
  drop: DropProps;
  onDelete: () => void;
}) {
  return (
    <div
      {...drop}
      onClick={() => emit("openView", { view: "playbook", params: { id: pb.id } })}
      className={`group flex cursor-pointer flex-col gap-2 rounded-lg border bg-bg-card p-3 transition ${
        over ? "border-accent ring-2 ring-accent/40" : "border-divider hover:border-accent/50"
      }`}
    >
      <div className="flex items-center gap-2">
        <span className="truncate text-[13px] font-bold text-ink-primary">{pb.name}</span>
        <span className="ml-auto shrink-0 rounded bg-bg-base px-1.5 py-0.5 text-[10px] text-ink-dim ring-1 ring-divider">
          {pb.steps.length} {pb.steps.length === 1 ? "step" : "steps"}
        </span>
        <DeleteBtn name={pb.name} onDelete={onDelete} />
      </div>
      <div className="flex min-h-[20px] flex-wrap gap-1">
        {pb.steps.slice(0, 8).map((s, i) => (
          <span key={i} className="rounded bg-bg-base px-1.5 py-0.5 text-[10px] text-ink-muted ring-1 ring-divider">
            {s.tool_id}
          </span>
        ))}
        {pb.steps.length === 0 && <span className="text-[10px] text-ink-dim">empty — drag tools here</span>}
        {pb.steps.length > 8 && <span className="text-[10px] text-ink-dim">+{pb.steps.length - 8}</span>}
      </div>
    </div>
  );
}

function PlaybookRow({
  pb,
  over,
  drop,
  onDelete,
}: {
  pb: Playbook;
  over: boolean;
  drop: DropProps;
  onDelete: () => void;
}) {
  return (
    <div
      {...drop}
      onClick={() => emit("openView", { view: "playbook", params: { id: pb.id } })}
      className={`group flex cursor-pointer items-center gap-2 border-b border-divider px-3 py-2 last:border-b-0 ${
        over ? "bg-accent/10 ring-1 ring-inset ring-accent/40" : "hover:bg-nav-hover"
      }`}
    >
      <Icon name="book" size={14} />
      <span className="truncate text-[13px] text-ink-primary">{pb.name}</span>
      <span className="ml-auto shrink-0 text-[11px] text-ink-dim">
        {pb.steps.length} {pb.steps.length === 1 ? "step" : "steps"}
      </span>
      <DeleteBtn name={pb.name} onDelete={onDelete} />
    </div>
  );
}

// Small two-click delete: first click arms (turns red), second confirms. Stops
// propagation so it never opens the editor. Resets if you move away.
function DeleteBtn({ name, onDelete }: { name: string; onDelete: () => void }) {
  const [armed, setArmed] = useState(false);
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        if (armed) onDelete();
        else setArmed(true);
      }}
      onMouseLeave={() => setArmed(false)}
      title={armed ? `Click again to delete “${name}”` : `Delete “${name}”`}
      className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] transition ${
        armed
          ? "bg-danger/20 text-danger ring-1 ring-danger/40"
          : "text-ink-dim opacity-0 hover:text-danger group-hover:opacity-100"
      }`}
    >
      {armed ? "Confirm" : "✕"}
    </button>
  );
}

// ── Small bits ───────────────────────────────────────────────────────────────
function ViewBtn({ icon, on, onClick, label }: { icon: string; on: boolean; onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={`flex h-6 w-7 items-center justify-center first:rounded-l last:rounded-r ${
        on ? "bg-accent/15 text-accent" : "text-ink-dim hover:text-ink-primary"
      }`}
    >
      <Icon name={icon} size={14} />
    </button>
  );
}

function Dot({ color, pulse }: { color: string; pulse?: boolean }) {
  return (
    <span className="relative flex h-2 w-2 shrink-0">
      {pulse && <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" style={{ backgroundColor: color }} />}
      <span className="relative inline-flex h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
    </span>
  );
}

function timeAgo(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  return `${m}m ago`;
}
