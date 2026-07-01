// Workbench tab — the engagement's tools-and-playbooks surface.
//
// This is where the active engagement's ARMED sub-targets get worked. It reads
// the full tool set from the registry (shell/tools) — never hardcoded — shows
// each tool's info (what it does, passive/active, what it requires), and runs a
// tool (or a whole playbook) against a chosen armed sub-target via the spine
// pairing path (`runPairing`), so the server-side arm gate + scope/attestation
// still apply. No armed sub-target → a clear empty state, never a blank panel,
// never a silent run.
//
// NB: backend `_execute` (lib/spine.py) is still a connectivity-probe stub — the
// per-tool arsenal hooks in there separately; this surface is the UI + run
// orchestration over the existing pairing contract.
import { useEffect, useMemo, useState } from "react";
import { Button, Sparkle, StatusDot } from "performative-ui";
import Icon from "../shell/Icon";
import { isApiError } from "../api";
import { failStamp, inkConfirm, radarSweep } from "../lib/dopamine";
import { FINDING_SEVERITIES, type FindingSeverity } from "../lib/engagement";
import {
  createPairingFinding,
  runPairing,
  type SubTarget,
  type Target,
} from "../lib/spine";
import { allToolGroups, toolMode, type ToolDescriptor } from "../shell/tools";
import {
  STATUS_META,
  probeTools,
  statusFor,
  useLiveness,
} from "../shell/tools/liveness";
import {
  TOOL_DND_MIME,
  appendStep,
  createPlaybook,
  deletePlaybook,
  listPlaybooks,
  type Playbook,
} from "../build/playbookApi";

type FlatSub = SubTarget & { targetName: string; targetId: string };
type ConsoleLine = { level: "cmd" | "out" | "err" | "ok"; text: string };

export default function WorkbenchTab({
  targets,
  onError,
}: {
  targets: Target[];
  onError: (m: string) => void;
}) {
  const armed = useMemo<FlatSub[]>(
    () =>
      targets.flatMap((t) =>
        (t.sub_targets ?? [])
          .filter((s) => s.armed)
          .map((s) => ({ ...s, targetName: t.name, targetId: t.id })),
      ),
    [targets],
  );

  const [selSubId, setSelSubId] = useState<string | null>(armed[0]?.id ?? null);
  useEffect(() => {
    if (!armed.some((s) => s.id === selSubId)) setSelSubId(armed[0]?.id ?? null);
  }, [armed, selSubId]);
  const sub = armed.find((s) => s.id === selSubId) ?? null;

  const [mode, setMode] = useState<"tools" | "playbooks">("tools");
  const [lines, setLines] = useState<ConsoleLine[]>([]);
  const [running, setRunning] = useState(false);
  const [lastOk, setLastOk] = useState(false);

  // ── No armed sub-target → the explicit empty state (never a blank panel). ──
  if (armed.length === 0) {
    return (
      <div className="flex h-full min-h-0 flex-col items-center justify-center gap-3 p-8 text-center">
        <Icon name="wrench" size={28} />
        <h3 className="text-[calc(15px_*_var(--text-scale))] font-bold tracking-tight text-ink-primary">
          Nothing armed to run against
        </h3>
        <p className="max-w-md text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-muted">
          The Workbench runs tools against this engagement's <b>armed</b> sub-targets.
          Open the <b>Targets</b> tab, add a sub-target, and click <b>Arm</b> to attach
          this engagement — then its tools light up here. Arming is the deliberate act
          that authorizes a run.
        </p>
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          Nothing runs from here until a sub-target is armed.
        </span>
      </div>
    );
  }

  async function run(toolId: string, label: string) {
    if (!sub) return;
    setRunning(true);
    setLastOk(false);
    void radarSweep(undefined);
    setLines((l) => [...l, { level: "cmd", text: `> run ${label} @ ${sub.address}` }]);
    try {
      const r = await runPairing(sub, toolId);
      const outLines = (r.output || "").split("\n").filter(Boolean);
      setLines((l) => [
        ...l,
        ...outLines.map((t) => ({ level: "out" as const, text: t })),
        { level: "ok", text: `— ${r.status}: ${r.summary}` },
      ]);
      setLastOk(r.status === "completed");
      return r.status === "completed";
    } catch (e) {
      const msg = isApiError(e) ? e.message : e instanceof Error ? e.message : String(e);
      const refused = isApiError(e) && e.status === 403;
      void failStamp(undefined);
      setLines((l) => [
        ...l,
        { level: "err", text: refused ? `REFUSED (server-side): ${msg}` : `error: ${msg}` },
      ]);
      return false;
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Run-target bar — the armed sub-target every tool/playbook fires at. */}
      <div className="flex shrink-0 flex-wrap items-center gap-2.5 border-b border-divider px-4 py-2.5">
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">Run against</span>
        <select
          value={selSubId ?? ""}
          onChange={(e) => setSelSubId(e.target.value)}
          className="min-w-[220px] rounded-md border border-divider bg-bg-base px-2 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent/50"
        >
          {armed.map((s) => (
            <option key={s.id} value={s.id}>
              {s.targetName} › {s.type} {s.address}
            </option>
          ))}
        </select>
        {sub && (
          <span className="flex items-center gap-1.5 text-[calc(11.5px_*_var(--text-scale))] font-medium text-accent">
            <StatusDot color="var(--accent)" /> armed · {sub.arming?.engagement_name ?? "engagement"}
          </span>
        )}
        <div className="flex-1" />
        <div className="flex items-center rounded-md ring-1 ring-divider">
          {(["tools", "playbooks"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-3 py-1 text-[calc(12px_*_var(--text-scale))] font-medium capitalize first:rounded-l-md last:rounded-r-md ${
                mode === m ? "bg-accent/15 text-accent" : "text-ink-dim hover:text-ink-primary"
              }`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      <div className="flex min-h-0 flex-1">
        {/* Left — tools registry or playbooks board */}
        <div className="flex w-1/2 min-w-0 flex-col border-r border-divider">
          {mode === "tools" ? (
            <ToolsPalette onRun={(t) => run(t.id, t.label)} running={running} />
          ) : (
            <PlaybooksBoard
              onRunPlaybook={async (pb) => {
                for (const step of pb.steps) {
                  const ok = await run(step.tool_id, step.tool_id);
                  if (!ok) break; // stop the chain on a refusal/error
                }
              }}
              onError={onError}
            />
          )}
        </div>

        {/* Right — run console + promote */}
        <section className="flex min-w-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 overflow-auto bg-bg-base p-4 text-[calc(12px_*_var(--text-scale))] leading-relaxed">
            {lines.length === 0 ? (
              <div className="text-[calc(12.5px_*_var(--text-scale))] text-ink-dim">
                {mode === "tools"
                  ? "Pick a tool on the left and run it against the armed sub-target."
                  : "Build a playbook on the left, then run it against the armed sub-target."}
              </div>
            ) : (
              lines.map((l, i) => (
                <div
                  key={i}
                  className={
                    l.level === "cmd"
                      ? "text-ink-muted"
                      : l.level === "err"
                        ? "text-critical"
                        : l.level === "ok"
                          ? "text-accent"
                          : "text-ink-primary"
                  }
                >
                  {l.text}
                </div>
              ))
            )}
          </div>
          {sub && lastOk && (
            <PromoteFinding
              sub={sub}
              onError={onError}
              onDone={() =>
                setLines((l) => [...l, { level: "ok", text: "✓ finding created from this pairing" }])
              }
            />
          )}
        </section>
      </div>
    </div>
  );
}

// ── Tools palette — the full registry, grouped, with info + run ──────────────
function ToolsPalette({
  onRun,
  running,
}: {
  onRun: (t: ToolDescriptor) => void;
  running: boolean;
}) {
  const live = useLiveness();
  useEffect(() => {
    void probeTools();
  }, []);
  const [q, setQ] = useState("");
  const [selId, setSelId] = useState<string | null>(null);
  const groups = useMemo(() => allToolGroups(), []);
  const total = useMemo(() => groups.reduce((n, g) => n + g.tools.length, 0), [groups]);

  const ql = q.trim().toLowerCase();
  const filtered = groups
    .map((g) => ({
      group: g.group,
      tools: g.tools.filter(
        (t) => !ql || t.label.toLowerCase().includes(ql) || t.id.includes(ql) || t.group.toLowerCase().includes(ql),
      ),
    }))
    .filter((g) => g.tools.length > 0);

  const sel = selId ? groups.flatMap((g) => g.tools).find((t) => t.id === selId) ?? null : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 border-b border-divider px-3 py-2">
        <div className="flex items-center gap-2">
          <Icon name="wrench" size={14} />
          <span className="text-[calc(12px_*_var(--text-scale))] font-bold tracking-tight text-ink-primary">Tools</span>
          <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">{total} total</span>
        </div>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter tools…"
          className="mt-2 w-full rounded border border-divider bg-bg-card px-2 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent placeholder:text-ink-dim"
        />
      </div>
      <div className="min-h-0 flex-1 overflow-auto pb-3">
        {filtered.map(({ group, tools }) => (
          <div key={group} className="pt-2">
            <div className="px-3 pb-1 text-[calc(10px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">{group}</div>
            {tools.map((t) => {
              const status = statusFor(t, live.routes);
              const attack = toolMode(t) === "active";
              return (
                <button
                  key={t.id}
                  draggable
                  onDragStart={(e) => {
                    e.dataTransfer.setData(TOOL_DND_MIME, t.id);
                    e.dataTransfer.setData("text/plain", t.id);
                    e.dataTransfer.effectAllowed = "copy";
                  }}
                  onClick={() => setSelId(t.id)}
                  className={`flex w-full cursor-grab items-center gap-2 px-3 py-1.5 text-left active:cursor-grabbing ${
                    selId === t.id ? "bg-nav-active" : "hover:bg-nav-hover"
                  }`}
                >
                  <Dot color={STATUS_META[status].color} pulse={status === "live"} />
                  <span className="truncate text-[calc(12.5px_*_var(--text-scale))] text-ink-muted">{t.label}</span>
                  <span
                    className={`ml-auto shrink-0 rounded px-1 text-[calc(9px_*_var(--text-scale))] uppercase tracking-wide ${
                      attack ? "bg-danger/15 text-danger" : "bg-bg-base text-ink-dim ring-1 ring-divider"
                    }`}
                  >
                    {attack ? "active" : "passive"}
                  </span>
                </button>
              );
            })}
          </div>
        ))}
        {filtered.length === 0 && <div className="px-3 py-6 text-[calc(12px_*_var(--text-scale))] text-ink-dim">No tools match “{q}”.</div>}
      </div>

      {/* Tool info + run */}
      {sel && (
        <div className="shrink-0 border-t border-divider bg-bg-surface p-3">
          <div className="flex items-center gap-2">
            <span className="text-[calc(13px_*_var(--text-scale))] font-bold tracking-tight text-ink-primary">{sel.label}</span>
            <span className="rounded bg-bg-base px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] text-ink-dim ring-1 ring-divider">{sel.group}</span>
            <span className={`rounded px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold ${toolMode(sel) === "active" ? "bg-danger/15 text-danger" : "bg-accent/[0.13] text-accent"}`}>
              {toolMode(sel) === "active" ? "active · touches the target" : "passive · observe only"}
            </span>
          </div>
          <p className="mt-1.5 text-[calc(11.5px_*_var(--text-scale))] leading-relaxed text-ink-muted">{sel.blurb}</p>
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
            <span>tier {sel.tier}</span>
            {sel.requires && <span>requires: {sel.requires}</span>}
            {sel.fields.length > 0 && (
              <span>inputs: {sel.fields.map((f) => f.label).join(", ")}</span>
            )}
          </div>
          <Button
            variant="solid"
            size="sm"
            className="mt-2.5"
            disabled={running}
            onClick={(e) => { void inkConfirm(e.currentTarget); onRun(sel); }}
          >
            <Icon name="terminal" size={13} /> {running ? "Running…" : `Run ${sel.label}`}
          </Button>
        </div>
      )}
    </div>
  );
}

// ── Playbooks board — build (drag tools / create) + run against the sub-target ─
function PlaybooksBoard({
  onRunPlaybook,
  onError,
}: {
  onRunPlaybook: (pb: Playbook) => Promise<void>;
  onError: (m: string) => void;
}) {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [over, setOver] = useState<string | null>(null);

  function refresh() {
    listPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
  }
  useEffect(refresh, []);

  async function create() {
    const clean = name.trim() || "Untitled playbook";
    try {
      await createPlaybook(clean);
      setName("");
      setCreating(false);
      refresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  async function drop(pb: Playbook, toolId: string) {
    if (!toolId) return;
    try {
      await appendStep(pb, toolId);
      refresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setOver(null);
    }
  }

  async function remove(pb: Playbook) {
    setPlaybooks((cur) => cur.filter((p) => p.id !== pb.id));
    try {
      await deletePlaybook(pb.id);
    } finally {
      refresh();
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-divider px-3 py-2">
        <Icon name="book" size={14} />
        <span className="text-[calc(12px_*_var(--text-scale))] font-bold tracking-tight text-ink-primary">Playbooks</span>
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">{playbooks.length}</span>
        <button
          onClick={() => setCreating((c) => !c)}
          className="ml-auto rounded bg-accent/15 px-2 py-1 text-[calc(11px_*_var(--text-scale))] font-bold text-accent ring-1 ring-accent/30 hover:bg-accent/25"
        >
          + New
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {creating && (
          <form
            onSubmit={(e) => { e.preventDefault(); void create(); }}
            className="mb-2 flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/[0.06] p-2"
          >
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Escape" && setCreating(false)}
              placeholder="Name this playbook…"
              className="min-w-0 flex-1 bg-transparent px-1 text-[calc(13px_*_var(--text-scale))] text-ink-primary outline-none placeholder:text-ink-dim"
            />
            <button type="submit" className="rounded bg-accent px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] font-bold text-bg-base">Create</button>
          </form>
        )}
        {playbooks.length === 0 && !creating ? (
          <div className="mt-4 rounded-lg border border-dashed border-divider py-8 text-center text-[calc(12px_*_var(--text-scale))] text-ink-dim">
            No playbooks yet. Hit <span className="text-accent">+ New</span>, name it, then drag tools in from the Tools tab.
          </div>
        ) : (
          <div className="space-y-2">
            {playbooks.map((pb) => (
              <div
                key={pb.id}
                onDragOver={(e) => {
                  if (e.dataTransfer.types.includes(TOOL_DND_MIME)) {
                    e.preventDefault();
                    e.dataTransfer.dropEffect = "copy";
                    setOver(pb.id);
                  }
                }}
                onDragLeave={() => setOver((c) => (c === pb.id ? null : c))}
                onDrop={(e) => {
                  e.preventDefault();
                  void drop(pb, e.dataTransfer.getData(TOOL_DND_MIME) || e.dataTransfer.getData("text/plain"));
                }}
                className={`rounded-lg border bg-bg-card p-2.5 ${over === pb.id ? "border-accent ring-2 ring-accent/40" : "border-divider"}`}
              >
                <div className="flex items-center gap-2">
                  <span className="truncate text-[calc(13px_*_var(--text-scale))] font-bold text-ink-primary">{pb.name}</span>
                  <span className="ml-auto shrink-0 rounded bg-bg-base px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-ink-dim ring-1 ring-divider">
                    {pb.steps.length} {pb.steps.length === 1 ? "step" : "steps"}
                  </span>
                  <Button variant="ghost" size="sm" disabled={pb.steps.length === 0} onClick={() => void onRunPlaybook(pb)}>
                    <Sparkle solid /> Run
                  </Button>
                  <button onClick={() => void remove(pb)} title="Delete" className="text-ink-dim hover:text-danger">✕</button>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {pb.steps.length === 0 ? (
                    <span className="text-[calc(10px_*_var(--text-scale))] text-ink-dim">empty — drag tools here</span>
                  ) : (
                    pb.steps.map((s, i) => (
                      <span key={i} className="rounded bg-bg-base px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-ink-muted ring-1 ring-divider">
                        {i + 1}. {s.tool_id}
                      </span>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      <p className="shrink-0 border-t border-divider px-3 py-1.5 text-[calc(10px_*_var(--text-scale))] text-ink-dim">
        Drag a tool from the Tools tab onto a playbook to append a step.
      </p>
    </div>
  );
}

function PromoteFinding({
  sub,
  onError,
  onDone,
}: {
  sub: FlatSub;
  onError: (m: string) => void;
  onDone: () => void;
}) {
  const [title, setTitle] = useState("");
  const [sev, setSev] = useState<FindingSeverity>("medium");
  const [busy, setBusy] = useState(false);

  async function onCreate() {
    if (!title.trim()) return;
    setBusy(true);
    try {
      await createPairingFinding({
        sub_target_id: sub.id,
        title: title.trim(),
        severity: sev,
        tool: "spine-workbench",
        evidence: `Pairing run against ${sub.address}`,
      });
      setTitle("");
      onDone();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="shrink-0 border-t border-divider bg-bg-surface p-3">
      <div className="mb-2 flex items-center gap-1.5">
        <Icon name="flag" size={13} />
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">Promote to finding</span>
      </div>
      <div className="flex items-center gap-2">
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onCreate()}
          placeholder="Finding title"
          className="flex-1 rounded-md border border-divider bg-bg-base px-2 py-1.5 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent/50"
        />
        <select
          value={sev}
          onChange={(e) => setSev(e.target.value as FindingSeverity)}
          className="rounded-md border border-divider bg-bg-base px-2 py-1.5 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent/50"
        >
          {FINDING_SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <Button variant="solid" size="sm" disabled={busy || !title.trim()} onClick={(e) => { void inkConfirm(e.currentTarget); onCreate(); }}>
          <Sparkle solid /> Create
        </Button>
      </div>
    </div>
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
