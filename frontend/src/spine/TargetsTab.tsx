// Targets tab — declare/browse Targets with their sub-targets nested beneath
// them as an expandable tree.
//
// Declaring a Target or sub-target is FREE (inert, authorizes nothing). Arming a
// sub-target — attaching an engagement — is the deliberate act, done inline here
// or from the Engagements tab. Each sub-target shows its armed/un-armed state
// and, when armed, which engagement arms it.
import { useEffect, useState } from "react";
import { Button, GlassCard, Sparkle, StatusDot } from "performative-ui";
import Icon from "../shell/Icon";
import { inkConfirm, pulse } from "../lib/dopamine";
import type { Engagement } from "../lib/engagement";
import {
  PROVENANCES,
  SUBTARGET_TYPES,
  armSubTarget,
  createSubTarget,
  createTarget,
  deleteSubTarget,
  deleteTarget,
  disarmSubTarget,
  type Provenance,
  type SubTarget,
  type SubTargetType,
  type Target,
} from "../lib/spine";

const PROV_PILL: Record<Provenance, string> = {
  lab: "bg-accent/[0.13] text-accent ring-1 ring-accent/30",
  owned: "bg-low/[0.13] text-low ring-1 ring-low/30",
  external: "bg-high/[0.13] text-high ring-1 ring-high/30",
};

// CSS-var color for the armed StatusDot (matches the accent "we're live" dot).
const ARMED_COLOR = "var(--accent)";

export default function TargetsTab({
  targets,
  engagements,
  reload,
  onError,
  onOpen,
}: {
  targets: Target[];
  engagements: Engagement[];
  reload: () => Promise<void>;
  onError: (m: string) => void;
  /** When set, a Target can be opened (drilled into). Omitted inside an
   *  engagement, where targets are leaves and the tree only expands inline. */
  onOpen?: (target: Target) => void;
}) {
  const [name, setName] = useState("");
  const [prov, setProv] = useState<Provenance>("external");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // First load: expand every target so its sub-targets are visible by default.
  const [seeded, setSeeded] = useState(false);
  useEffect(() => {
    if (!seeded && targets.length) {
      setExpanded(new Set(targets.map((t) => t.id)));
      setSeeded(true);
    }
  }, [targets, seeded]);

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function guard(fn: () => Promise<unknown>) {
    try {
      await fn();
      await reload();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  async function onDeclare() {
    if (!name.trim()) return;
    await guard(async () => {
      const t = await createTarget({ name: name.trim(), provenance: prov });
      setName("");
      setExpanded((prev) => new Set(prev).add(t.id));
    });
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Declare bar */}
      <div className="flex shrink-0 flex-wrap items-center gap-2.5 border-b border-divider px-4 py-3">
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">Declare a target</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onDeclare()}
          placeholder="Name (e.g. Acme staging)"
          className="min-w-[200px] flex-1 rounded-md border border-divider bg-bg-base px-2.5 py-1.5 text-[calc(13px_*_var(--text-scale))] text-ink-primary outline-none placeholder:text-ink-dim focus:border-accent/50"
        />
        <select
          value={prov}
          onChange={(e) => setProv(e.target.value as Provenance)}
          className="rounded-md border border-divider bg-bg-base px-2 py-1.5 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent/50"
        >
          {PROVENANCES.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <Button variant="solid" size="sm" onClick={onDeclare}>
          <Sparkle solid /> Declare
        </Button>
      </div>

      {/* Tree */}
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {targets.length === 0 && (
          <div className="p-3 text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-muted">
            No targets yet. Declaring one is free — it authorizes nothing until an
            engagement arms its sub-targets.
          </div>
        )}
        <div className="space-y-1.5">
          {targets.map((t) => (
            <TargetNode
              key={t.id}
              target={t}
              engagements={engagements}
              open={expanded.has(t.id)}
              onToggle={() => toggle(t.id)}
              onOpen={onOpen ? () => onOpen(t) : undefined}
              guard={guard}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function TargetNode({
  target,
  engagements,
  open,
  onToggle,
  onOpen,
  guard,
}: {
  target: Target;
  engagements: Engagement[];
  open: boolean;
  onToggle: () => void;
  onOpen?: () => void;
  guard: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const subs = target.sub_targets ?? [];
  const armed = subs.filter((s) => s.armed).length;

  return (
    <GlassCard className="p-0" glowOnHover>
      {/* Target row */}
      <div className="flex items-center gap-2 px-3 py-2.5">
        <button
          onClick={onToggle}
          className="text-ink-dim hover:text-ink-primary"
          title={open ? "Collapse" : "Expand"}
        >
          <span className="inline-block w-3 text-[calc(11px_*_var(--text-scale))]">{open ? "▾" : "▸"}</span>
        </button>
        <Icon name="box" size={14} />
        {onOpen ? (
          <button onClick={onOpen} className="text-[calc(13px_*_var(--text-scale))] font-semibold tracking-tight text-ink-primary hover:text-accent">
            {target.name}
          </button>
        ) : (
          <span className="text-[calc(13px_*_var(--text-scale))] font-semibold tracking-tight text-ink-primary">{target.name}</span>
        )}
        <span className={`rounded px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold ${PROV_PILL[target.provenance]}`}>
          {target.provenance}
        </span>
        <span className="flex items-center gap-1.5 text-[calc(11.5px_*_var(--text-scale))] text-ink-muted">
          {armed > 0 && <StatusDot color={ARMED_COLOR} />}
          <span className="">{subs.length}</span> sub-target{subs.length === 1 ? "" : "s"}
          {armed > 0 && <span className="text-accent"><span className="">{armed}</span> armed</span>}
        </span>
        <span className="hidden text-[calc(11.5px_*_var(--text-scale))] text-ink-dim lg:inline">inert · authorizes nothing</span>
        <div className="flex-1" />
        {onOpen && (
          <Button
            variant="ghost"
            size="sm"
            onClick={onOpen}
            title="Open this target"
          >
            Open →
          </Button>
        )}
        <button
          onClick={() => guard(() => deleteTarget(target.id))}
          title="Delete target"
          className="rounded-md border border-divider px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-dim hover:border-danger/40 hover:text-danger"
        >
          Delete
        </button>
      </div>

      {/* Sub-targets + add row */}
      {open && (
        <div className="border-t border-divider/60 px-3 py-2.5">
          <div className="space-y-1.5">
            {subs.length === 0 && (
              <div className="pl-5 text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-muted">
                No sub-targets. Add an addressable component below — it stays un-armed
                until an engagement arms it.
              </div>
            )}
            {subs.map((s) => (
              <SubTargetRow key={s.id} sub={s} engagements={engagements} guard={guard} />
            ))}
          </div>
          <AddSubTarget targetId={target.id} guard={guard} />
        </div>
      )}
    </GlassCard>
  );
}

function SubTargetRow({
  sub,
  engagements,
  guard,
}: {
  sub: SubTarget;
  engagements: Engagement[];
  guard: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [pick, setPick] = useState<string>(engagements[0]?.id ?? "");

  return (
    <div
      className={`ml-5 flex flex-wrap items-center gap-3 rounded-md border px-3 py-2 ${
        sub.armed ? "border-accent/30 bg-accent/[0.05]" : "border-divider bg-bg-base"
      }`}
    >
      <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold text-ink-muted ring-1 ring-divider">
        {sub.type}
      </span>
      <span className="text-ink-primary">{sub.address}</span>
      {sub.label && <span className="text-[calc(11.5px_*_var(--text-scale))] text-ink-dim">{sub.label}</span>}

      <div className="flex-1" />

      {sub.armed ? (
        <>
          <span className="flex items-center gap-1.5 text-[calc(11.5px_*_var(--text-scale))] font-medium text-accent">
            <StatusDot color={ARMED_COLOR} />
            armed · {sub.arming?.engagement_name ?? sub.arming?.engagement_id?.slice(0, 8)}
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={(e) => { void pulse(e.currentTarget); guard(() => disarmSubTarget(sub)); }}
          >
            Disarm
          </Button>
        </>
      ) : (
        <>
          <span className="text-[calc(11.5px_*_var(--text-scale))] text-ink-dim">un-armed</span>
          <select
            value={pick}
            onChange={(e) => setPick(e.target.value)}
            disabled={engagements.length === 0}
            className="rounded-md border border-divider bg-bg-base px-2 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent/50 disabled:opacity-50"
          >
            {engagements.length === 0 && <option value="">no engagements</option>}
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>{e.name}</option>
            ))}
          </select>
          <Button
            variant="solid"
            size="sm"
            disabled={!pick}
            onClick={(e) => { if (pick) { void inkConfirm(e.currentTarget); guard(() => armSubTarget(sub, pick)); } }}
          >
            <Sparkle solid /> Arm
          </Button>
        </>
      )}
      <button
        onClick={() => guard(() => deleteSubTarget(sub.id))}
        title="Delete sub-target"
        className="text-ink-dim hover:text-danger"
      >
        ×
      </button>
    </div>
  );
}

function AddSubTarget({
  targetId,
  guard,
}: {
  targetId: string;
  guard: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [type, setType] = useState<SubTargetType>("host");
  const [addr, setAddr] = useState("");
  const [label, setLabel] = useState("");

  async function onAdd() {
    if (!addr.trim()) return;
    await guard(async () => {
      await createSubTarget(targetId, { type, address: addr.trim(), label: label.trim() });
      setAddr("");
      setLabel("");
    });
  }

  return (
    <div className="ml-5 mt-2.5 flex flex-wrap items-center gap-2">
      <span className="text-ink-dim">+</span>
      <select
        value={type}
        onChange={(e) => setType(e.target.value as SubTargetType)}
        className="rounded-md border border-divider bg-bg-base px-2 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent/50"
      >
        {SUBTARGET_TYPES.map((t) => (
          <option key={t} value={t}>{t}</option>
        ))}
      </select>
      <input
        value={addr}
        onChange={(e) => setAddr(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && onAdd()}
        placeholder="address (host, host:port, url, path…)"
        className="min-w-[200px] flex-1 rounded-md border border-divider bg-bg-base px-2.5 py-1 text-ink-primary outline-none placeholder:text-ink-dim focus:border-accent/50"
      />
      <input
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && onAdd()}
        placeholder="label (optional)"
        className="w-32 rounded-md border border-divider bg-bg-base px-2.5 py-1 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none placeholder:text-ink-dim focus:border-accent/50"
      />
      <Button variant="ghost" size="sm" onClick={onAdd}>
        Add sub-target
      </Button>
    </div>
  );
}
