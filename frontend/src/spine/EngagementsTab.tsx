// Engagements tab — manage the authorized context + see/attach what it arms.
//
// An engagement owns scope + attestation. Attaching it to a sub-target ARMS that
// sub-target (brings it into this engagement's scope; the parent Target never
// confers scope). Each attach/detach is an explicit act. Engagement creation
// itself lives on the Home dashboard — this tab focuses on the arming surface.
import { useEffect, useMemo, useState } from "react";
import { Button, Sparkle } from "performative-ui";
import Icon from "../shell/Icon";
import { inkConfirm } from "../lib/dopamine";
import { createEngagement, type Engagement } from "../lib/engagement";
import {
  armSubTarget,
  disarmSubTarget,
  type SubTarget,
  type Target,
} from "../lib/spine";

type FlatSub = SubTarget & { targetName: string; targetId: string };

export default function EngagementsTab({
  targets,
  engagements,
  reload,
  onError,
  onOpenWorkbench,
  restrictTargetId,
}: {
  targets: Target[];
  engagements: Engagement[];
  reload: () => Promise<void>;
  onError: (m: string) => void;
  onOpenWorkbench: () => void;
  /** When set, the tab is scoped to one Target's sub-targets only. */
  restrictTargetId?: string;
}) {
  const [selId, setSelId] = useState<string | null>(engagements[0]?.id ?? null);
  const [newName, setNewName] = useState("");

  useEffect(() => {
    if (!engagements.some((e) => e.id === selId)) setSelId(engagements[0]?.id ?? null);
  }, [engagements, selId]);

  const allSubs = useMemo<FlatSub[]>(
    () =>
      targets
        .filter((t) => !restrictTargetId || t.id === restrictTargetId)
        .flatMap((t) =>
          (t.sub_targets ?? []).map((s) => ({ ...s, targetName: t.name, targetId: t.id })),
        ),
    [targets, restrictTargetId],
  );

  async function onCreate() {
    if (!newName.trim()) return;
    try {
      const e = await createEngagement({ name: newName.trim() });
      setNewName("");
      await reload();
      setSelId(e.id);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  const sel = engagements.find((e) => e.id === selId) ?? null;

  async function guard(fn: () => Promise<unknown>) {
    try {
      await fn();
      await reload();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  function armedBy(eid: string): FlatSub[] {
    return allSubs.filter((s) => s.armed && s.arming?.engagement_id === eid);
  }

  return (
    <div className="flex h-full min-h-0">
      {/* Left — engagement list */}
      <aside className="flex w-72 shrink-0 flex-col border-r border-divider">
        <div className="shrink-0 border-b border-divider px-3 py-2.5">
          <div className="mb-2 text-[11px] uppercase tracking-wide text-ink-dim">Engagements</div>
          <div className="flex gap-1.5">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onCreate()}
              placeholder="New engagement name"
              className="min-w-0 flex-1 rounded-md border border-divider bg-bg-base px-2 py-1 text-[12px] text-ink-primary outline-none focus:border-accent/50"
            />
            <Button variant="solid" size="sm" onClick={onCreate}>
              <Sparkle solid /> Create
            </Button>
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {engagements.length === 0 && (
            <div className="p-4 text-[12px] text-ink-dim">
              No engagements. Create one on the dashboard, then attach it to
              sub-targets here to arm them.
            </div>
          )}
          {engagements.map((e) => {
            const armed = armedBy(e.id).length;
            const active = e.id === selId;
            return (
              <button
                key={e.id}
                onClick={() => setSelId(e.id)}
                className={`flex w-full flex-col gap-1 border-b border-divider/60 px-3 py-2.5 text-left ${
                  active ? "bg-bg-hover" : "hover:bg-bg-hover/50"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-[13px] text-ink-primary">{e.name}</span>
                  <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[10px] text-ink-muted ring-1 ring-divider">
                    {e.provenance}
                  </span>
                </div>
                <span className="text-[11px] text-ink-dim">
                  {armed > 0 ? <span className="text-accent">{armed} sub-target{armed === 1 ? "" : "s"} armed</span> : "arms nothing"}
                </span>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Right — detail */}
      <section className="min-w-0 flex-1 overflow-auto">
        {!sel ? (
          <div className="p-6 text-sm text-ink-dim">Select an engagement.</div>
        ) : (
          <EngagementDetail
            engagement={sel}
            armed={armedBy(sel.id)}
            candidates={allSubs.filter((s) => !s.armed)}
            guard={guard}
            onOpenWorkbench={onOpenWorkbench}
          />
        )}
      </section>
    </div>
  );
}

function EngagementDetail({
  engagement,
  armed,
  candidates,
  guard,
  onOpenWorkbench,
}: {
  engagement: Engagement;
  armed: FlatSub[];
  candidates: FlatSub[];
  guard: (fn: () => Promise<unknown>) => Promise<void>;
  onOpenWorkbench: () => void;
}) {
  const [pick, setPick] = useState<string>(candidates[0]?.id ?? "");

  useEffect(() => {
    if (!candidates.some((c) => c.id === pick)) setPick(candidates[0]?.id ?? "");
  }, [candidates, pick]);

  const scope = engagement.scope ?? [];

  return (
    <div className="p-5">
      <h2 className="text-[17px] font-semibold text-ink-primary">{engagement.name}</h2>
      <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px]">
        <span className="rounded bg-bg-hover px-1.5 py-0.5 text-ink-muted ring-1 ring-divider">
          {engagement.provenance}
        </span>
        <span className="rounded bg-bg-hover px-1.5 py-0.5 text-ink-muted ring-1 ring-divider">
          {engagement.type}
        </span>
        <span className="text-ink-dim">
          scope: {scope.length === 0 ? "unrestricted" : scope.join(", ")}
        </span>
      </div>

      {/* Attach a sub-target (arm) */}
      <div className="mt-4 rounded-lg border border-divider bg-bg-surface p-3">
        <div className="mb-2 text-[11px] uppercase tracking-wide text-ink-dim">
          Arm a sub-target with this engagement
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={pick}
            onChange={(e) => setPick(e.target.value)}
            disabled={candidates.length === 0}
            className="min-w-[260px] flex-1 rounded-md border border-divider bg-bg-base px-2 py-1.5 text-[12px] text-ink-primary outline-none focus:border-accent/50 disabled:opacity-50"
          >
            {candidates.length === 0 && <option value="">no un-armed sub-targets</option>}
            {candidates.map((s) => (
              <option key={s.id} value={s.id}>
                {s.targetName} › {s.type} {s.address}
              </option>
            ))}
          </select>
          <Button
            variant="solid"
            size="sm"
            disabled={!pick}
            onClick={(e) => {
              const sub = candidates.find((c) => c.id === pick);
              if (sub) { void inkConfirm(e.currentTarget); guard(() => armSubTarget(sub, engagement.id)); }
            }}
          >
            <Sparkle solid /> Attach &amp; arm
          </Button>
        </div>
      </div>

      {/* Armed sub-targets */}
      <div className="mt-4 flex items-center justify-between">
        <div className="text-[11px] uppercase tracking-wide text-ink-dim">
          Sub-targets this engagement arms ({armed.length})
        </div>
        {armed.length > 0 && (
          <button
            onClick={onOpenWorkbench}
            className="flex items-center gap-1.5 text-[11px] text-accent hover:underline"
          >
            <Icon name="wrench" size={13} /> Run in Workbench
          </button>
        )}
      </div>
      <div className="mt-2 space-y-2">
        {armed.length === 0 && (
          <div className="text-[12px] text-ink-dim">
            This engagement arms nothing yet. Attaching it above brings a sub-target
            into its scope and unlocks it in the Workbench.
          </div>
        )}
        {armed.map((s) => (
          <div
            key={s.id}
            className="flex flex-wrap items-center gap-3 rounded-lg border border-accent/30 bg-accent/[0.05] px-3 py-2.5"
          >
            <span className="text-[11px] text-ink-dim">{s.targetName} ›</span>
            <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[10px] text-ink-muted ring-1 ring-divider">
              {s.type}
            </span>
            <span className="font-mono text-[12px] text-ink-primary">{s.address}</span>
            <div className="flex-1" />
            <Button variant="ghost" size="sm" onClick={() => guard(() => disarmSubTarget(s))}>
              Detach
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}
