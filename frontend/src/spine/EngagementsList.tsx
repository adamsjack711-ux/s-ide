// Engagements list — the front door of the spine.
//
// Engagement-first IA: this lists every engagement; opening one drills into its
// workspace (Targets / Workbench / Findings / Reporting). Creating an engagement
// is free here. Each card surfaces how much the engagement arms — the count of
// targets it reaches and sub-targets it has live — because an engagement's whole
// point is the scope it authorizes.
import { useState } from "react";
import { Button, GlassCard, Sparkle, StatusDot } from "performative-ui";
import Icon from "../shell/Icon";
import { createEngagement, isLabEngagement, type Engagement } from "../lib/engagement";
import type { Target } from "../lib/spine";

const ARMED_COLOR = "var(--accent)";

export default function EngagementsList({
  engagements,
  targets,
  reload,
  onError,
  onOpen,
}: {
  engagements: Engagement[];
  targets: Target[];
  reload: () => Promise<void>;
  onError: (m: string) => void;
  onOpen: (engagement: Engagement) => void;
}) {
  const [name, setName] = useState("");

  // Lab engagements (local sandbox + lab spin-ups + "Lab: …" attaches) live in
  // the Learn → Labs area, not here. The engagements list is for real ones.
  const shown = engagements.filter((e) => !isLabEngagement(e));

  async function onCreate() {
    if (!name.trim()) return;
    try {
      const e = await createEngagement({ name: name.trim() });
      setName("");
      await reload();
      onOpen(e);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  // Per-engagement arming roll-up: which targets it reaches + sub-targets it arms.
  function stats(eid: string): { targets: number; armed: number } {
    const tset = new Set<string>();
    let armed = 0;
    for (const t of targets) {
      for (const s of t.sub_targets ?? []) {
        if (s.armed && s.arming?.engagement_id === eid) {
          armed += 1;
          tset.add(t.id);
        }
      }
    }
    return { targets: tset.size, armed };
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Create bar */}
      <div className="flex shrink-0 flex-wrap items-center gap-2.5 border-b border-divider px-4 py-3">
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">New engagement</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onCreate()}
          placeholder="Name (e.g. Acme Q3 Pentest)"
          className="min-w-[220px] flex-1 rounded-md border border-divider bg-bg-base px-2.5 py-1.5 text-[calc(13px_*_var(--text-scale))] text-ink-primary outline-none placeholder:text-ink-dim focus:border-accent/50"
        />
        <Button variant="solid" size="sm" onClick={onCreate}>
          <Sparkle solid /> Create
        </Button>
      </div>

      {/* List */}
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {shown.length === 0 && (
          <div className="p-3 text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-muted">
            No engagements yet. Create one above — it's the authorized context that
            arms targets. Targets live inside the engagement that arms them.
          </div>
        )}
        <div className="space-y-1.5">
          {shown.map((e) => {
            const { targets: tcount, armed } = stats(e.id);
            return (
              <GlassCard key={e.id} className="p-0" glowOnHover>
                <div className="flex items-center gap-2 px-3 py-2.5">
                  <Icon name="shield" size={14} />
                  <button
                    onClick={() => onOpen(e)}
                    className="text-[calc(13px_*_var(--text-scale))] font-semibold tracking-tight text-ink-primary hover:text-accent"
                  >
                    {e.name}
                  </button>
                  <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold text-ink-muted ring-1 ring-divider">
                    {e.provenance}
                  </span>
                  <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold text-ink-muted ring-1 ring-divider">
                    {e.type}
                  </span>
                  <span className="flex items-center gap-1.5 text-[calc(11.5px_*_var(--text-scale))] text-ink-muted">
                    {armed > 0 && <StatusDot color={ARMED_COLOR} />}
                    <span className="">{tcount}</span> target{tcount === 1 ? "" : "s"}
                    {armed > 0 && (
                      <span className="text-accent"><span className="">{armed}</span> armed</span>
                    )}
                  </span>
                  <div className="flex-1" />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onOpen(e)}
                    title="Open this engagement — its Targets, Workbench, Findings and Reporting"
                  >
                    Open →
                  </Button>
                </div>
              </GlassCard>
            );
          })}
        </div>
      </div>
    </div>
  );
}
