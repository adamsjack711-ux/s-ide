// SpineView — the Engagement-first engagement spine.
//
// The information architecture is Engagement-centric: the front door is the
// Engagements list (create/browse engagements). Opening an Engagement drills
// into its workspace, where its Targets, Workbench, Findings and Reporting all
// live — scoped to that one engagement. Targets are nested inside the engagement
// because authorization flows from the engagement that arms them, never from a
// target existing on its own.
//
// The spine bus events (armed/disarmed/findingCreated) trigger a reload so every
// surface stays consistent.
import { useCallback, useEffect, useState } from "react";
import { GradientText, Sparkle } from "performative-ui";
import { on } from "../shell/bus";
import { celebrateBig, pulse } from "../lib/dopamine";
import { listEngagements, type Engagement } from "../lib/engagement";
import { listTargets, type Target } from "../lib/spine";
import EngagementsList from "./EngagementsList";
import EngagementWorkspace from "./EngagementWorkspace";

export default function SpineView() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const [ts, es] = await Promise.all([listTargets(true), listEngagements()]);
      setTargets(ts);
      setEngagements(es);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Cross-link: any arming / finding event refreshes the shared model — and
  // earns a little dopamine (arming = a sub-target goes live; a finding = a win).
  useEffect(() => on("subTargetArmed", () => { void reload(); void pulse(); }), [reload]);
  useEffect(() => on("subTargetDisarmed", () => void reload()), [reload]);
  useEffect(() => on("findingCreated", () => { void reload(); void celebrateBig(); }), [reload]);

  const openEngagement = openId ? engagements.find((e) => e.id === openId) ?? null : null;

  return (
    <div className="spine-ui flex h-full min-h-0 flex-col bg-bg-base">
      {/* Header — Engagements is the top of the spine. */}
      {!openEngagement && (
        <div className="flex shrink-0 items-center gap-3 border-b border-divider bg-bg-sidebar px-4 py-3">
          <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">Engagement Spine</span>
          <h1 className="flex items-center gap-2 text-[calc(20px_*_var(--text-scale))] font-bold tracking-tight leading-none">
            <GradientText>Engagements</GradientText>
            <Sparkle />
          </h1>
          <span className="hidden text-[calc(12px_*_var(--text-scale))] text-ink-muted md:inline">
            create an engagement, then open it for its targets, workbench, findings &amp; reporting
          </span>
        </div>
      )}

      {err && (
        <div className="shrink-0 border-b border-divider bg-critical/[0.08] px-4 py-1.5 text-[calc(12px_*_var(--text-scale))] text-critical">
          {err}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-hidden">
        {loading ? (
          <div className="p-6 text-sm text-ink-dim">Loading spine…</div>
        ) : openEngagement ? (
          <EngagementWorkspace
            engagement={openEngagement}
            targets={targets}
            engagements={engagements}
            reload={reload}
            onError={setErr}
            onBack={() => setOpenId(null)}
          />
        ) : (
          <EngagementsList
            engagements={engagements}
            targets={targets}
            reload={reload}
            onError={setErr}
            onOpen={(e) => setOpenId(e.id)}
          />
        )}
      </div>
    </div>
  );
}
