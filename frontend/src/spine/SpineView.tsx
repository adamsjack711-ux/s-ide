// SpineView — the Target-first engagement spine.
//
// The information architecture is Target-centric: the front door is the Targets
// list (declare/browse Targets + sub-targets, arm/disarm inline). Opening a
// Target drills into its workspace, where its Engagements, Workbench, Findings
// and Reporting all live — scoped to that one Target.
//
// The governing rule, enforced server-side and reflected here: authorization
// flows from the engagement, never from a target existing. The spine bus events
// (armed/disarmed/findingCreated) trigger a reload so every surface stays
// consistent.
import { useCallback, useEffect, useState } from "react";
import { Button, EyebrowPill, GradientText, Sparkle } from "performative-ui";
import { on } from "../shell/bus";
import { celebrateBig, pulse } from "../lib/dopamine";
import { listEngagements, type Engagement } from "../lib/engagement";
import { listTargets, bootstrapLocal, type Target } from "../lib/spine";
import TargetsTab from "./TargetsTab";
import TargetWorkspace from "./TargetWorkspace";

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

  const openTarget = openId ? targets.find((t) => t.id === openId) ?? null : null;

  async function onBootstrapLocal() {
    try {
      await bootstrapLocal();
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      {/* Header — Targets is the top of the spine. */}
      {!openTarget && (
        <div className="flex shrink-0 items-center gap-3 border-b border-divider bg-bg-sidebar px-4 py-3">
          <EyebrowPill className="mhp-eyebrow">Engagement Spine</EyebrowPill>
          <h1 className="flex items-center gap-2 text-[20px] font-bold tracking-tight leading-none">
            <GradientText>Targets</GradientText>
            <Sparkle />
          </h1>
          <span className="hidden text-[12px] text-ink-muted md:inline">
            declare a system, then open it for its engagements, workbench, findings &amp; reporting
          </span>
          <div className="flex-1" />
          <Button
            variant="ghost"
            size="sm"
            onClick={onBootstrapLocal}
            title="Declare the local machine as a lab Target + a local-only engagement (idempotent; nothing is auto-armed)"
          >
            <Sparkle solid /> Local surface
          </Button>
        </div>
      )}

      {err && (
        <div className="shrink-0 border-b border-divider bg-critical/[0.08] px-4 py-1.5 text-[12px] text-critical">
          {err}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-hidden">
        {loading ? (
          <div className="p-6 text-sm text-ink-dim">Loading spine…</div>
        ) : openTarget ? (
          <TargetWorkspace
            target={openTarget}
            engagements={engagements}
            reload={reload}
            onError={setErr}
            onBack={() => setOpenId(null)}
          />
        ) : (
          <TargetsTab
            targets={targets}
            engagements={engagements}
            reload={reload}
            onError={setErr}
            onOpen={(t) => setOpenId(t.id)}
          />
        )}
      </div>
    </div>
  );
}
