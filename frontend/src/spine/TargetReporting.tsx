// Target Reporting — a report scoped to one Target.
//
// A Target's report is the roll-up across its sub-targets' pairings: findings by
// severity, by sub-target, and by the engagement that produced them. Backend
// reports are engagement-scoped; this is the Target-level view the IA now nests
// inside each Target.
import { useCallback, useEffect, useMemo, useState } from "react";
import { GlassCard, GradientText, Sparkle, StatCounter } from "performative-ui";
import { useBus } from "../shell/bus";
import { SEV_PILL, SEV_LABEL } from "../engagement/findings/style";
import type { Engagement, FindingSeverity } from "../lib/engagement";
import { listTargetFindings, type PairingFinding, type Target } from "../lib/spine";

const SEV_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

export default function TargetReporting({
  target,
  engagements,
}: {
  target: Target;
  engagements: Engagement[];
}) {
  const [findings, setFindings] = useState<PairingFinding[]>([]);

  const load = useCallback(async () => {
    try {
      setFindings(await listTargetFindings(target.id));
    } catch {
      /* keep the panel responsive */
    }
  }, [target.id]);

  useEffect(() => {
    void load();
  }, [load]);
  useBus("findingCreated", () => void load());

  const engName = useMemo(() => {
    const m = new Map(engagements.map((e) => [e.id, e.name]));
    return (id: string) => m.get(id) ?? id.slice(0, 8);
  }, [engagements]);
  const subAddr = useMemo(() => {
    const m = new Map((target.sub_targets ?? []).map((s) => [s.id, s.address]));
    return (id: string) => m.get(id) ?? id.slice(0, 8);
  }, [target]);

  const bySev = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  const bySub = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.sub_target_id, (m.get(f.sub_target_id) ?? 0) + 1);
    return [...m.entries()];
  }, [findings]);

  const byEng = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.engagement_id, (m.get(f.engagement_id) ?? 0) + 1);
    return [...m.entries()];
  }, [findings]);

  return (
    <div className="h-full overflow-auto p-5">
      <div className="mb-4">
        <h3 className="flex items-center gap-2 text-[16px] font-bold tracking-tight">
          <GradientText>Report — {target.name}</GradientText>
          <Sparkle />
        </h3>
        <p className="text-[12.5px] leading-relaxed text-ink-muted">
          Union of findings across this target's sub-targets (<span className="">{findings.length}</span> total).
        </p>
      </div>

      {/* Severity strip */}
      <div className="mb-5 flex flex-wrap gap-2">
        {SEV_ORDER.map((s) => (
          <GlassCard
            key={s}
            className={`flex items-center gap-2.5 px-3 py-2 ${(bySev[s] ?? 0) === 0 ? "opacity-50" : ""}`}
          >
            <span className={`rounded px-1.5 py-0.5 text-[9.5px] font-semibold ${SEV_PILL[s]}`}>{SEV_LABEL[s]}</span>
            <StatCounter className="text-[18px] font-bold leading-none text-ink-primary" target={bySev[s] ?? 0} />
          </GlassCard>
        ))}
      </div>

      {findings.length === 0 ? (
        <div className="text-[12.5px] leading-relaxed text-ink-muted">
          No findings yet. Run an armed pairing in this target's Workbench and promote it.
        </div>
      ) : (
        <div className="grid gap-5 md:grid-cols-2">
          {/* By sub-target */}
          <Section title="By sub-target">
            {bySub.map(([sid, n]) => (
              <Bar key={sid} label={subAddr(sid)} n={n} total={findings.length} mono />
            ))}
          </Section>
          {/* By engagement */}
          <Section title="By engagement">
            {byEng.map(([eid, n]) => (
              <Bar key={eid} label={engName(eid)} n={n} total={findings.length} />
            ))}
          </Section>
        </div>
      )}

      {/* Finding list */}
      {findings.length > 0 && (
        <div className="mt-6">
          <div className="mb-2.5"><span className="text-[11px] text-ink-dim">Findings</span></div>
          <div className="space-y-1.5">
            {findings.map((f) => (
              <GlassCard
                key={f.id}
                className="flex flex-wrap items-center gap-3 px-3 py-2"
              >
                <span className={`rounded px-1.5 py-0.5 text-[9.5px] font-semibold ${SEV_PILL[f.severity as FindingSeverity]}`}>
                  {SEV_LABEL[f.severity as FindingSeverity]}
                </span>
                <span className="text-[13px] font-medium text-ink-primary">{f.title}</span>
                <div className="flex-1" />
                <span className="text-ink-muted">{subAddr(f.sub_target_id)}</span>
                <span className="text-[11.5px] font-medium text-accent">{engName(f.engagement_id)}</span>
              </GlassCard>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <GlassCard className="p-3">
      <div className="mb-2.5"><span className="text-[11px] text-ink-dim">{title}</span></div>
      <div className="space-y-2">{children}</div>
    </GlassCard>
  );
}

function Bar({ label, n, total }: { label: string; n: number; total: number; mono?: boolean }) {
  const pct = total > 0 ? Math.round((n / total) * 100) : 0;
  return (
    <div>
      <div className="flex items-center justify-between text-[11.5px]">
        <span className="truncate text-ink-primary">{label}</span>
        <span className="text-ink-muted">{n}</span>
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-bg-hover">
        <div className="h-full rounded bg-accent" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
