// Engagement Reporting — a report scoped to one Engagement.
//
// An engagement's report is the roll-up across every pairing it armed: findings
// by severity, by the Target they landed on, and by the sub-target address. It's
// the engagement-first mirror of TargetReporting — the IA now nests reporting
// inside each Engagement (the engagement is the authority that produced them).
import { useCallback, useEffect, useMemo, useState } from "react";
import { GlassCard, GradientText, Sparkle, StatCounter } from "performative-ui";
import { useBus } from "../shell/bus";
import { SEV_PILL, SEV_LABEL } from "../engagement/findings/style";
import type { Engagement, FindingSeverity } from "../lib/engagement";
import { listAllPairingFindings, type PairingFinding, type Target } from "../lib/spine";

const SEV_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

export default function EngagementReporting({
  engagement,
  targets,
}: {
  engagement: Engagement;
  targets: Target[];
}) {
  const [all, setAll] = useState<PairingFinding[]>([]);

  const load = useCallback(async () => {
    try {
      setAll(await listAllPairingFindings());
    } catch {
      /* keep the panel responsive */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);
  useBus("findingCreated", () => void load());

  // This engagement's findings only.
  const findings = useMemo(
    () => all.filter((f) => f.engagement_id === engagement.id),
    [all, engagement.id],
  );

  const targetName = useMemo(() => {
    const m = new Map(targets.map((t) => [t.id, t.name]));
    return (id: string) => m.get(id) ?? id.slice(0, 8);
  }, [targets]);
  const subAddr = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of targets)
      for (const s of t.sub_targets ?? []) m.set(s.id, s.address);
    return (id: string) => m.get(id) ?? id.slice(0, 8);
  }, [targets]);

  const bySev = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  const byTarget = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.target_id, (m.get(f.target_id) ?? 0) + 1);
    return [...m.entries()];
  }, [findings]);

  const bySub = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.sub_target_id, (m.get(f.sub_target_id) ?? 0) + 1);
    return [...m.entries()];
  }, [findings]);

  return (
    <div className="h-full overflow-auto p-5">
      <div className="mb-4">
        <h3 className="flex items-center gap-2 text-[calc(16px_*_var(--text-scale))] font-bold tracking-tight">
          <GradientText>Report — {engagement.name}</GradientText>
          <Sparkle />
        </h3>
        <p className="text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-muted">
          Union of findings across every pairing this engagement armed (<span className="">{findings.length}</span> total).
        </p>
      </div>

      {/* Severity strip */}
      <div className="mb-5 flex flex-wrap gap-2">
        {SEV_ORDER.map((s) => (
          <GlassCard
            key={s}
            className={`flex items-center gap-2.5 px-3 py-2 ${(bySev[s] ?? 0) === 0 ? "opacity-50" : ""}`}
          >
            <span className={`rounded px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold ${SEV_PILL[s]}`}>{SEV_LABEL[s]}</span>
            <StatCounter className="text-[calc(18px_*_var(--text-scale))] font-bold leading-none text-ink-primary" target={bySev[s] ?? 0} />
          </GlassCard>
        ))}
      </div>

      {findings.length === 0 ? (
        <div className="text-[calc(12.5px_*_var(--text-scale))] leading-relaxed text-ink-muted">
          No findings yet. Run an armed pairing in this engagement's Workbench and promote it.
        </div>
      ) : (
        <div className="grid gap-5 md:grid-cols-2">
          {/* By target */}
          <Section title="By target">
            {byTarget.map(([tid, n]) => (
              <Bar key={tid} label={targetName(tid)} n={n} total={findings.length} />
            ))}
          </Section>
          {/* By sub-target */}
          <Section title="By sub-target">
            {bySub.map(([sid, n]) => (
              <Bar key={sid} label={subAddr(sid)} n={n} total={findings.length} />
            ))}
          </Section>
        </div>
      )}

      {/* Finding list */}
      {findings.length > 0 && (
        <div className="mt-6">
          <div className="mb-2.5"><span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">Findings</span></div>
          <div className="space-y-1.5">
            {findings.map((f) => (
              <GlassCard
                key={f.id}
                className="flex flex-wrap items-center gap-3 px-3 py-2"
              >
                <span className={`rounded px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold ${SEV_PILL[f.severity as FindingSeverity]}`}>
                  {SEV_LABEL[f.severity as FindingSeverity]}
                </span>
                <span className="text-[calc(13px_*_var(--text-scale))] font-medium text-ink-primary">{f.title}</span>
                <div className="flex-1" />
                <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[calc(11.5px_*_var(--text-scale))] text-ink-muted ring-1 ring-divider">{targetName(f.target_id)}</span>
                <span className="text-ink-muted">{subAddr(f.sub_target_id)}</span>
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
      <div className="mb-2.5"><span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">{title}</span></div>
      <div className="space-y-2">{children}</div>
    </GlassCard>
  );
}

function Bar({ label, n, total }: { label: string; n: number; total: number }) {
  const pct = total > 0 ? Math.round((n / total) * 100) : 0;
  return (
    <div>
      <div className="flex items-center justify-between text-[calc(11.5px_*_var(--text-scale))]">
        <span className="truncate text-ink-primary">{label}</span>
        <span className="text-ink-muted">{n}</span>
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-bg-hover">
        <div className="h-full rounded bg-accent" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
