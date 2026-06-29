// Findings tab — evidence chains from pairings.
//
// Every finding here was born from a specific engagement × sub-target pairing
// and is tagged with { engagement_id, sub_target_id, target_id }. The list is
// filterable by engagement, by sub-target, and rolls up by Target (a Target's
// findings = the union across its sub-targets).
import { useCallback, useEffect, useMemo, useState } from "react";
import { GlassCard } from "performative-ui";
import { useBus } from "../shell/bus";
import { SEV_PILL, SEV_LABEL } from "../engagement/findings/style";
import type { Engagement, FindingSeverity } from "../lib/engagement";
import { listAllPairingFindings, type PairingFinding, type Target } from "../lib/spine";

export default function FindingsTab({
  targets,
  engagements,
  lockTargetId,
}: {
  targets: Target[];
  engagements: Engagement[];
  /** When set, findings are locked to one Target (the picker is hidden). */
  lockTargetId?: string;
}) {
  const [findings, setFindings] = useState<PairingFinding[]>([]);
  const [targetFilter, setTargetFilter] = useState(lockTargetId ?? "all");
  const [engFilter, setEngFilter] = useState("all");
  const [rollup, setRollup] = useState(false);

  const load = useCallback(async () => {
    try {
      setFindings(await listAllPairingFindings());
    } catch {
      /* surfaced elsewhere; keep the tab responsive */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);
  useBus("findingCreated", () => void load());

  const targetName = useMemo(() => {
    const m = new Map(targets.map((t) => [t.id, t.name]));
    return (id: string) => m.get(id) ?? id.slice(0, 8);
  }, [targets]);
  const engName = useMemo(() => {
    const m = new Map(engagements.map((e) => [e.id, e.name]));
    return (id: string) => m.get(id) ?? id.slice(0, 8);
  }, [engagements]);
  const subAddr = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of targets)
      for (const s of t.sub_targets ?? []) m.set(s.id, s.address);
    return (id: string) => m.get(id) ?? id.slice(0, 8);
  }, [targets]);

  const filtered = findings.filter(
    (f) =>
      (targetFilter === "all" || f.target_id === targetFilter) &&
      (engFilter === "all" || f.engagement_id === engFilter),
  );

  // Roll-up: group filtered findings under their parent Target.
  const grouped = useMemo(() => {
    const g = new Map<string, PairingFinding[]>();
    for (const f of filtered) {
      const arr = g.get(f.target_id) ?? [];
      arr.push(f);
      g.set(f.target_id, arr);
    }
    return [...g.entries()];
  }, [filtered]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Filter bar */}
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-divider px-4 py-2.5">
        {!lockTargetId && (
          <label className="flex items-center gap-1.5 text-[11px] text-ink-dim">
            Target
            <select
              value={targetFilter}
              onChange={(e) => setTargetFilter(e.target.value)}
              className="rounded-md border border-divider bg-bg-base px-2 py-1 text-[12px] text-ink-primary outline-none focus:border-accent/50"
            >
              <option value="all">all</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
          </label>
        )}
        <label className="flex items-center gap-1.5 text-[11px] text-ink-dim">
          Engagement
          <select
            value={engFilter}
            onChange={(e) => setEngFilter(e.target.value)}
            className="rounded-md border border-divider bg-bg-base px-2 py-1 text-[12px] text-ink-primary outline-none focus:border-accent/50"
          >
            <option value="all">all</option>
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>{e.name}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-[11px] text-ink-dim">
          <input
            type="checkbox"
            checked={rollup}
            onChange={(e) => setRollup(e.target.checked)}
            className="accent-accent"
          />
          Roll up by Target
        </label>
        <div className="flex-1" />
        <span className="text-[11.5px] text-ink-muted"><span className="">{filtered.length}</span> finding{filtered.length === 1 ? "" : "s"}</span>
      </div>

      {/* List */}
      <div className="min-h-0 flex-1 overflow-auto p-4">
        {filtered.length === 0 ? (
          <div className="text-[12.5px] leading-relaxed text-ink-muted">
            No findings yet. Promote a Workbench run against an armed pairing into a finding.
          </div>
        ) : rollup ? (
          <div className="space-y-5">
            {grouped.map(([tid, fs]) => (
              <div key={tid}>
                <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold tracking-tight text-ink-primary">
                  {targetName(tid)}
                  <span className="text-[11.5px] font-normal text-ink-muted">
                    <span className="">{fs.length}</span> finding{fs.length === 1 ? "" : "s"} across sub-targets
                  </span>
                </div>
                <div className="space-y-1.5">
                  {fs.map((f) => (
                    <Row key={f.id} f={f} engName={engName} subAddr={subAddr} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="space-y-1.5">
            {filtered.map((f) => (
              <Row key={f.id} f={f} engName={engName} subAddr={subAddr} showTarget targetName={targetName} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Row({
  f,
  engName,
  subAddr,
  showTarget,
  targetName,
}: {
  f: PairingFinding;
  engName: (id: string) => string;
  subAddr: (id: string) => string;
  showTarget?: boolean;
  targetName?: (id: string) => string;
}) {
  return (
    <GlassCard className="flex flex-wrap items-center gap-3 px-3 py-2.5" glowOnHover>
      <span className={`rounded px-1.5 py-0.5 text-[9.5px] font-semibold ${SEV_PILL[f.severity as FindingSeverity]}`}>
        {SEV_LABEL[f.severity as FindingSeverity]}
      </span>
      <span className="text-[13px] font-medium text-ink-primary">{f.title}</span>
      <div className="flex-1" />
      <div className="flex flex-wrap items-center gap-2 text-[11.5px] text-ink-muted">
        {showTarget && targetName && (
          <span className="rounded bg-bg-hover px-1.5 py-0.5 ring-1 ring-divider">
            {targetName(f.target_id)}
          </span>
        )}
        <span className="">{subAddr(f.sub_target_id)}</span>
        <span className="font-medium text-accent">{engName(f.engagement_id)}</span>
      </div>
    </GlassCard>
  );
}
