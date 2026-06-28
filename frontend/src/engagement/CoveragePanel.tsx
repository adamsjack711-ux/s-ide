import { useCallback, useEffect, useState } from "react";
import { authFetch } from "../api";
import { useActiveEngagementId } from "../lib/engagement";
import { useBus } from "../shell/bus";

type Area = {
  key: string;
  label: string;
  description: string;
  covered: boolean;
  runs: number;
  last_ts: string | null;
};
type Coverage = { areas: Area[]; covered_count: number; total: number };

/** The "what's been checked" coverage matrix for the active engagement. */
export default function CoveragePanel() {
  const eid = useActiveEngagementId();
  const [cov, setCov] = useState<Coverage | null>(null);

  const refresh = useCallback(() => {
    if (!eid) {
      setCov(null);
      return;
    }
    authFetch(`/engagements/${eid}/coverage`)
      .then((r) => (r.ok ? r.json() : null))
      .then(setCov)
      .catch(() => setCov(null));
  }, [eid]);

  useEffect(refresh, [refresh]);
  useBus("findingsChanged", refresh);

  if (!eid || !cov) return null;

  return (
    <div className="border-b border-divider px-3 py-2">
      <div className="mb-1.5 flex items-center justify-between text-xs">
        <span className="uppercase tracking-wide text-ink-dim">Coverage</span>
        <span className="text-ink-muted">{cov.covered_count}/{cov.total}</span>
      </div>
      <div className="space-y-1">
        {cov.areas.map((a) => (
          <div key={a.key} className="flex items-center gap-2 text-xs" title={a.description}>
            <span className={a.covered ? "text-success" : "text-ink-dim"}>{a.covered ? "●" : "○"}</span>
            <span className={a.covered ? "text-ink-primary" : "text-ink-muted"}>{a.label}</span>
            {a.runs > 0 && <span className="ml-auto text-ink-dim">{a.runs}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}
