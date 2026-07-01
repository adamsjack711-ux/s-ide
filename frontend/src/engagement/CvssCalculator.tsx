import { useState } from "react";
import {
  METRICS,
  DEFAULT_VECTOR,
  calculateScore,
  vectorToString,
  severityFromScore,
  type CvssVector,
  type Metric,
} from "../lib/cvss";

const BAND: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-ink-muted",
};

/**
 * Compact CVSS v3.1 base-score calculator (pure-local via lib/cvss). Reports
 * score + vector + severity band up to the caller on every change.
 */
export default function CvssCalculator({
  onChange,
}: {
  onChange: (score: number, vector: string, severity: string) => void;
}) {
  const [vec, setVec] = useState<CvssVector>({ ...DEFAULT_VECTOR });

  function set(m: Metric, value: string) {
    const next = { ...vec, [m]: value };
    setVec(next);
    const score = calculateScore(next);
    onChange(score, vectorToString(next), severityFromScore(score));
  }

  const score = calculateScore(vec);
  const sev = severityFromScore(score);

  return (
    <div className="rounded bg-bg-base/50 p-2 ring-1 ring-divider">
      <div className="mb-2 flex items-center justify-between text-xs">
        <span className="font-mono text-ink-muted">{vectorToString(vec)}</span>
        <span className={`font-semibold ${BAND[sev]}`}>{score.toFixed(1)} {sev}</span>
      </div>
      <div className="grid grid-cols-2 gap-1.5">
        {METRICS.map((m) => (
          <label key={m.id} className="flex items-center justify-between gap-1 text-[calc(11px_*_var(--text-scale))] text-ink-muted">
            {m.label}
            <select
              value={vec[m.id]}
              onChange={(e) => set(m.id, e.target.value)}
              className="rounded bg-bg-card px-1 py-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
            >
              {m.options.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </label>
        ))}
      </div>
    </div>
  );
}
