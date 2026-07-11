import { useCallback, useEffect, useRef, useState } from "react";
import { authFetch } from "../api";
import { useActiveEngagementId } from "../lib/engagement";
import { useBus } from "../shell/bus";

type Check = {
  id: string;
  label: string;
  status: "ok" | "warn" | "gap";
  detail: string;
  count: number;
  items: string[];
};
type Assessment = {
  checks: Check[];
  summary: { ok: number; warn: number; gap: number; total: number };
  score: number;
  ready: boolean;
};

const DOT: Record<Check["status"], string> = {
  ok: "text-success",
  warn: "text-amber",
  gap: "text-danger",
};
const GLYPH: Record<Check["status"], string> = { ok: "●", warn: "▲", gap: "✕" };

/**
 * Self-Assess — "is this engagement ready to report?". A readiness roll-up over
 * the coverage matrix plus findings quality (evidence / CVSS / triage),
 * external-target attestation, and report export. Read-only; sits above the
 * coverage panel in the findings view.
 */
export default function SelfAssessPanel() {
  const eid = useActiveEngagementId();
  const [rep, setRep] = useState<Assessment | null>(null);
  const [open, setOpen] = useState(false);
  // Guard against a slow response for a previous engagement landing last and
  // overwriting the current one (fast engagement switching).
  const reqIdRef = useRef(0);

  const refresh = useCallback(() => {
    if (!eid) {
      setRep(null);
      return;
    }
    const myId = ++reqIdRef.current;
    authFetch(`/self-assess/${eid}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (myId === reqIdRef.current) setRep(d);
      })
      .catch(() => {
        if (myId === reqIdRef.current) setRep(null);
      });
  }, [eid]);

  useEffect(refresh, [refresh]);
  useBus("findingsChanged", refresh);

  if (!eid || !rep) return null;

  const scoreColor = rep.ready ? "text-success" : rep.summary.gap > 0 ? "text-danger" : "text-amber";

  return (
    <div className="border-b border-divider px-3 py-2">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between text-xs"
        title="Readiness self-assessment for this engagement"
      >
        <span className="uppercase tracking-wide text-ink-dim">Self-Assess</span>
        <span className="flex items-center gap-2">
          <span className="text-ink-dim">
            {rep.summary.ok}/{rep.summary.total}
          </span>
          <span className={`font-medium ${scoreColor}`}>{rep.score}%</span>
          <span className="text-ink-dim">{open ? "▾" : "▸"}</span>
        </span>
      </button>

      {open && (
        <div className="mt-1.5 space-y-1">
          {rep.checks.map((c) => (
            <div key={c.id} className="text-xs" title={c.items.join(" · ")}>
              <div className="flex items-center gap-2">
                <span className={DOT[c.status]}>{GLYPH[c.status]}</span>
                <span className={c.status === "ok" ? "text-ink-primary" : "text-ink-muted"}>{c.label}</span>
                {c.count > 0 && <span className="ml-auto text-ink-dim">{c.count}</span>}
              </div>
              {c.status !== "ok" && (
                <div className="ml-5 truncate text-[11px] text-ink-dim">{c.detail}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
