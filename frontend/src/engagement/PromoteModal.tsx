import { useEffect, useState } from "react";
import { emit, on } from "../shell/bus";
import {
  getActiveEngagementId,
  promoteToFinding,
  type FindingSeverity,
} from "../lib/engagement";
import CvssCalculator from "./CvssCalculator";

const SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

type Draft = {
  title: string;
  severity: FindingSeverity;
  description: string;
  tool: string;
  target: string;
  evidence: string;
};

/**
 * Promote-to-finding flow. Listens for the `promote` bus event (fired from a
 * tool panel's result), pre-fills, lets the user score CVSS, and writes a
 * tracked finding against the active engagement.
 */
export default function PromoteModal() {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [cvss, setCvss] = useState<{ score: number; vector: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(
    () =>
      on("promote", (p) => {
        setErr("");
        setCvss(null);
        setDraft({ title: p.title, severity: "medium", description: p.description, tool: p.tool, target: p.target, evidence: p.evidence });
      }),
    [],
  );

  if (!draft) return null;

  async function save() {
    const eid = getActiveEngagementId();
    if (!eid) {
      setErr("No active engagement — select or create one first.");
      return;
    }
    setBusy(true);
    try {
      await promoteToFinding({
        engagement_id: eid,
        title: draft!.title,
        severity: draft!.severity,
        description: draft!.description,
        tool: draft!.tool,
        target: draft!.target,
        evidence: draft!.evidence,
        cvss: cvss?.score ?? null,
        cvss_vector: cvss?.vector ?? null,
      });
      emit("findingsChanged", {});
      setDraft(null);
    } catch (e: any) {
      setErr(e?.message || "failed to save finding");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={() => setDraft(null)}>
      <div className="w-[32rem] rounded-lg bg-bg-card p-4 shadow-2xl ring-1 ring-divider" onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 text-sm font-semibold text-ink-primary">Promote to finding</div>

        <label className="mb-2 block text-xs text-ink-muted">
          Title
          <input
            value={draft.title}
            onChange={(e) => setDraft({ ...draft, title: e.target.value })}
            className="mt-1 w-full rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
          />
        </label>

        <div className="mb-2 flex gap-3">
          <label className="text-xs text-ink-muted">
            Severity
            <select
              value={draft.severity}
              onChange={(e) => setDraft({ ...draft, severity: e.target.value as FindingSeverity })}
              className="mt-1 block rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>
          <div className="flex-1 text-xs text-ink-muted">
            Tool / target
            <div className="mt-1 truncate rounded bg-bg-base px-2 py-1 font-mono text-xs text-ink-dim ring-1 ring-divider">
              {draft.tool} · {draft.target || "—"}
            </div>
          </div>
        </div>

        <label className="mb-2 block text-xs text-ink-muted">
          Description
          <textarea
            value={draft.description}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })}
            rows={3}
            className="mt-1 w-full rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
          />
        </label>

        <div className="mb-3 text-xs text-ink-muted">
          CVSS (optional)
          <div className="mt-1">
            <CvssCalculator onChange={(score, vector) => setCvss({ score, vector })} />
          </div>
        </div>

        {err && <div className="mb-2 text-xs text-danger">{err}</div>}

        <div className="flex justify-end gap-2">
          <button onClick={() => setDraft(null)} className="rounded px-3 py-1.5 text-sm text-ink-muted hover:text-ink-primary">
            Cancel
          </button>
          <button onClick={save} disabled={busy} className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:bg-accentBright disabled:opacity-50">
            {busy ? "Saving…" : "Save finding"}
          </button>
        </div>
      </div>
    </div>
  );
}
