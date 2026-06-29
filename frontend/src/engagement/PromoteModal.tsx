import { useEffect, useState } from "react";
import { emit, on } from "../shell/bus";
import { notify } from "../shell/toast";
import { api } from "../api";
import {
  getActiveEngagementId,
  promoteToFinding,
  useActiveEngagementId,
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
  // Re-render when the active engagement changes so the save affordance can
  // disable/relabel up front instead of only erroring after a full fill.
  const activeEid = useActiveEngagementId();

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

  function close() {
    setDraft(null);
  }

  /**
   * Seed at least one method Step from the promoted result so the finding's
   * investigation isn't born empty (Friction #5 — root cause was blank because
   * MethodReconstruction had no steps to render). Best-effort: a step failing
   * to seed must never block the promote itself.
   */
  async function seedMethodStep(findingId: string, d: Draft): Promise<void> {
    try {
      await api<unknown>(`/method/findings/${encodeURIComponent(findingId)}/steps`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: { tool_id: d.tool || "unknown", params: d.target ? { target: d.target } : {} },
          evidence: { raw_output: d.evidence || d.description || "" },
          interpretation: d.description || null,
          links_from: null,
          anchored: false,
        }),
      });
    } catch {
      /* best-effort — the finding is already saved */
    }
  }

  async function save() {
    if (busy) return;
    const eid = getActiveEngagementId();
    if (!eid) {
      setErr("No active engagement — select or create one first.");
      return;
    }
    const d = draft!;
    setBusy(true);
    try {
      const finding = await promoteToFinding({
        engagement_id: eid,
        title: d.title,
        severity: d.severity,
        description: d.description,
        tool: d.tool,
        target: d.target,
        evidence: d.evidence,
        cvss: cvss?.score ?? null,
        cvss_vector: cvss?.vector ?? null,
      });
      await seedMethodStep(finding.id, d);
      emit("findingsChanged", {});
      setDraft(null);
      notify({
        kind: "success",
        message: "Finding logged",
        action: {
          label: "View finding →",
          onClick: () => {
            emit("openView", { view: "findings" });
            emit("focusFinding", { findingId: finding.id });
          },
        },
      });
    } catch (e: any) {
      const msg = e?.message || "failed to save finding";
      setErr(msg);
      notify({ kind: "error", message: msg });
    } finally {
      setBusy(false);
    }
  }

  const canSave = !!activeEid;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={close}
    >
      <div
        className="w-[32rem] rounded-lg bg-bg-card p-4 shadow-2xl ring-1 ring-divider"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            close();
          } else if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
            e.preventDefault();
            if (canSave) void save();
          }
        }}
      >
        <div className="mb-3 text-sm font-semibold text-ink-primary">Promote to finding</div>

        <label className="mb-2 block text-xs text-ink-muted">
          Title
          <input
            autoFocus
            value={draft.title}
            onChange={(e) => setDraft({ ...draft, title: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                if (canSave) void save();
              }
            }}
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

        {!canSave && (
          <div className="mb-2 rounded border border-amber/30 bg-amber/10 px-2 py-1.5 text-xs text-amber">
            No active engagement — select or create one before logging a finding.
          </div>
        )}
        {err && <div className="mb-2 text-xs text-danger">{err}</div>}

        <div className="flex items-center justify-between gap-2">
          <span className="text-[10.5px] text-ink-dim">
            <kbd className="font-mono">↵</kbd> save · <kbd className="font-mono">esc</kbd> cancel
          </span>
          <div className="flex gap-2">
            <button onClick={close} className="rounded px-3 py-1.5 text-sm text-ink-muted hover:text-ink-primary">
              Cancel
            </button>
            <button
              onClick={save}
              disabled={busy || !canSave}
              title={canSave ? undefined : "Select or create an engagement first"}
              className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:bg-accentBright disabled:opacity-50"
            >
              {busy ? "Saving…" : !canSave ? "No engagement" : "Save finding"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
