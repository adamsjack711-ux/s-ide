import { useEffect, useState } from "react";
import {
  patchTrackedFinding,
  type Finding,
  type FindingStatus,
} from "../../lib/engagement";
import { api } from "../../api";
import type { FindingMethod } from "../../lib/methodAnalysis";
import { resolveFindingLabId, confirmStepWhy } from "../../lib/retest";
import { RETEST_COMING_SOON, COMING_SOON_TOOLTIP } from "../../lib/comingSoon";
import MethodReconstruction from "../../copilot/MethodReconstruction";
import { SEV_PILL, SEV_LABEL, statusLabel } from "./style";

const STATUSES: FindingStatus[] = ["open", "confirmed", "false_positive", "remediated"];

const TABS = ["Description", "Root Cause", "Data Flow", "Vulnerable Code", "Remediation", "History"] as const;
type Tab = typeof TABS[number];

/** A labelled placeholder for design sections we don't have data for yet. */
function Placeholder({ what }: { what: string }) {
  return (
    <div className="rounded-lg border border-dashed border-divider bg-bg-base/40 px-4 py-6 text-center text-xs text-ink-dim">
      No {what} data yet.
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-2.5 font-mono text-[calc(11px_*_var(--text-scale))] font-semibold uppercase tracking-[0.05em] text-ink-dim">
      {children}
    </div>
  );
}

/**
 * Investigation detail pane for the selected finding. Outline tabs mirror the
 * design (Description / Data Flow / Vulnerable Code / Remediation / History);
 * Description renders finding.description, the rest are wired placeholders for
 * where future data (evidence/flow/remediation/audit) will land.
 */
export default function FindingDetail({
  finding,
  onChanged,
  onRetest,
}: {
  finding: Finding;
  onChanged: () => void;
  /** Retest the selected finding (resolves its lab + replays the steps). */
  onRetest?: () => void;
}) {
  const [tab, setTab] = useState<Tab>("Description");
  const f = finding;

  // The method (root cause / remediation / steps) backing this finding.
  const [method, setMethod] = useState<FindingMethod | null>(null);
  // Whether this finding resolves to a lab (gates the Retest button).
  const [labId, setLabId] = useState<string | null | undefined>(undefined); // undefined = resolving
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    setMethod(null);
    api<FindingMethod>(`/method/findings/${encodeURIComponent(f.id)}`)
      .then((m) => alive && setMethod(m))
      .catch(() => alive && setMethod(null));
    setLabId(undefined);
    resolveFindingLabId(f)
      .then((id) => alive && setLabId(id))
      .catch(() => alive && setLabId(null));
    return () => {
      alive = false;
    };
  }, [f.id, f.target, f.engagement_id]);

  async function setStatus(status: FindingStatus) {
    setBusy(true);
    try {
      await patchTrackedFinding(f.id, { status });
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  function reloadMethod() {
    api<FindingMethod>(`/method/findings/${encodeURIComponent(f.id)}`)
      .then(setMethod)
      .catch(() => {});
  }

  // Persist an operator-confirmed "why" for a step, then refresh the method so
  // the new rationale shows on the reconstructed flow.
  async function onConfirmWhy(stepId: string, why: string) {
    await confirmStepWhy(f.id, stepId, why);
    reloadMethod();
  }

  const rootCause = method?.root_cause ?? null;
  const remediation = method?.remediation ?? null;
  const steps = method?.steps ?? [];

  // Retest is scaffolded but its backend (replay the recorded Step chain) is
  // not wired yet — gate it OFF so the button can't invoke a no-op.
  const retestable = !RETEST_COMING_SOON && !!labId;
  const retestTitle = RETEST_COMING_SOON
    ? COMING_SOON_TOOLTIP
    : labId === undefined
      ? "Resolving lab…"
      : labId
        ? "Replay the recorded steps to confirm the fix"
        : "No associated lab — retest is only available for lab-backed findings";

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto bg-bg-base">
      {/* header: pill + title + id line */}
      <div className="border-b border-divider px-6 pb-5 pt-5">
        <div className="flex items-start gap-3">
          <span
            className={`mt-0.5 inline-flex items-center rounded-md px-2.5 py-1 font-mono text-[calc(10.5px_*_var(--text-scale))] font-semibold tracking-wide ${SEV_PILL[f.severity]}`}
          >
            {SEV_LABEL[f.severity]}
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="text-[calc(19px_*_var(--text-scale))] font-bold leading-snug text-ink-primary">{f.title}</h2>
            <div className="mt-1.5 font-mono text-xs text-ink-dim">
              {f.id}
              {f.tool ? ` · ${f.tool}` : ""}
            </div>
          </div>
          <button
            onClick={() => onRetest?.()}
            disabled={!retestable || !onRetest}
            title={retestTitle}
            className="mt-0.5 shrink-0 rounded-md px-3 py-1.5 text-xs font-medium text-accent ring-1 ring-accent/40 transition-colors hover:bg-accent/10 disabled:cursor-not-allowed disabled:text-ink-dim disabled:ring-divider disabled:hover:bg-transparent"
          >
            {labId === undefined ? "Retest…" : "Retest"}
          </button>
        </div>

        {/* meta cards: CVSS / Type / Status / Owner(tool) */}
        <div className="mt-4 grid grid-cols-4 gap-2.5">
          <MetaCard label="CVSS" value={f.cvss != null ? f.cvss.toFixed(1) : "—"} accent />
          <MetaCard label="Type" value={f.tool || "—"} />
          <div className="rounded-[10px] border border-divider bg-bg-card px-3.5 py-3">
            <div className="mb-1.5 font-mono text-[calc(10.5px_*_var(--text-scale))] uppercase tracking-[0.04em] text-ink-dim">
              Status
            </div>
            <select
              value={f.status}
              disabled={busy}
              onChange={(e) => setStatus(e.target.value as FindingStatus)}
              className="w-full bg-transparent text-sm font-semibold text-ink-primary outline-none disabled:opacity-60"
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>{statusLabel(s)}</option>
              ))}
            </select>
          </div>
          <MetaCard label="Location" value={f.target || "—"} mono />
        </div>
      </div>

      {/* outline tabs */}
      <div className="flex items-center gap-1 border-b border-divider px-6">
        {TABS.map((t) => {
          const active = t === tab;
          return (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`-mb-px border-b-2 px-3 py-2.5 text-xs transition-colors ${
                active
                  ? "border-accent font-medium text-ink-primary"
                  : "border-transparent text-ink-dim hover:text-ink-muted"
              }`}
            >
              {t}
            </button>
          );
        })}
      </div>

      {/* tab body */}
      <div className="min-h-0 flex-1 px-6 py-5">
        {tab === "Description" && (
          <div>
            <SectionLabel>Description</SectionLabel>
            {f.description ? (
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-primary">
                {f.description}
              </p>
            ) : (
              <Placeholder what="description" />
            )}
            {f.cvss_vector && (
              <div className="mt-5">
                <SectionLabel>CVSS Vector</SectionLabel>
                <code className="block break-all rounded-lg border border-divider bg-bg-card px-3 py-2 font-mono text-xs text-ink-muted">
                  {f.cvss_vector}
                </code>
              </div>
            )}
          </div>
        )}

        {tab === "Root Cause" && (
          <div>
            <SectionLabel>Root Cause</SectionLabel>
            {rootCause?.explanation ? (
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-primary">
                {rootCause.explanation}
              </p>
            ) : (
              <Placeholder what="root-cause" />
            )}
            {rootCause?.anchor && (
              <div className="mt-3 inline-flex items-center rounded-md border border-divider bg-bg-card px-3 py-1.5 font-mono text-xs text-ink-muted">
                {rootCause.anchor}
              </div>
            )}

            {/* Reconstructed method — reachable here without opening the copilot
                rail. It does its own fetch + renders FACT/INFERENCE per step. */}
            <div className="mt-5 overflow-hidden rounded-xl border border-divider">
              <MethodReconstruction findingId={f.id} onConfirmWhy={onConfirmWhy} />
            </div>
          </div>
        )}

        {tab === "Data Flow" && (
          <div>
            <SectionLabel>Data Flow — source to sink</SectionLabel>
            <Placeholder what="data-flow" />
          </div>
        )}

        {tab === "Vulnerable Code" && (
          <div>
            <SectionLabel>Vulnerable Code</SectionLabel>
            {f.target ? (
              <div className="mb-3 inline-flex items-center rounded-md border border-divider bg-bg-card px-3 py-1.5 font-mono text-xs text-ink-muted">
                {f.target}
              </div>
            ) : null}
            {rootCause?.anchor ? (
              <code className="block break-all rounded-lg border border-divider bg-bg-card px-3 py-2 font-mono text-xs text-ink-muted">
                {rootCause.anchor}
              </code>
            ) : (
              <Placeholder what="code-snippet" />
            )}
          </div>
        )}

        {tab === "Remediation" && (
          <div className="rounded-xl border border-accent/30 bg-accent/[0.06] p-4">
            <div className="mb-3 flex items-center gap-2">
              <span className="text-sm font-semibold text-ink-primary">
                Recommended Remediation
              </span>
              <span className="ml-auto font-mono text-[calc(11px_*_var(--text-scale))] text-accent">S-IDE Copilot</span>
            </div>
            {remediation?.change || remediation?.why ? (
              <div className="space-y-3">
                {remediation.change && (
                  <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-primary">
                    {remediation.change}
                  </p>
                )}
                {remediation.why && (
                  <p className="whitespace-pre-wrap text-xs leading-relaxed text-ink-muted">
                    {remediation.why}
                  </p>
                )}
              </div>
            ) : (
              <Placeholder what="remediation" />
            )}
          </div>
        )}

        {tab === "History" && (
          <div>
            <SectionLabel>History — recorded steps</SectionLabel>
            {steps.length === 0 ? (
              <Placeholder what="audit-trail" />
            ) : (
              <ol className="space-y-2">
                {steps.map((s, i) => (
                  <li
                    key={s.id}
                    className="flex items-start gap-3 rounded-lg border border-divider bg-bg-card px-3 py-2"
                  >
                    <span className="mt-px shrink-0 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-dim">
                      {(s.ordinal ?? i) + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-xs text-ink-primary">
                        {String(s.action?.tool_id ?? "unknown")}
                      </div>
                      {s.evidence?.timestamp != null && (
                        <div className="mt-0.5 font-mono text-[calc(10.5px_*_var(--text-scale))] text-ink-dim">
                          {String(s.evidence.timestamp)}
                        </div>
                      )}
                    </div>
                    <span
                      className={`shrink-0 rounded px-1.5 py-px text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide ${
                        s.anchored ? "text-phos ring-1 ring-phos/30" : "text-amber ring-1 ring-amber/30"
                      }`}
                    >
                      {s.anchored ? "anchored" : "unanchored"}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function MetaCard({
  label,
  value,
  accent,
  mono,
}: {
  label: string;
  value: string;
  accent?: boolean;
  mono?: boolean;
}) {
  return (
    <div className="rounded-[10px] border border-divider bg-bg-card px-3.5 py-3">
      <div className="mb-1.5 font-mono text-[calc(10.5px_*_var(--text-scale))] uppercase tracking-[0.04em] text-ink-dim">
        {label}
      </div>
      <div
        className={`truncate text-sm font-semibold ${accent ? "text-accent" : "text-ink-primary"} ${
          mono ? "font-mono" : ""
        }`}
        title={value}
      >
        {value}
      </div>
    </div>
  );
}
