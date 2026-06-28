import { useState } from "react";
import {
  patchTrackedFinding,
  type Finding,
  type FindingStatus,
} from "../../lib/engagement";
import { SEV_PILL, SEV_LABEL, statusLabel } from "./style";

const STATUSES: FindingStatus[] = ["open", "confirmed", "false_positive", "remediated"];

const TABS = ["Description", "Data Flow", "Vulnerable Code", "Remediation", "History"] as const;
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
    <div className="mb-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.05em] text-ink-dim">
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
}: {
  finding: Finding;
  onChanged: () => void;
}) {
  const [tab, setTab] = useState<Tab>("Description");
  const f = finding;

  async function setStatus(status: FindingStatus) {
    await patchTrackedFinding(f.id, { status });
    onChanged();
  }

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto bg-bg-base">
      {/* header: pill + title + id line */}
      <div className="border-b border-divider px-6 pb-5 pt-5">
        <div className="flex items-start gap-3">
          <span
            className={`mt-0.5 inline-flex items-center rounded-md px-2.5 py-1 font-mono text-[10.5px] font-semibold tracking-wide ${SEV_PILL[f.severity]}`}
          >
            {SEV_LABEL[f.severity]}
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="text-[19px] font-bold leading-snug text-ink-primary">{f.title}</h2>
            <div className="mt-1.5 font-mono text-xs text-ink-dim">
              {f.id}
              {f.tool ? ` · ${f.tool}` : ""}
            </div>
          </div>
        </div>

        {/* meta cards: CVSS / Type / Status / Owner(tool) */}
        <div className="mt-4 grid grid-cols-4 gap-2.5">
          <MetaCard label="CVSS" value={f.cvss != null ? f.cvss.toFixed(1) : "—"} accent />
          <MetaCard label="Type" value={f.tool || "—"} />
          <div className="rounded-[10px] border border-divider bg-bg-card px-3.5 py-3">
            <div className="mb-1.5 font-mono text-[10.5px] uppercase tracking-[0.04em] text-ink-dim">
              Status
            </div>
            <select
              value={f.status}
              onChange={(e) => setStatus(e.target.value as FindingStatus)}
              className="w-full bg-transparent text-sm font-semibold text-ink-primary outline-none"
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
            <Placeholder what="code-snippet" />
          </div>
        )}

        {tab === "Remediation" && (
          <div className="rounded-xl border border-accent/30 bg-accent/[0.06] p-4">
            <div className="mb-3 flex items-center gap-2">
              <span className="text-sm font-semibold text-ink-primary">
                Recommended Remediation
              </span>
              <span className="ml-auto font-mono text-[11px] text-accent">S-IDE Copilot</span>
            </div>
            <Placeholder what="remediation" />
          </div>
        )}

        {tab === "History" && (
          <div>
            <SectionLabel>History</SectionLabel>
            <Placeholder what="audit-trail" />
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
      <div className="mb-1.5 font-mono text-[10.5px] uppercase tracking-[0.04em] text-ink-dim">
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
