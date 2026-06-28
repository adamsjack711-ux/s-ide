import { useMemo } from "react";
import {
  type Finding,
  type FindingSeverity,
} from "../lib/engagement";
import {
  SEV_PILL,
  SEV_LABEL,
  SEV_ORDER,
  SEV_TEXT,
  STATUS_TEXT,
  statusLabel,
  sourceSwatch,
} from "./findings/style";

type SevFilter = FindingSeverity | "all";

/**
 * Faceted findings list (design "Triage Queue"): severity filter chips with
 * counts, source + status facets, and finding rows with a mono severity PILL,
 * title, monospace location, source swatch, and CVSS. Selection is lifted to
 * the parent so the detail pane stays in sync.
 */
export default function FindingsPanel({
  findings,
  selectedId,
  onSelect,
  sevFilter,
  onSevFilter,
}: {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (f: Finding) => void;
  sevFilter: SevFilter;
  onSevFilter: (s: SevFilter) => void;
}) {
  const counts = useMemo(() => {
    const c: Record<FindingSeverity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  // Source facets keyed by tool name (design srcColors are per-source).
  const sourceFacets = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) {
      const k = f.tool || "(none)";
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [findings]);

  const statusFacets = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.status, (m.get(f.status) ?? 0) + 1);
    return [...m.entries()];
  }, [findings]);

  const shown = sevFilter === "all"
    ? findings
    : findings.filter((f) => f.severity === sevFilter);

  const chips: { key: SevFilter; label: string; n: number }[] = [
    { key: "all", label: "All", n: findings.length },
    ...SEV_ORDER.filter((s) => s !== "info" || counts.info > 0).map((s) => ({
      key: s as SevFilter, label: SEV_LABEL[s], n: counts[s],
    })),
  ];

  return (
    <div className="flex h-full min-h-0 overflow-hidden">
      {/* facets rail */}
      <aside className="hidden w-52 shrink-0 flex-col gap-5 overflow-auto border-r border-divider bg-bg-sidebar px-3 py-4 md:flex">
        <FacetGroup title="Source">
          {sourceFacets.length === 0 ? (
            <div className="px-1 text-xs text-ink-dim">—</div>
          ) : (
            sourceFacets.map(([tool, n]) => (
              <div key={tool} className="flex items-center gap-2 px-1 py-0.5 text-xs text-ink-muted">
                <span className={`h-[7px] w-[7px] shrink-0 rounded-[2px] ${sourceSwatch(tool)}`} />
                <span className="truncate">{tool}</span>
                <span className="ml-auto font-mono text-ink-dim">{n}</span>
              </div>
            ))
          )}
        </FacetGroup>

        <FacetGroup title="Status">
          {statusFacets.length === 0 ? (
            <div className="px-1 text-xs text-ink-dim">—</div>
          ) : (
            statusFacets.map(([st, n]) => (
              <div key={st} className="flex items-center gap-2 px-1 py-0.5 text-xs">
                <span className={STATUS_TEXT[st as keyof typeof STATUS_TEXT] ?? "text-ink-muted"}>
                  {statusLabel(st as Finding["status"])}
                </span>
                <span className="ml-auto font-mono text-ink-dim">{n}</span>
              </div>
            ))
          )}
        </FacetGroup>
      </aside>

      {/* list */}
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        {/* header: title + severity chips */}
        <div className="border-b border-divider px-4 pb-3 pt-3.5">
          <div className="flex items-end justify-between gap-3">
            <div>
              <div className="text-[15px] font-bold text-ink-primary">Triage Queue</div>
              <div className="mt-0.5 text-xs text-ink-dim">
                {shown.length} of {findings.length} findings · sorted by severity
              </div>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {chips.map((c) => {
              const active = sevFilter === c.key;
              return (
                <button
                  key={c.key}
                  onClick={() => onSevFilter(c.key)}
                  className={`inline-flex items-center rounded-lg border px-3 py-1 text-xs transition-colors ${
                    active
                      ? "border-accent bg-accent text-bg-base"
                      : "border-divider bg-bg-card text-ink-muted hover:border-borderBright"
                  }`}
                >
                  {c.label}
                  <span className="ml-1.5 font-mono opacity-70">{c.n}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* rows */}
        <div className="min-h-0 flex-1 overflow-auto">
          {shown.length === 0 ? (
            <div className="p-4 text-sm text-ink-dim">
              No findings yet — promote a tool result.
            </div>
          ) : (
            shown.map((f) => {
              const active = f.id === selectedId;
              return (
                <button
                  key={f.id}
                  onClick={() => onSelect(f)}
                  className={`flex w-full items-center gap-3 border-b border-divider px-4 py-3 text-left transition-colors ${
                    active ? "bg-bg-nav-active" : "hover:bg-bg-hover"
                  }`}
                >
                  <span
                    className={`inline-flex w-[72px] shrink-0 justify-center rounded-md px-2 py-1 font-mono text-[10.5px] font-semibold tracking-wide ${SEV_PILL[f.severity]}`}
                  >
                    {SEV_LABEL[f.severity]}
                  </span>
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="truncate text-[13px] font-medium text-ink-primary">
                      {f.title}
                    </span>
                    <span className="flex items-center gap-2 truncate font-mono text-[11px] text-ink-dim">
                      <span className={`inline-flex items-center gap-1.5 ${SEV_TEXT.info}`}>
                        <span className={`h-[6px] w-[6px] rounded-[2px] ${sourceSwatch(f.tool)}`} />
                        {f.tool || "—"}
                      </span>
                      <span className="truncate">{f.target}</span>
                    </span>
                  </div>
                  <span
                    className={`shrink-0 text-[11px] ${STATUS_TEXT[f.status] ?? "text-ink-muted"}`}
                  >
                    {statusLabel(f.status)}
                  </span>
                  {f.cvss != null && (
                    <span className="w-9 shrink-0 text-right font-mono text-xs text-ink-muted">
                      {f.cvss.toFixed(1)}
                    </span>
                  )}
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

function FacetGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-2 px-1 font-mono text-[10.5px] font-semibold uppercase tracking-[0.05em] text-ink-dim">
        {title}
      </div>
      <div className="flex flex-col">{children}</div>
    </div>
  );
}
