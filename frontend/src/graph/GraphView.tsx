/**
 * GraphView — the open engagement's codebase, mapped.
 *
 * No path input: the codebase comes from the ACTIVE ENGAGEMENT's `source_root`
 * (set once, here or at engagement creation). When an engagement with a
 * codebase is open, this view auto-scans it (POST /codescan) and renders:
 *
 *   1. Architecture graph — a visual frontend → backend map. Frontend modules
 *      on the left, the backend areas/tools they call on the right, edges drawn
 *      between them (WS/streaming tools styled distinctly). Hover to trace.
 *   2. Asset tiles — clickable categories (Languages, Frameworks, Routes, …).
 *   3. Code review — the SAST findings with a severity donut + filters.
 */
import { useCallback, useEffect, useMemo, useState } from "react";

import { authFetch } from "../api";
import {
  updateEngagement,
  useActiveEngagementId,
  type Engagement,
} from "../lib/engagement";
import { emit } from "../shell/bus";
import type { Anchor } from "../shell/refs";

// ── Types ────────────────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low" | "info";

type AssetItem = { name: string; detail?: string; file?: string; line?: number };
type AssetCategory = { id: string; label: string; count: number; items: AssetItem[] };

type Finding = {
  severity: Severity;
  title: string;
  type: string;
  file: string;
  line: number;
  snippet?: string;
};

type GNode = {
  id: string;
  label: string;
  layer: "frontend" | "backend";
  kind?: "route" | "ws";
  defined?: boolean;
  routes?: number;
  calls?: number;
};
type GEdge = { from: string; to: string; kind: "api" | "ws"; count: number };
type ConnGraph = {
  nodes: GNode[];
  edges: GEdge[];
  frontend_count: number;
  backend_count: number;
  unwired_backend_groups: number;
};

type ScanResult = {
  root: string;
  scanned_files: number;
  findings: Finding[];
  assets: AssetCategory[];
  graph: ConnGraph;
};

// ── Palette ──────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff5d6c", high: "#ff9340", medium: "#ffc043", low: "#4d9fff", info: "#586173",
};
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};

const CAT_COLOR: Record<string, string> = {
  languages: "#39d98a", frameworks: "#4d9fff", entrypoints: "#a78bfa",
  routes: "#22d3ee", dependencies: "#ffc043", configs: "#fb923c", findings: "#ff5d6c",
};
const CAT_GLYPH: Record<string, string> = {
  languages: "◇", frameworks: "⬡", entrypoints: "▶", routes: "⇄",
  dependencies: "⬢", configs: "⚙", findings: "⚠",
};
const ACCENT = "#39d98a";
const FE_COLOR = "#4d9fff"; // frontend nodes
const BE_COLOR = "#a78bfa"; // backend route nodes
const TOOL_COLOR = "#22d3ee"; // backend ws/streaming "tools"
const FAINT = "#586173";

function hexA(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

// ── Bus wiring ───────────────────────────────────────────────────────────────
// A click anywhere in the graph resolves to a code `Anchor` and broadcasts
// `selectAnchor` (source "graph"). The pivot inspector and the fixdiff code view
// subscribe to that event, so clicking a node/asset/finding jumps them to the
// location. The graph is a codebase MAP, not an engagement-finding graph — its
// entities are code locations, so they map to file/route/config anchors rather
// than to `selectFinding` (which needs a spine finding's provenance triple).

/** Anchor for an architecture-graph node: backend → route, frontend → file. */
export function nodeAnchor(n: GNode): Anchor {
  return n.layer === "backend"
    ? { kind: "route", route: n.label }
    : { kind: "file", file: n.label };
}

/** Anchor for an asset-tile item, or null if it carries no locatable target. */
export function itemAnchor(catId: string, it: AssetItem): Anchor | null {
  if (it.file) return { kind: "file", file: it.file, line: it.line };
  if (catId === "routes") return { kind: "route", route: it.name };
  if (catId === "configs") return { kind: "config", key: it.name };
  return null;
}

/** Anchor for a SAST code-review finding (always a file location). */
export function findingAnchor(f: Finding): Anchor {
  return { kind: "file", file: f.file, line: f.line };
}

function publishAnchor(ref: Anchor | null): void {
  if (ref) emit("selectAnchor", { ref, source: "graph" });
}

// ── Component ────────────────────────────────────────────────────────────────

export default function GraphView() {
  const eid = useActiveEngagementId();
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [engLoading, setEngLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedCat, setSelectedCat] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<Severity | null>(null);

  const codebase = engagement?.source_root?.trim() || "";
  const canBrowse = typeof (window as any).nt?.pickDirectory === "function";

  // Load the active engagement (for its source_root).
  useEffect(() => {
    if (!eid) {
      setEngagement(null);
      setResult(null);
      return;
    }
    let alive = true;
    setEngLoading(true);
    authFetch(`/engagements/${eid}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((e: Engagement | null) => alive && setEngagement(e))
      .catch(() => alive && setEngagement(null))
      .finally(() => alive && setEngLoading(false));
    return () => {
      alive = false;
    };
  }, [eid]);

  const scan = useCallback(async (path: string) => {
    if (!path) return;
    setScanning(true);
    setError(null);
    try {
      const res = await authFetch("/codescan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }),
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const b = await res.json();
          msg = b.detail || b.error || msg;
        } catch {
          /* keep */
        }
        setError(msg);
        setResult(null);
        return;
      }
      const data = (await res.json()) as ScanResult;
      setResult(data);
      setSelectedCat(data.assets.find((c) => c.count > 0)?.id ?? null);
      setSevFilter(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setResult(null);
    } finally {
      setScanning(false);
    }
  }, []);

  // Auto-scan whenever the engagement's codebase is known/changes.
  useEffect(() => {
    if (codebase) void scan(codebase);
    else setResult(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [codebase]);

  // Pick / change the engagement's codebase folder (persists to the engagement).
  async function pickCodebase() {
    if (!eid) return;
    try {
      const picked = await (window as any).nt?.pickDirectory?.();
      if (!picked) return;
      const updated = await updateEngagement(eid, { source_root: picked });
      setEngagement(updated);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  // Severity counts + donut.
  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of result?.findings ?? []) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [result]);
  const total = result?.findings.length ?? 0;
  const donutBg = useMemo(() => {
    if (total === 0) return `conic-gradient(${hexA(FAINT, 0.25)} 0 100%)`;
    let acc = 0;
    const stops: string[] = [];
    for (const s of SEV_ORDER) {
      const n = counts[s];
      if (n === 0) continue;
      const from = (acc / total) * 100;
      acc += n;
      stops.push(`${SEV_COLOR[s]} ${from}% ${(acc / total) * 100}%`);
    }
    return `conic-gradient(${stops.join(", ")})`;
  }, [counts, total]);

  const selected = result?.assets.find((c) => c.id === selectedCat) ?? null;
  const visibleFindings = useMemo(
    () => (result?.findings ?? []).filter((f) => !sevFilter || f.severity === sevFilter),
    [result, sevFilter],
  );

  // ── Render guards ─────────────────────────────────────────────────────────
  if (!eid) {
    return <Empty title="No active engagement" sub="Open an engagement to map its codebase." />;
  }
  if (engLoading && !engagement) {
    return <Empty title="Loading engagement…" sub="" />;
  }
  if (!codebase) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 bg-bg-base px-8 text-center">
        <Glyph />
        <div>
          <div className="text-[calc(15px_*_var(--text-scale))] font-semibold text-ink-primary">No codebase set for this engagement</div>
          <div className="mt-1.5 max-w-[420px] text-[calc(12.5px_*_var(--text-scale))] text-ink-dim">
            Point this engagement at its source folder once — the graph then scans it
            automatically every time you open it.
          </div>
        </div>
        {canBrowse ? (
          <button
            onClick={pickCodebase}
            className="rounded-md bg-accent px-4 py-2 text-[calc(12.5px_*_var(--text-scale))] font-bold text-bg-base"
            style={{ boxShadow: `0 4px 16px ${hexA(ACCENT, 0.3)}` }}
          >
            Set codebase folder…
          </button>
        ) : (
          <div className="text-[calc(12px_*_var(--text-scale))] text-ink-dim">
            Set this engagement's source folder from the desktop app.
          </div>
        )}
        {error && <div className="text-[calc(12px_*_var(--text-scale))] text-danger">{error}</div>}
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-base px-7 pb-12 pt-6 text-ink-primary">
      {/* Header */}
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[calc(20px_*_var(--text-scale))] font-bold text-ink-primary">Codebase Map</div>
          <div className="mt-1 text-[calc(12.5px_*_var(--text-scale))] text-ink-dim">
            <span className="data">{codebase}</span>
            {result && (
              <>
                {" "}
                · {result.scanned_files} files · {result.graph.frontend_count}→
                {result.graph.backend_count} wired · {total} finding{total === 1 ? "" : "s"}
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void scan(codebase)}
            disabled={scanning}
            className="rounded-md bg-accent px-3.5 py-1.5 text-[calc(12px_*_var(--text-scale))] font-bold text-bg-base disabled:opacity-50"
          >
            {scanning ? "Scanning…" : "Rescan"}
          </button>
          {canBrowse && (
            <button
              onClick={pickCodebase}
              className="rounded-md border border-divider px-3 py-1.5 text-[calc(12px_*_var(--text-scale))] text-ink-muted hover:border-accent hover:text-accent"
            >
              Change folder…
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-[calc(12px_*_var(--text-scale))] text-danger">
          {error}
        </div>
      )}

      {scanning && !result && <Empty title="Scanning the codebase…" sub="Walking files, mapping calls, running SAST." />}

      {result && (
        <>
          {/* ── Architecture graph ── */}
          <SectionLabel>Architecture · frontend → backend</SectionLabel>
          <ConnectionGraph graph={result.graph} />

          {/* ── Asset tiles ── */}
          <SectionLabel className="mt-6">Application Assets</SectionLabel>
          <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-4">
            {result.assets.map((cat) => {
              const color = CAT_COLOR[cat.id] ?? ACCENT;
              const on = selectedCat === cat.id;
              const empty = cat.count === 0;
              return (
                <button
                  key={cat.id}
                  disabled={empty}
                  onClick={() => setSelectedCat(cat.id)}
                  className="flex flex-col items-start gap-1.5 rounded-[12px] border bg-bg-card p-3.5 text-left transition disabled:opacity-40"
                  style={{
                    borderColor: on ? color : "var(--divider)",
                    boxShadow: on ? `0 0 0 1px ${color}, 0 8px 22px ${hexA(color, 0.18)}` : "none",
                    cursor: empty ? "default" : "pointer",
                  }}
                >
                  <div className="flex w-full items-center gap-2">
                    <span
                      className="flex h-7 w-7 items-center justify-center rounded-md text-[calc(14px_*_var(--text-scale))]"
                      style={{ background: hexA(color, 0.14), color }}
                    >
                      {CAT_GLYPH[cat.id] ?? "•"}
                    </span>
                    <span className="data text-[calc(22px_*_var(--text-scale))] font-bold leading-none" style={{ color }}>
                      {cat.count}
                    </span>
                  </div>
                  <span className="text-[calc(12.5px_*_var(--text-scale))] font-semibold text-ink-primary">{cat.label}</span>
                </button>
              );
            })}
          </div>

          {/* ── Selected category items + donut ── */}
          <div className="grid gap-3.5" style={{ gridTemplateColumns: "1fr 268px" }}>
            <div className="min-h-[200px] rounded-[13px] border border-divider bg-bg-card p-4">
              {selected ? (
                <>
                  <div className="mb-3 flex items-center gap-2">
                    <span
                      className="flex h-6 w-6 items-center justify-center rounded-md text-[calc(12px_*_var(--text-scale))]"
                      style={{
                        background: hexA(CAT_COLOR[selected.id] ?? ACCENT, 0.14),
                        color: CAT_COLOR[selected.id] ?? ACCENT,
                      }}
                    >
                      {CAT_GLYPH[selected.id] ?? "•"}
                    </span>
                    <span className="text-[calc(13px_*_var(--text-scale))] font-semibold text-ink-primary">{selected.label}</span>
                    <span className="data text-[calc(11.5px_*_var(--text-scale))] text-ink-dim">{selected.count}</span>
                  </div>
                  {selected.items.length === 0 ? (
                    <div className="text-[calc(12px_*_var(--text-scale))] text-ink-dim">None found.</div>
                  ) : (
                    <div className="flex flex-col gap-1.5">
                      {selected.items.map((it, i) => {
                        const a = itemAnchor(selected.id, it);
                        const body = (
                          <>
                            <span className="data flex-1 truncate text-[calc(12.5px_*_var(--text-scale))] text-ink-primary">{it.name}</span>
                            {it.detail && <span className="data shrink-0 text-[calc(11px_*_var(--text-scale))] text-ink-dim">{it.detail}</span>}
                          </>
                        );
                        return a ? (
                          <button
                            key={`${it.name}-${i}`}
                            onClick={() => publishAnchor(a)}
                            title={a.kind === "file" ? `${a.file}${a.line ? `:${a.line}` : ""}` : (a.route ?? a.key)}
                            className="flex items-baseline gap-3 border-b border-divider/60 py-1.5 text-left transition-colors last:border-b-0 hover:text-accent"
                          >
                            {body}
                          </button>
                        ) : (
                          <div
                            key={`${it.name}-${i}`}
                            className="flex items-baseline gap-3 border-b border-divider/60 py-1.5 last:border-b-0"
                          >
                            {body}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </>
              ) : (
                <div className="text-[calc(12px_*_var(--text-scale))] text-ink-dim">Select an asset tile to list its members.</div>
              )}
            </div>

            <div className="rounded-[13px] border border-divider bg-bg-card p-4">
              <div className="mb-3 text-[calc(12px_*_var(--text-scale))] font-semibold text-ink-primary">Severity Breakdown</div>
              <div className="flex items-center gap-4">
                <div className="relative h-[88px] w-[88px] flex-[0_0_88px] rounded-full" style={{ background: donutBg }}>
                  <div className="absolute inset-[14px] flex flex-col items-center justify-center rounded-full bg-bg-card">
                    <div className="data text-[calc(20px_*_var(--text-scale))] font-bold leading-none text-ink-primary">{total}</div>
                    <div className="mt-0.5 text-[calc(9px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">findings</div>
                  </div>
                </div>
                <div className="flex flex-1 flex-col gap-1.5">
                  {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                    <div key={s} className="flex items-center gap-2 text-[calc(11.5px_*_var(--text-scale))]">
                      <span className="h-[7px] w-[7px] rounded-full" style={{ background: SEV_COLOR[s] }} />
                      <span className="flex-1 text-ink-muted">{SEV_LABEL[s]}</span>
                      <span className="data text-ink-primary">{counts[s]}</span>
                    </div>
                  ))}
                  {total === 0 && <div className="text-[calc(11.5px_*_var(--text-scale))] text-ink-dim">No findings 🎉</div>}
                </div>
              </div>
            </div>
          </div>

          {/* ── Code review ── */}
          <div className="mt-6">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="text-[calc(12px_*_var(--text-scale))] font-semibold uppercase tracking-widest text-ink-dim">Code Review</span>
              <span className="data text-[calc(11.5px_*_var(--text-scale))] text-ink-dim">{visibleFindings.length}/{total}</span>
              <div className="ml-auto flex items-center gap-1.5">
                <Chip on={sevFilter === null} onClick={() => setSevFilter(null)} color={FAINT}>All</Chip>
                {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                  <Chip key={s} on={sevFilter === s} onClick={() => setSevFilter(sevFilter === s ? null : s)} color={SEV_COLOR[s]}>
                    {SEV_LABEL[s]} {counts[s]}
                  </Chip>
                ))}
              </div>
            </div>
            <div className="overflow-hidden rounded-[13px] border border-divider bg-bg-card">
              {visibleFindings.length === 0 ? (
                <div className="p-6 text-center text-[calc(12.5px_*_var(--text-scale))] text-ink-dim">
                  {total === 0 ? "No code findings — clean scan." : "No findings at this severity."}
                </div>
              ) : (
                visibleFindings.map((f, i) => (
                  <button
                    key={i}
                    onClick={() => publishAnchor(findingAnchor(f))}
                    title={`${f.file}:${f.line}`}
                    className="flex w-full items-start gap-3 border-b border-divider/60 px-4 py-2.5 text-left transition-colors last:border-b-0 hover:bg-bg-hover"
                  >
                    <span className="mt-1 h-[8px] w-[8px] shrink-0 rounded-full" style={{ background: SEV_COLOR[f.severity] }} title={SEV_LABEL[f.severity]} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[calc(12.5px_*_var(--text-scale))] font-semibold text-ink-primary">{f.title}</span>
                        <span
                          className="rounded border px-1.5 py-0.5 text-[calc(9px_*_var(--text-scale))] font-bold uppercase tracking-widest"
                          style={{ color: SEV_COLOR[f.severity], borderColor: hexA(SEV_COLOR[f.severity], 0.4), background: hexA(SEV_COLOR[f.severity], 0.1) }}
                        >
                          {f.type}
                        </span>
                        <span className="data text-[calc(11px_*_var(--text-scale))] text-ink-dim">{f.file}:{f.line}</span>
                      </div>
                      {f.snippet && (
                        <pre className="data mt-1 overflow-x-auto rounded bg-bg-base px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-muted">{f.snippet}</pre>
                      )}
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Architecture graph (SVG, 2 columns: frontend | backend) ──────────────────

const NW = 168;
const NH = 26;
const ROW = 34;
const PADY = 18;
const CANVAS_W = 760;
const LEFT_X = 18;
const RIGHT_X = CANVAS_W - NW - 18;

function ConnectionGraph({ graph }: { graph: ConnGraph }) {
  const [hover, setHover] = useState<string | null>(null);

  const { fe, be, pos, height } = useMemo(() => {
    const fe = graph.nodes
      .filter((n) => n.layer === "frontend")
      .sort((a, b) => (b.calls ?? 0) - (a.calls ?? 0) || a.label.localeCompare(b.label));
    // tools (ws) first, then routes; each alphabetical
    const be = graph.nodes
      .filter((n) => n.layer === "backend")
      .sort(
        (a, b) =>
          Number(b.kind === "ws") - Number(a.kind === "ws") || a.label.localeCompare(b.label),
      );
    const pos = new Map<string, { x: number; y: number }>();
    fe.forEach((n, i) => pos.set(n.id, { x: LEFT_X, y: PADY + i * ROW }));
    be.forEach((n, i) => pos.set(n.id, { x: RIGHT_X, y: PADY + i * ROW }));
    const height = Math.max(fe.length, be.length) * ROW + PADY * 2;
    return { fe, be, pos, height };
  }, [graph]);

  if (graph.edges.length === 0 && graph.nodes.length === 0) {
    return (
      <div className="mb-2 rounded-[13px] border border-divider bg-bg-card p-6 text-center text-[calc(12.5px_*_var(--text-scale))] text-ink-dim">
        No frontend→backend calls detected in this codebase.
      </div>
    );
  }

  const lit = (id: string): boolean => {
    if (!hover) return true;
    if (hover === id) return true;
    return graph.edges.some(
      (e) => (e.from === hover && e.to === id) || (e.to === hover && e.from === id),
    );
  };

  const colorOf = (n: GNode) =>
    n.layer === "frontend" ? FE_COLOR : n.kind === "ws" ? TOOL_COLOR : BE_COLOR;

  return (
    <div className="mb-2">
      <div className="relative overflow-auto rounded-[13px] border border-divider bg-bg-card">
        <div className="relative" style={{ width: CANVAS_W, height: Math.max(height, 160) }}>
          {/* Column captions */}
          <div className="absolute left-[18px] top-1 text-[calc(10px_*_var(--text-scale))] font-bold uppercase tracking-widest" style={{ color: FE_COLOR }}>
            Frontend ({fe.length})
          </div>
          <div className="absolute top-1 text-[calc(10px_*_var(--text-scale))] font-bold uppercase tracking-widest" style={{ left: RIGHT_X, color: BE_COLOR }}>
            Backend ({be.length})
          </div>

          <svg width={CANVAS_W} height={Math.max(height, 160)} className="absolute inset-0">
            {graph.edges.map((e, i) => {
              const A = pos.get(e.from);
              const B = pos.get(e.to);
              if (!A || !B) return null;
              const ax = A.x + NW;
              const ay = A.y + NH / 2;
              const bx = B.x;
              const by = B.y + NH / 2;
              const mid = (ax + bx) / 2;
              const on = !hover || hover === e.from || hover === e.to;
              const c = e.kind === "ws" ? TOOL_COLOR : FE_COLOR;
              return (
                <path
                  key={i}
                  d={`M ${ax} ${ay} C ${mid} ${ay}, ${mid} ${by}, ${bx} ${by}`}
                  fill="none"
                  stroke={hexA(c, on ? 0.55 : 0.12)}
                  strokeWidth={on ? Math.min(1 + e.count * 0.3, 3) : 1}
                  strokeDasharray={e.kind === "ws" ? "4 3" : undefined}
                />
              );
            })}
          </svg>

          {[...fe, ...be].map((n) => {
            const p = pos.get(n.id)!;
            const color = colorOf(n);
            const on = lit(n.id);
            const detail =
              n.layer === "frontend"
                ? `${n.calls} call${n.calls === 1 ? "" : "s"}`
                : n.kind === "ws"
                  ? "tool · ws"
                  : n.defined
                    ? `${n.routes} route${n.routes === 1 ? "" : "s"}`
                    : "endpoint";
            return (
              <div
                key={n.id}
                role="button"
                tabIndex={0}
                onMouseEnter={() => setHover(n.id)}
                onMouseLeave={() => setHover(null)}
                onClick={() => publishAnchor(nodeAnchor(n))}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); publishAnchor(nodeAnchor(n)); }
                }}
                title={`${n.label} · ${detail}`}
                className="absolute z-[2] flex cursor-pointer items-center gap-1.5 rounded-[8px] px-2.5 py-1.5 transition-[opacity,filter]"
                style={{
                  left: p.x,
                  top: p.y,
                  width: NW,
                  height: NH,
                  opacity: on ? 1 : 0.28,
                  background: "var(--bg-panel, #11161f)",
                  border: `1px solid ${hexA(color, hover === n.id ? 0.9 : 0.45)}`,
                  boxShadow: hover === n.id ? `0 0 0 1px ${color}, 0 6px 16px ${hexA(color, 0.25)}` : "none",
                }}
              >
                <span className="h-[7px] w-[7px] flex-[0_0_7px] rounded-full" style={{ background: color }} />
                <span className="data flex-1 overflow-hidden text-ellipsis whitespace-nowrap text-[calc(11.5px_*_var(--text-scale))] font-medium text-ink-primary">
                  {n.label}
                </span>
                <span className="data shrink-0 text-[calc(9px_*_var(--text-scale))] text-ink-dim">{detail}</span>
              </div>
            );
          })}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-4 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
        <Legend color={FE_COLOR} label="Frontend module" />
        <Legend color={BE_COLOR} label="Backend route" />
        <Legend color={TOOL_COLOR} label="Tool (WS/stream)" />
        {graph.unwired_backend_groups > 0 && (
          <span>· {graph.unwired_backend_groups} more backend areas not called from the UI</span>
        )}
      </div>
    </div>
  );
}

// ── Bits ─────────────────────────────────────────────────────────────────────

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="h-[8px] w-[8px] rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}

function SectionLabel({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`mb-2 text-[calc(12px_*_var(--text-scale))] font-semibold uppercase tracking-widest text-ink-dim ${className}`}>
      {children}
    </div>
  );
}

function Chip({ on, onClick, color, children }: { on: boolean; onClick: () => void; color: string; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className="rounded-full border px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] font-medium transition"
      style={{ color: on ? "#0a0e15" : color, background: on ? color : "transparent", borderColor: hexA(color, 0.5) }}
    >
      {children}
    </button>
  );
}

function Glyph() {
  return (
    <div className="flex h-12 w-12 items-center justify-center rounded-full border border-divider text-ink-dim">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <circle cx="6" cy="6" r="2.5" />
        <circle cx="18" cy="6" r="2.5" />
        <circle cx="12" cy="18" r="2.5" />
        <line x1="7.6" y1="7.6" x2="11" y2="16" />
        <line x1="16.4" y1="7.6" x2="13" y2="16" />
      </svg>
    </div>
  );
}

function Empty({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center bg-bg-base px-8 text-center">
      <Glyph />
      <div className="mt-2 text-[calc(15px_*_var(--text-scale))] font-semibold text-ink-primary">{title}</div>
      {sub && <div className="mt-1.5 max-w-[360px] text-[calc(12.5px_*_var(--text-scale))] text-ink-dim">{sub}</div>}
    </div>
  );
}
