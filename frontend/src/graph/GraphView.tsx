/**
 * GraphView — the asset / finding relationship graph.
 *
 * Self-contained SVG node-edge graph (no npm deps, no force sim). Replicates
 * the GRAPH section of the S-IDE design mock: severity-colored node pills with
 * a mono label + dot, severity-tinted edges, a legend, and a severity donut.
 *
 * Data sources (both keyed off the active engagement):
 *   - listFindings(eid)        → Finding[]  { severity, title, target, tool }
 *   - GET /method/assets/eng:<eid> → { assets: [{ kind, key, props }] }
 *
 * Build rule: hosts are roots; their services / endpoints hang off them as
 * leaves; findings attach to whichever asset node best matches their `target`
 * (else to a synthetic "unassigned findings" hub off the engagement root). A
 * node carrying findings is colored by its worst severity.
 *
 * Interactions: hover a node → highlight it + its incident edges; click a node
 * that carries findings → emit("focusFinding", { findingId }) for its worst.
 */
import { useEffect, useMemo, useState } from "react";

import { authFetch } from "../api";
import {
  useActiveEngagementId,
  listFindings,
  type Finding,
  type FindingSeverity,
} from "../lib/engagement";
import { emit } from "../shell/bus";

// ── Types ────────────────────────────────────────────────────────────────────

type Asset = {
  kind: string; // host | service | endpoint | cert | tech | ...
  key: string;
  props?: Record<string, unknown>;
};

type GNode = {
  id: string;
  label: string;
  kind: string;
  x: number;
  y: number;
  root: boolean;
  sev: FindingSeverity | null; // worst severity of attached findings
  findingCount: number;
  worstFindingId: string | null;
};

type GEdge = { from: string; to: string };

// ── Severity palette (mirrors index.css tokens) ──────────────────────────────

const SEV_COLOR: Record<FindingSeverity, string> = {
  critical: "#ff5d6c",
  high: "#ff9340",
  medium: "#ffc043",
  low: "#4d9fff",
  info: "#586173",
};

const SEV_RANK: Record<FindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const SEV_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL: Record<FindingSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const ACCENT = "#39d98a";
const FAINT = "#586173";

// hex (#rrggbb) → rgba string
function hexA(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

// ── Layout geometry ──────────────────────────────────────────────────────────

const NW = 138; // node pill width
const NH = 38; // node pill height (without CVE line)
const COL_GAP = 230; // horizontal gap between depth columns
const ROW_GAP = 60; // vertical gap between siblings
const PAD_X = 40;
const PAD_Y = 30;

/**
 * Assemble the graph model from raw assets + findings.
 *
 * Columns by depth:  [root] → [hosts] → [services/endpoints] → [unmatched/tech]
 * A radial-ish grid: each column is laid out vertically and centered.
 */
function buildGraph(
  eid: string,
  assets: Asset[],
  findings: Finding[],
): { nodes: GNode[]; edges: GEdge[]; width: number; height: number } {
  const edges: GEdge[] = [];

  // Worst-finding accumulator per node id.
  const attach = new Map<
    string,
    { count: number; worst: FindingSeverity; worstId: string }
  >();
  const addFinding = (nodeId: string, f: Finding) => {
    const sev = (f.severity ?? "info") as FindingSeverity;
    const cur = attach.get(nodeId);
    if (!cur) {
      attach.set(nodeId, { count: 1, worst: sev, worstId: f.id });
    } else {
      cur.count += 1;
      if (SEV_RANK[sev] > SEV_RANK[cur.worst]) {
        cur.worst = sev;
        cur.worstId = f.id;
      }
    }
  };

  // Asset buckets.
  const hosts = assets.filter((a) => a.kind === "host");
  const leaves = assets.filter(
    (a) => a.kind === "service" || a.kind === "endpoint",
  );
  const techs = assets.filter(
    (a) => a.kind !== "host" && a.kind !== "service" && a.kind !== "endpoint",
  );

  const nodeKey = (a: Asset) => `${a.kind}:${a.key}`;

  // Match a finding target to the best asset key (exact, then containment).
  const allAssetNodes = [...hosts, ...leaves, ...techs];
  function matchNode(target: string): string | null {
    if (!target) return null;
    const t = target.trim();
    // exact key
    let hit = allAssetNodes.find((a) => a.key === t);
    if (hit) return nodeKey(hit);
    // target contains the asset key, or asset key contains the target —
    // longest matching key wins so "host:port/path" beats "host".
    let best: { id: string; len: number } | null = null;
    for (const a of allAssetNodes) {
      if (!a.key) continue;
      if (t.includes(a.key) || a.key.includes(t)) {
        if (!best || a.key.length > best.len) best = { id: nodeKey(a), len: a.key.length };
      }
    }
    return best?.id ?? null;
  }

  const ROOT = "root";
  const UNASSIGNED = "unassigned";
  let hasUnassigned = false;

  for (const f of findings) {
    const id = matchNode(f.target);
    if (id) addFinding(id, f);
    else {
      hasUnassigned = true;
      addFinding(UNASSIGNED, f);
    }
  }

  // Map each leaf to a parent host. A service/endpoint key usually starts with
  // or contains its host key; fall back to round-robin so nothing floats.
  const leafParent = new Map<string, string>();
  for (const l of leaves) {
    const host = hosts.find((h) => h.key && l.key.includes(h.key));
    leafParent.set(nodeKey(l), host ? nodeKey(host) : ROOT);
  }

  // ── Place nodes column by column ──────────────────────────────────────────
  const nodes: GNode[] = [];
  const place = (
    id: string,
    label: string,
    kind: string,
    col: number,
    rowIdx: number,
    rowCount: number,
    root: boolean,
  ) => {
    const colHeight = Math.max(rowCount - 1, 0) * ROW_GAP;
    const yStart = PAD_Y + 200 - colHeight / 2; // vertically center the column
    const a = attach.get(id);
    nodes.push({
      id,
      label,
      kind,
      x: PAD_X + col * COL_GAP,
      y: Math.max(PAD_Y, yStart + rowIdx * ROW_GAP),
      root,
      sev: a ? a.worst : null,
      findingCount: a ? a.count : 0,
      worstFindingId: a ? a.worstId : null,
    });
  };

  // Column 0: engagement root.
  place(ROOT, eid, "root", 0, 0, 1, true);

  // Column 1: hosts (+ unassigned hub if needed).
  const col1: { id: string; label: string; kind: string }[] = hosts.map((h) => ({
    id: nodeKey(h),
    label: h.key,
    kind: "host",
  }));
  if (hasUnassigned) {
    col1.push({ id: UNASSIGNED, label: "unassigned", kind: "host" });
  }
  col1.forEach((c, i) => {
    place(c.id, c.label, c.kind, 1, i, col1.length, false);
    edges.push({ from: ROOT, to: c.id });
  });

  // Column 2: services + endpoints, grouped under their host.
  const col2 = leaves.map((l) => ({ id: nodeKey(l), label: l.key, kind: l.kind }));
  col2.forEach((c, i) => {
    place(c.id, c.label, c.kind, 2, i, Math.max(col2.length, 1), false);
    edges.push({ from: leafParent.get(c.id) ?? ROOT, to: c.id });
  });

  // Column 3: tech / cert / other — hung off the root for context.
  const col3 = techs.map((t) => ({ id: nodeKey(t), label: t.key, kind: t.kind }));
  col3.forEach((c, i) => {
    place(c.id, c.label, c.kind, 3, i, Math.max(col3.length, 1), false);
    edges.push({ from: ROOT, to: c.id });
  });

  const maxCol = 3;
  const width = PAD_X + maxCol * COL_GAP + NW + PAD_X;
  const maxY = nodes.reduce((m, n) => Math.max(m, n.y), 0);
  const height = Math.max(460, maxY + NH + PAD_Y);

  return { nodes, edges, width, height };
}

// ── Component ────────────────────────────────────────────────────────────────

export default function GraphView() {
  const eid = useActiveEngagementId();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);

  useEffect(() => {
    if (!eid) {
      setFindings([]);
      setAssets([]);
      setLoading(false);
      return;
    }
    let alive = true;
    setLoading(true);
    setError(null);

    const fp = listFindings(eid).catch(() => [] as Finding[]);
    const ap = authFetch(`/method/assets/eng:${eid}`)
      .then((r) => (r.ok ? r.json() : { assets: [] }))
      .then((b: { assets?: Asset[] }) => b.assets ?? [])
      .catch(() => [] as Asset[]);

    Promise.all([fp, ap])
      .then(([f, a]) => {
        if (!alive) return;
        setFindings(f);
        setAssets(a);
      })
      .catch((e) => {
        if (alive) setError(String(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });

    return () => {
      alive = false;
    };
  }, [eid]);

  // Severity counts for the donut + legend.
  const counts = useMemo(() => {
    const c: Record<FindingSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of findings) {
      const s = (f.severity ?? "info") as FindingSeverity;
      c[s] = (c[s] ?? 0) + 1;
    }
    return c;
  }, [findings]);

  const total = findings.length;

  const graph = useMemo(
    () => (eid ? buildGraph(eid, assets, findings) : null),
    [eid, assets, findings],
  );

  const nodeMap = useMemo(() => {
    const m = new Map<string, GNode>();
    graph?.nodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [graph]);

  // Conic-gradient donut.
  const donutBg = useMemo(() => {
    if (total === 0) return `conic-gradient(${hexA(FAINT, 0.25)} 0 100%)`;
    let acc = 0;
    const stops: string[] = [];
    for (const s of SEV_ORDER) {
      const n = counts[s];
      if (n === 0) continue;
      const from = (acc / total) * 100;
      acc += n;
      const to = (acc / total) * 100;
      stops.push(`${SEV_COLOR[s]} ${from}% ${to}%`);
    }
    return `conic-gradient(${stops.join(", ")})`;
  }, [counts, total]);

  const vulnNodes = useMemo(
    () =>
      (graph?.nodes ?? [])
        .filter((n) => n.findingCount > 0)
        .sort(
          (a, b) =>
            SEV_RANK[(b.sev ?? "info")] - SEV_RANK[(a.sev ?? "info")] ||
            b.findingCount - a.findingCount,
        ),
    [graph],
  );

  // ── Render guards ──────────────────────────────────────────────────────────

  if (!eid) {
    return (
      <Empty title="No active engagement" sub="Select an engagement to view its asset graph." />
    );
  }
  if (loading) {
    return <Empty title="Loading graph…" sub="" />;
  }
  if (error) {
    return <Empty title="Couldn't load the graph" sub={error} />;
  }
  if (!graph || (assets.length === 0 && findings.length === 0)) {
    return (
      <Empty
        title="No assets yet"
        sub="Run tools to populate the asset graph — discovered hosts, services and findings will appear here."
      />
    );
  }

  const nodeIsHi = (id: string): boolean => {
    if (!hover) return true;
    if (hover === id) return true;
    // a node is "lit" if it shares an edge with the hovered node
    return (graph.edges ?? []).some(
      (e) =>
        (e.from === hover && e.to === id) || (e.to === hover && e.from === id),
    );
  };

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-base px-7 pb-10 pt-6 text-ink-primary">
      {/* Header */}
      <div className="mb-5 flex items-center justify-between">
        <div>
          <div className="text-[20px] font-bold text-ink-primary">Asset Graph</div>
          <div className="mt-1 text-[12.5px] text-ink-dim">
            <span className="data">{eid}</span> · {assets.length} asset
            {assets.length === 1 ? "" : "s"} · {total} finding
            {total === 1 ? "" : "s"}
            {counts.critical > 0 && (
              <>
                {" "}
                · <span style={{ color: SEV_COLOR.critical }}>{counts.critical} critical</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3.5">
          {SEV_ORDER.filter((s) => s !== "info" || counts.info > 0).map((s) => (
            <div
              key={s}
              className="flex items-center gap-1.5 text-[11.5px] font-medium text-ink-dim"
            >
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: SEV_COLOR[s] }}
              />
              {SEV_LABEL[s]}
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-3.5" style={{ gridTemplateColumns: "1fr 268px" }}>
        {/* ── Graph canvas ── */}
        <div className="relative h-[480px] overflow-auto rounded-[13px] border border-divider bg-bg-card">
          <div
            className="relative"
            style={{ width: graph.width, height: graph.height }}
          >
            <svg
              width={graph.width}
              height={graph.height}
              className="absolute inset-0"
            >
              {graph.edges.map((e, i) => {
                const A = nodeMap.get(e.from);
                const B = nodeMap.get(e.to);
                if (!A || !B) return null;
                const tgtSev = B.sev;
                const lit = hover ? hover === e.from || hover === e.to : true;
                const color = tgtSev
                  ? hexA(SEV_COLOR[tgtSev], lit ? 0.7 : 0.4)
                  : hexA(FAINT, lit ? 0.6 : 0.3);
                return (
                  <line
                    key={i}
                    x1={A.x + NW / 2}
                    y1={A.y + NH / 2}
                    x2={B.x + NW / 2}
                    y2={B.y + NH / 2}
                    stroke={color}
                    strokeWidth={tgtSev ? 1.6 : 1}
                  />
                );
              })}
            </svg>

            {graph.nodes.map((n) => {
              const sevColor = n.sev ? SEV_COLOR[n.sev] : null;
              const dot = sevColor ?? (n.root ? ACCENT : FAINT);
              const lit = nodeIsHi(n.id);
              const border = sevColor ?? (n.root ? hexA(ACCENT, 0.4) : "var(--border)");
              const clickable = n.findingCount > 0 && n.worstFindingId;
              return (
                <div
                  key={n.id}
                  onMouseEnter={() => setHover(n.id)}
                  onMouseLeave={() => setHover(null)}
                  onClick={() => {
                    if (clickable && n.worstFindingId) {
                      emit("focusFinding", { findingId: n.worstFindingId });
                    }
                  }}
                  title={`${n.kind} · ${n.label}${
                    n.findingCount ? ` · ${n.findingCount} finding(s)` : ""
                  }`}
                  className="absolute z-[2] rounded-[9px] px-3 py-2 transition-[filter,opacity]"
                  style={{
                    left: n.x,
                    top: n.y,
                    width: NW,
                    cursor: clickable ? "pointer" : "default",
                    opacity: lit ? 1 : 0.4,
                    filter: hover === n.id ? "brightness(1.14)" : "none",
                    background: n.root ? hexA(ACCENT, 0.13) : "var(--bg-panel, #11161f)",
                    border: `1px solid ${border}`,
                    boxShadow: sevColor
                      ? `0 0 0 1px ${sevColor}, 0 8px 22px ${hexA(sevColor, 0.22)}`
                      : "0 2px 8px rgba(0,0,0,.28)",
                  }}
                >
                  <div className="flex items-center gap-1.5">
                    <span
                      className="h-[7px] w-[7px] flex-[0_0_7px] rounded-full"
                      style={{ background: dot }}
                    />
                    <span
                      className="data flex-1 overflow-hidden text-ellipsis whitespace-nowrap text-[11.5px] font-medium text-ink-primary"
                    >
                      {n.label}
                    </span>
                  </div>
                  {n.findingCount > 0 && (
                    <div
                      className="data mt-1 text-[9.5px]"
                      style={{ color: dot }}
                    >
                      {n.findingCount} finding{n.findingCount === 1 ? "" : "s"}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Sidebar: donut + vulnerable assets ── */}
        <div className="flex flex-col gap-3">
          {/* Donut */}
          <div className="rounded-[13px] border border-divider bg-bg-card p-4">
            <div className="mb-3 text-[12px] font-semibold text-ink-primary">
              Severity Breakdown
            </div>
            <div className="flex items-center gap-4">
              <div
                className="relative h-[88px] w-[88px] flex-[0_0_88px] rounded-full"
                style={{ background: donutBg }}
              >
                <div className="absolute inset-[14px] flex flex-col items-center justify-center rounded-full bg-bg-card">
                  <div className="data text-[20px] font-bold leading-none text-ink-primary">
                    {total}
                  </div>
                  <div className="mt-0.5 text-[9px] uppercase tracking-wide text-ink-dim">
                    findings
                  </div>
                </div>
              </div>
              <div className="flex flex-1 flex-col gap-1.5">
                {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                  <div key={s} className="flex items-center gap-2 text-[11.5px]">
                    <span
                      className="h-[7px] w-[7px] rounded-full"
                      style={{ background: SEV_COLOR[s] }}
                    />
                    <span className="flex-1 text-ink-muted">{SEV_LABEL[s]}</span>
                    <span className="data text-ink-primary">{counts[s]}</span>
                  </div>
                ))}
                {total === 0 && (
                  <div className="text-[11.5px] text-ink-dim">No findings</div>
                )}
              </div>
            </div>
          </div>

          {/* Vulnerable assets list */}
          <div className="rounded-[13px] border border-divider bg-bg-card p-[15px]">
            <div className="mb-3 text-[12px] font-semibold text-ink-primary">
              Vulnerable Assets
            </div>
            {vulnNodes.length === 0 && (
              <div className="text-[11.5px] text-ink-dim">
                No findings attached to assets yet.
              </div>
            )}
            {vulnNodes.map((n) => (
              <div
                key={n.id}
                onClick={() => {
                  if (n.worstFindingId)
                    emit("focusFinding", { findingId: n.worstFindingId });
                }}
                onMouseEnter={() => setHover(n.id)}
                onMouseLeave={() => setHover(null)}
                className="cursor-pointer border-b border-divider py-2.5 last:border-b-0 hover:opacity-80"
              >
                <div className="mb-1 flex items-center gap-2">
                  <span
                    className="h-[7px] w-[7px] rounded-full"
                    style={{ background: n.sev ? SEV_COLOR[n.sev] : FAINT }}
                  />
                  <span className="data flex-1 truncate text-[12.5px] font-medium text-ink-primary">
                    {n.label}
                  </span>
                </div>
                <div className="data pl-[15px] text-[11px] text-ink-dim">
                  {n.findingCount} finding{n.findingCount === 1 ? "" : "s"} ·{" "}
                  {n.sev ? SEV_LABEL[n.sev] : "—"} · {n.kind}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Empty / status state ─────────────────────────────────────────────────────

function Empty({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center bg-bg-base px-8 text-center">
      <div className="mb-2 flex h-12 w-12 items-center justify-center rounded-full border border-divider text-ink-dim">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
          <circle cx="6" cy="6" r="2.5" />
          <circle cx="18" cy="6" r="2.5" />
          <circle cx="12" cy="18" r="2.5" />
          <line x1="7.6" y1="7.6" x2="11" y2="16" />
          <line x1="16.4" y1="7.6" x2="13" y2="16" />
        </svg>
      </div>
      <div className="text-[15px] font-semibold text-ink-primary">{title}</div>
      {sub && <div className="mt-1.5 max-w-[360px] text-[12.5px] text-ink-dim">{sub}</div>}
    </div>
  );
}
