/**
 * GraphView — one-click application scan.
 *
 * Point it at a project folder and hit Scan: it runs the backend codebase scan
 * (POST /codescan) ONCE and renders BOTH halves of the result:
 *
 *   1. Asset tiles — clickable cards, one per discovered asset category
 *      (Languages, Frameworks, Entry Points, Routes, Dependencies, Config &
 *      Secrets, Code Findings). Clicking a tile lists that category's members.
 *   2. Code review — the SAST findings, with a severity donut + filter chips.
 *
 * The last-scanned path is remembered (localStorage) and re-scanned on mount so
 * the view "just works" on reopen. No engagement required — this is about the
 * codebase itself.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { authFetch } from "../api";

// ── Types ────────────────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low" | "info";

type AssetItem = {
  name: string;
  detail?: string;
  file?: string;
  line?: number;
  source?: string;
};
type AssetCategory = { id: string; label: string; count: number; items: AssetItem[] };

type Finding = {
  severity: Severity;
  title: string;
  type: string;
  file: string;
  line: number;
  snippet?: string;
};

type ScanResult = {
  root: string;
  scanned_files: number;
  findings: Finding[];
  assets: AssetCategory[];
};

// ── Palette ──────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff5d6c",
  high: "#ff9340",
  medium: "#ffc043",
  low: "#4d9fff",
  info: "#586173",
};
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};

// Per-category accent + glyph for the tiles.
const CAT_COLOR: Record<string, string> = {
  languages: "#39d98a",
  frameworks: "#4d9fff",
  entrypoints: "#a78bfa",
  routes: "#22d3ee",
  dependencies: "#ffc043",
  configs: "#fb923c",
  findings: "#ff5d6c",
};
const CAT_GLYPH: Record<string, string> = {
  languages: "◇",
  frameworks: "⬡",
  entrypoints: "▶",
  routes: "⇄",
  dependencies: "⬢",
  configs: "⚙",
  findings: "⚠",
};
const FAINT = "#586173";
const ACCENT = "#39d98a";

const PATH_KEY = "s-ide:codescan-path";

function hexA(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

// ── Component ────────────────────────────────────────────────────────────────

export default function GraphView() {
  const [path, setPath] = useState<string>(() => {
    try {
      return localStorage.getItem(PATH_KEY) ?? "";
    } catch {
      return "";
    }
  });
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedCat, setSelectedCat] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<Severity | null>(null);
  const reviewRef = useRef<HTMLDivElement | null>(null);

  const canBrowse = typeof (window as any).nt?.pickDirectory === "function";

  const scan = useCallback(async (p: string) => {
    const target = p.trim();
    if (!target) {
      setError("Pick a project folder to scan.");
      return;
    }
    setScanning(true);
    setError(null);
    try {
      const res = await authFetch("/codescan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: target }),
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
          const b = await res.json();
          msg = b.detail || b.error || msg;
        } catch {
          /* keep status */
        }
        setError(msg);
        setResult(null);
        return;
      }
      const data = (await res.json()) as ScanResult;
      setResult(data);
      setSelectedCat(
        data.assets.find((c) => c.count > 0)?.id ?? null,
      );
      setSevFilter(null);
      try {
        localStorage.setItem(PATH_KEY, target);
      } catch {
        /* quota */
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setResult(null);
    } finally {
      setScanning(false);
    }
  }, []);

  // Auto-scan on mount if we remember a path — "just works" on reopen.
  useEffect(() => {
    if (path) void scan(path);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function browse() {
    try {
      const picked = await (window as any).nt?.pickDirectory?.();
      if (picked) {
        setPath(picked);
        void scan(picked);
      }
    } catch {
      /* user cancelled */
    }
  }

  // Severity counts for the donut.
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
      const to = (acc / total) * 100;
      stops.push(`${SEV_COLOR[s]} ${from}% ${to}%`);
    }
    return `conic-gradient(${stops.join(", ")})`;
  }, [counts, total]);

  const selected = result?.assets.find((c) => c.id === selectedCat) ?? null;
  const visibleFindings = useMemo(
    () => (result?.findings ?? []).filter((f) => !sevFilter || f.severity === sevFilter),
    [result, sevFilter],
  );

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-base px-7 pb-12 pt-6 text-ink-primary">
      {/* Header */}
      <div className="mb-4">
        <div className="text-[20px] font-bold text-ink-primary">Application Scan</div>
        <div className="mt-1 text-[12.5px] text-ink-dim">
          {result ? (
            <>
              <span className="data">{result.root}</span> · {result.scanned_files} files ·{" "}
              {total} finding{total === 1 ? "" : "s"}
              {counts.critical > 0 && (
                <>
                  {" "}
                  · <span style={{ color: SEV_COLOR.critical }}>{counts.critical} critical</span>
                </>
              )}
            </>
          ) : (
            "Scan a project folder to map its assets and review its code."
          )}
        </div>
      </div>

      {/* Scan bar */}
      <div className="mb-5 flex flex-wrap items-center gap-2 rounded-[11px] border border-divider bg-bg-card p-2.5">
        <input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void scan(path)}
          placeholder="/path/to/your/project"
          spellCheck={false}
          className="data min-w-0 flex-1 rounded-md border border-divider bg-bg-base px-3 py-2 text-[12.5px] text-ink-primary outline-none placeholder:text-ink-dim focus:border-accent"
        />
        {canBrowse && (
          <button
            onClick={browse}
            disabled={scanning}
            className="rounded-md border border-divider px-3 py-2 text-[12px] text-ink-muted hover:border-accent hover:text-accent disabled:opacity-50"
          >
            Browse…
          </button>
        )}
        <button
          onClick={() => void scan(path)}
          disabled={scanning || !path.trim()}
          className="rounded-md bg-accent px-4 py-2 text-[12.5px] font-bold text-bg-base disabled:opacity-50"
          style={{ boxShadow: scanning ? "none" : `0 4px 16px ${hexA(ACCENT, 0.3)}` }}
        >
          {scanning ? "Scanning…" : "Scan"}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
          {error}
        </div>
      )}

      {!result && !scanning && !error && (
        <Empty
          title="Nothing scanned yet"
          sub="Choose your application's folder above and hit Scan — assets and code findings appear here."
        />
      )}

      {scanning && !result && <Empty title="Scanning the codebase…" sub="Walking files and running SAST." />}

      {result && (
        <>
          {/* ── Asset tiles ── */}
          <div className="mb-2 text-[12px] font-semibold uppercase tracking-widest text-ink-dim">
            Application Assets
          </div>
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
                      className="flex h-7 w-7 items-center justify-center rounded-md text-[14px]"
                      style={{ background: hexA(color, 0.14), color }}
                    >
                      {CAT_GLYPH[cat.id] ?? "•"}
                    </span>
                    <span className="data text-[22px] font-bold leading-none" style={{ color }}>
                      {cat.count}
                    </span>
                  </div>
                  <span className="text-[12.5px] font-semibold text-ink-primary">{cat.label}</span>
                </button>
              );
            })}
          </div>

          {/* ── Selected category items + severity donut ── */}
          <div className="grid gap-3.5" style={{ gridTemplateColumns: "1fr 268px" }}>
            <div className="min-h-[220px] rounded-[13px] border border-divider bg-bg-card p-4">
              {selected ? (
                <>
                  <div className="mb-3 flex items-center gap-2">
                    <span
                      className="flex h-6 w-6 items-center justify-center rounded-md text-[12px]"
                      style={{
                        background: hexA(CAT_COLOR[selected.id] ?? ACCENT, 0.14),
                        color: CAT_COLOR[selected.id] ?? ACCENT,
                      }}
                    >
                      {CAT_GLYPH[selected.id] ?? "•"}
                    </span>
                    <span className="text-[13px] font-semibold text-ink-primary">
                      {selected.label}
                    </span>
                    <span className="data text-[11.5px] text-ink-dim">{selected.count}</span>
                  </div>
                  {selected.items.length === 0 ? (
                    <div className="text-[12px] text-ink-dim">None found.</div>
                  ) : (
                    <div className="flex flex-col gap-1.5">
                      {selected.items.map((it, i) => (
                        <div
                          key={`${it.name}-${i}`}
                          className="flex items-baseline gap-3 border-b border-divider/60 py-1.5 last:border-b-0"
                        >
                          <span className="data flex-1 truncate text-[12.5px] text-ink-primary">
                            {it.name}
                          </span>
                          {it.detail && (
                            <span className="data shrink-0 text-[11px] text-ink-dim">{it.detail}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="text-[12px] text-ink-dim">Select an asset tile to list its members.</div>
              )}
            </div>

            {/* Severity donut */}
            <div className="rounded-[13px] border border-divider bg-bg-card p-4">
              <div className="mb-3 text-[12px] font-semibold text-ink-primary">Severity Breakdown</div>
              <div className="flex items-center gap-4">
                <div
                  className="relative h-[88px] w-[88px] flex-[0_0_88px] rounded-full"
                  style={{ background: donutBg }}
                >
                  <div className="absolute inset-[14px] flex flex-col items-center justify-center rounded-full bg-bg-card">
                    <div className="data text-[20px] font-bold leading-none text-ink-primary">{total}</div>
                    <div className="mt-0.5 text-[9px] uppercase tracking-wide text-ink-dim">findings</div>
                  </div>
                </div>
                <div className="flex flex-1 flex-col gap-1.5">
                  {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                    <div key={s} className="flex items-center gap-2 text-[11.5px]">
                      <span className="h-[7px] w-[7px] rounded-full" style={{ background: SEV_COLOR[s] }} />
                      <span className="flex-1 text-ink-muted">{SEV_LABEL[s]}</span>
                      <span className="data text-ink-primary">{counts[s]}</span>
                    </div>
                  ))}
                  {total === 0 && <div className="text-[11.5px] text-ink-dim">No findings 🎉</div>}
                </div>
              </div>
            </div>
          </div>

          {/* ── Code review ── */}
          <div ref={reviewRef} className="mt-6">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="text-[12px] font-semibold uppercase tracking-widest text-ink-dim">
                Code Review
              </span>
              <span className="data text-[11.5px] text-ink-dim">
                {visibleFindings.length}/{total}
              </span>
              <div className="ml-auto flex items-center gap-1.5">
                <Chip on={sevFilter === null} onClick={() => setSevFilter(null)} color={FAINT}>
                  All
                </Chip>
                {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
                  <Chip
                    key={s}
                    on={sevFilter === s}
                    onClick={() => setSevFilter(sevFilter === s ? null : s)}
                    color={SEV_COLOR[s]}
                  >
                    {SEV_LABEL[s]} {counts[s]}
                  </Chip>
                ))}
              </div>
            </div>

            <div className="overflow-hidden rounded-[13px] border border-divider bg-bg-card">
              {visibleFindings.length === 0 ? (
                <div className="p-6 text-center text-[12.5px] text-ink-dim">
                  {total === 0 ? "No code findings — clean scan." : "No findings at this severity."}
                </div>
              ) : (
                visibleFindings.map((f, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 border-b border-divider/60 px-4 py-2.5 last:border-b-0"
                  >
                    <span
                      className="mt-1 h-[8px] w-[8px] shrink-0 rounded-full"
                      style={{ background: SEV_COLOR[f.severity] }}
                      title={SEV_LABEL[f.severity]}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[12.5px] font-semibold text-ink-primary">{f.title}</span>
                        <span
                          className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-widest"
                          style={{
                            color: SEV_COLOR[f.severity],
                            borderColor: hexA(SEV_COLOR[f.severity], 0.4),
                            background: hexA(SEV_COLOR[f.severity], 0.1),
                          }}
                        >
                          {f.type}
                        </span>
                        <span className="data text-[11px] text-ink-dim">
                          {f.file}:{f.line}
                        </span>
                      </div>
                      {f.snippet && (
                        <pre className="data mt-1 overflow-x-auto rounded bg-bg-base px-2 py-1 text-[11px] text-ink-muted">
                          {f.snippet}
                        </pre>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Bits ─────────────────────────────────────────────────────────────────────

function Chip({
  on,
  onClick,
  color,
  children,
}: {
  on: boolean;
  onClick: () => void;
  color: string;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className="rounded-full border px-2.5 py-1 text-[11px] font-medium transition"
      style={{
        color: on ? "#0a0e15" : color,
        background: on ? color : "transparent",
        borderColor: hexA(color, 0.5),
      }}
    >
      {children}
    </button>
  );
}

function Empty({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-8 text-center">
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
