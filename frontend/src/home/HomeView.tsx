// HomeView — the s-ide ENGAGEMENTS dashboard (the front page / project picker).
//
// The engagement IS the project, so this is the welcome/dashboard tab. It
// faithfully mirrors the design mockup's ENGAGEMENTS view:
//
//   1. Header        — "Engagements" + live summary (N active · N completed) +
//                       a New Engagement button that opens the same inline
//                       create field as the dashed grid card.
//   2. Metric cards  — Total Findings / Critical / Active Engagements / Avg
//                       Coverage. Big mono numbers + sublabels. Aggregated from
//                       real per-engagement findings + coverage.
//   3. Engagement    — a card per engagement: status pill (pulse when active),
//      grid            severity finding chips, methodology-coverage bar, last
//                       activity. "Open" pins it active. The grid's last cell is
//                       the design's prominent DASHED "+ New Engagement" create
//                       card — an inline name field (Enter or Create) →
//                       createEngagement → setActiveEngagementId.
//   4. Tools Used    — horizontal bar chart aggregated from findings' `tool`
//                       field (runs = how many findings each tool produced).
//   5. Activity feed — most-recent findings across engagements, severity-colored,
//                       timestamped.
//   6. Quick links   — emit("openView", …) to Learning / Reports / Settings.
//
// Labs are NOT here anymore — they're their own rail view. Home is purely the
// engagements dashboard.
//
// REAL DATA: listEngagements() → cards; listFindings(id) → severity counts +
// tools + activity; fetchCoverage(id) → coverage %. Everything aggregates up to
// the metric cards. Fields the backend doesn't expose (per-engagement target,
// lead, active-tool, lab/engagement mode) are OMITTED rather than fabricated.
//
// This view owns NO new backend contracts. Engagement CRUD + active-id state
// route through lib/engagement.ts; cross-view navigation is the bus's
// `openView` event.
//
// Bus events emitted: openView ("learn" | "reports" | "settings").

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode, RefObject } from "react";
import {
  AsciiHero,
  Button,
  EyebrowPill,
  GlassCard,
  GradientText,
  Sparkle,
  StatusDot,
  WibblingSpinner,
} from "performative-ui";

import {
  listEngagements,
  listFindings,
  fetchCoverage,
  createEngagement,
  setActiveEngagementId,
  useActiveEngagementId,
  type Engagement,
  type Finding,
  type FindingSeverity,
} from "../lib/engagement";
import { emit } from "../shell/bus";
import MatrixRain from "./MatrixRain";

// CSS-var colors for the live StatusDot (matches SettingsView's palette).
const C_SUCCESS = "rgb(var(--success-rgb))";
const C_ACCENT = "rgb(var(--accent-rgb))";
const C_DIM = "rgb(var(--ink-dim-rgb))";

// Severity → token color (CSS vars from index.css). Used for chips + the
// activity feed dots so colors track the app's severity palette, not the mock's.
const SEV_COLOR: Record<FindingSeverity, string> = {
  critical: "rgb(var(--critical-rgb))",
  high: "rgb(var(--high-rgb))",
  medium: "rgb(var(--medium-rgb))",
  low: "rgb(var(--low-rgb))",
  info: "rgb(var(--ink-dim-rgb))",
};

// Compact chip label per severity (mock uses single letters).
const SEV_CHIP: Record<FindingSeverity, string> = {
  critical: "C",
  high: "H",
  medium: "M",
  low: "L",
  info: "I",
};

// ── Per-engagement derived stats ────────────────────────────────────────────
// Findings counts + coverage, fetched once per engagement after the list loads.
// `coverage` is null until/unless /engagements/{id}/coverage succeeds — we
// never invent a coverage number.

type SevCounts = Record<FindingSeverity, number>;

type EngStats = {
  counts: SevCounts;
  total: number;
  coverage: number | null; // percent 0..100, or null if unavailable
};

// Raw findings kept per engagement so the Tools-used chart and Activity feed
// derive from the SAME single fetch as the stat counts (no re-fetching).
type FindingsByEng = Record<string, Finding[]>;

function emptyCounts(): SevCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

// ── Relative-time formatter ─────────────────────────────────────────────────

function relTime(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const sec = Math.round((Date.now() - t) / 1000);
  if (sec < 45) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.round(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.round(mo / 12)}y ago`;
}

// ── Shared create-engagement flow ───────────────────────────────────────────
// One hook drives both the header button's affordance and the dashed grid
// card's inline field. create() → createEngagement → pin active → broadcast so
// the dashboard refreshes. Best-effort: a failure surfaces inline, no crash.

function useCreateEngagement() {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function create() {
    const trimmed = name.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    setError("");
    try {
      const eng = await createEngagement({
        name: trimmed,
        scope: [],
        exclusions: [],
        notes: "",
      });
      setActiveEngagementId(eng.id);
      setName("");
      window.dispatchEvent(new CustomEvent("side:engagements-changed"));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return { name, setName, busy, error, create };
}

// ════════════════════════════════════════════════════════════════════════════

export default function HomeView() {
  return (
    <div className="h-full overflow-y-auto bg-bg-base">
      <Dashboard />
    </div>
  );
}

// ── Dashboard: owns the engagement list + per-engagement stat fetch ─────────

function Dashboard() {
  const activeId = useActiveEngagementId();
  const [engagements, setEngagements] = useState<Engagement[] | null>(null);
  const [stats, setStats] = useState<Record<string, EngStats>>({});
  const [findingsByEng, setFindingsByEng] = useState<FindingsByEng>({});
  const [error, setError] = useState("");
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Fetch findings + coverage for one engagement. Best-effort: a failure on
  // either leaves that engagement without the corresponding datum rather than
  // failing the whole dashboard.
  const loadStats = useCallback(async (eid: string) => {
    let findings: Finding[] = [];
    try {
      findings = await listFindings(eid);
    } catch {
      /* leave counts at zero */
    }
    const counts = emptyCounts();
    for (const f of findings) {
      if (counts[f.severity] !== undefined) counts[f.severity] += 1;
    }
    let coverage: number | null = null;
    try {
      const cov = await fetchCoverage(eid);
      if (cov.total > 0) {
        coverage = Math.round((cov.covered_count / cov.total) * 100);
      }
    } catch {
      /* coverage stays null — omitted, not faked */
    }
    if (!mounted.current) return;
    setStats((s) => ({
      ...s,
      [eid]: { counts, total: findings.length, coverage },
    }));
    setFindingsByEng((m) => ({ ...m, [eid]: findings }));
  }, []);

  const refresh = useCallback(async () => {
    try {
      const list = await listEngagements();
      list.sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
      if (!mounted.current) return;
      setEngagements(list);
      setError("");
      setStats({});
      setFindingsByEng({});
      for (const eng of list) void loadStats(eng.id);
    } catch (e) {
      if (!mounted.current) return;
      setError(e instanceof Error ? e.message : String(e));
      setEngagements([]);
    }
  }, [loadStats]);

  useEffect(() => {
    void refresh();
    const onChange = () => void refresh();
    window.addEventListener("side:engagements-changed", onChange);
    return () => window.removeEventListener("side:engagements-changed", onChange);
  }, [refresh]);

  // The dashed create card owns the canonical name input; the header's "New
  // Engagement" button just scrolls to + focuses it (single source of truth).
  const createInputRef = useRef<HTMLInputElement>(null);
  const focusCreate = useCallback(() => {
    const el = createInputRef.current;
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.focus();
  }, []);

  return (
    <>
      <DashboardHeader engagements={engagements} onNew={focusCreate} />
      <div className="mx-auto max-w-6xl space-y-4 px-6 pb-12">
        {engagements === null ? (
          <GlassCard className="p-0" glowOnHover>
            <div className="flex items-center gap-2 p-5 text-[11px] text-ink-dim">
              <WibblingSpinner /> loading engagements…
            </div>
          </GlassCard>
        ) : error ? (
          <GlassCard className="p-0" glowOnHover>
            <div className="p-5 text-[11px] text-danger">⚠ {error}</div>
          </GlassCard>
        ) : (
          <>
            <MetricCards engagements={engagements} stats={stats} />
            <EngagementGrid
              engagements={engagements}
              stats={stats}
              activeId={activeId}
              createInputRef={createInputRef}
            />
            <div className="grid gap-4 lg:grid-cols-2">
              <ToolsUsedCard
                engagements={engagements}
                findingsByEng={findingsByEng}
              />
              <ActivityCard
                engagements={engagements}
                findingsByEng={findingsByEng}
              />
            </div>
          </>
        )}
        <QuickLinksSection />
      </div>
    </>
  );
}

// ── Header — title + summary + New Engagement button ────────────────────────
// The button is the design's prominent green pill; it focuses the dashed
// create card below (the single canonical creation point).

function DashboardHeader({
  engagements,
  onNew,
}: {
  engagements: Engagement[] | null;
  onNew: () => void;
}) {
  // Live summary: N active · N completed (mirrors the mock's engSummary).
  let summary = "";
  if (engagements) {
    const active = engagements.filter((e) => e.status === "active").length;
    const completed = engagements.filter((e) => e.status === "completed").length;
    const archived = engagements.filter((e) => e.status === "archived").length;
    const parts = [`${active} active`, `${completed} completed`];
    if (archived) parts.push(`${archived} archived`);
    summary = parts.join(" · ");
  }

  return (
    <header className="relative overflow-hidden border-b border-divider px-6 pt-6 pb-5">
      {/* Matrix "digital rain" backdrop, with the ASCII hero layered on top and
          a base→transparent gradient so the header text stays legible. */}
      <MatrixRain className="pointer-events-none absolute inset-0 opacity-[0.22]" />
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "linear-gradient(180deg, rgb(var(--bg-base-rgb) / 0.35) 0%, rgb(var(--bg-base-rgb) / 0.65) 100%)",
        }}
        aria-hidden
      />
      <AsciiHero
        variant="bare"
        className="pointer-events-none absolute inset-0 opacity-[0.10]"
        aria-hidden
      />
      <div className="relative mx-auto max-w-6xl">
        <div className="flex items-end justify-between gap-4">
          <div className="min-w-0">
            <EyebrowPill icon={false} className="text-[10px]">
              security engagement IDE
            </EyebrowPill>
            <h1 className="mt-2 flex items-center gap-2 text-2xl font-bold tracking-tight">
              <GradientText>Engagements</GradientText>
              <Sparkle />
            </h1>
            <p className="mt-1.5 max-w-2xl text-[12px] text-ink-muted">
              {summary && (
                <span className="text-ink-primary">{summary}</span>
              )}
              {summary && <span aria-hidden> · </span>}
              the engagement is the project — scope, findings, coverage &amp;
              reports all live inside it.
            </p>
          </div>
          <Button
            variant="solid"
            size="sm"
            className="shrink-0"
            onClick={onNew}
          >
            <Sparkle solid /> New Engagement
          </Button>
        </div>
      </div>
    </header>
  );
}

// ── Metric cards — big mono numbers + sublabels, aggregated from real data ──

function MetricCard({
  label,
  value,
  sub,
  valueColor,
  subColor,
}: {
  label: string;
  value: string;
  sub: string;
  valueColor?: string;
  subColor?: string;
}) {
  return (
    <GlassCard className="p-0" glowOnHover>
      <div className="p-4">
        <div className="text-[11px] font-medium text-ink-dim">{label}</div>
        <div
          className="data mt-2.5 text-[30px] font-bold leading-none"
          style={{ color: valueColor ?? "rgb(var(--ink-primary-rgb))" }}
        >
          {value}
        </div>
        <div
          className="mt-2 text-[11px] font-medium"
          style={{ color: subColor ?? "rgb(var(--ink-dim-rgb))" }}
        >
          {sub}
        </div>
      </div>
    </GlassCard>
  );
}

function MetricCards({
  engagements,
  stats,
}: {
  engagements: Engagement[];
  stats: Record<string, EngStats>;
}) {
  // Aggregate across whatever stats have loaded so far.
  let totalFindings = 0;
  let critical = 0;
  const covVals: number[] = [];
  for (const eng of engagements) {
    const s = stats[eng.id];
    if (!s) continue;
    totalFindings += s.total;
    critical += s.counts.critical;
    if (s.coverage !== null) covVals.push(s.coverage);
  }
  const activeCount = engagements.filter((e) => e.status === "active").length;
  const completedCount = engagements.filter(
    (e) => e.status === "completed",
  ).length;
  // Avg coverage only across engagements that reported coverage — omit if none.
  const avgCov =
    covVals.length > 0
      ? Math.round(covVals.reduce((a, b) => a + b, 0) / covVals.length)
      : null;

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <MetricCard
        label="Total Findings"
        value={String(totalFindings)}
        sub={`across ${engagements.length} engagement${engagements.length === 1 ? "" : "s"}`}
      />
      <MetricCard
        label="Critical"
        value={String(critical)}
        sub={critical > 0 ? "require remediation" : "none open"}
        valueColor={critical > 0 ? SEV_COLOR.critical : undefined}
        subColor={critical > 0 ? SEV_COLOR.critical : undefined}
      />
      <MetricCard
        label="Active Engagements"
        value={String(activeCount)}
        sub={`${completedCount} completed`}
        valueColor={C_ACCENT}
      />
      <MetricCard
        label="Avg Coverage"
        value={avgCov === null ? "—" : `${avgCov}%`}
        sub={avgCov === null ? "no coverage yet" : "methodology covered"}
      />
    </div>
  );
}

// ── Engagement cards ────────────────────────────────────────────────────────

const STATUS_META: Record<
  Engagement["status"],
  { label: string; color: string; pulse: boolean }
> = {
  active: { label: "Active", color: C_ACCENT, pulse: true },
  completed: { label: "Completed", color: C_SUCCESS, pulse: false },
  archived: { label: "Archived", color: C_DIM, pulse: false },
};

function SevChips({ counts }: { counts: SevCounts }) {
  const order: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
  const present = order.filter((s) => counts[s] > 0);
  if (present.length === 0) {
    return (
      <span className="text-[10.5px] text-ink-dim">no findings yet</span>
    );
  }
  return (
    <>
      {present.map((s) => (
        <span
          key={s}
          className="data inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10.5px] font-semibold"
          style={{
            color: SEV_COLOR[s],
            background: `color-mix(in srgb, ${SEV_COLOR[s]} 13%, transparent)`,
          }}
        >
          {SEV_CHIP[s]} {counts[s]}
        </span>
      ))}
    </>
  );
}

function EngagementCard({
  eng,
  stat,
  isActive,
}: {
  eng: Engagement;
  stat: EngStats | undefined;
  isActive: boolean;
}) {
  const sm = STATUS_META[eng.status];
  return (
    <GlassCard className="p-0" glowOnHover>
      <div className="flex h-full flex-col p-4">
        {/* top row: status pill */}
        <div className="mb-3 flex items-center gap-2">
          {isActive && (
            <span className="inline-flex items-center gap-1 rounded-md border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[9.5px] font-bold uppercase tracking-wider text-accent">
              <Sparkle solid /> pinned
            </span>
          )}
          <span
            className="ml-auto inline-flex items-center gap-1.5 text-[11px] font-semibold"
            style={{ color: sm.color }}
          >
            <StatusDot color={sm.color} static={!sm.pulse} />
            {sm.label}
          </span>
        </div>

        {/* name */}
        <div className="mb-3 truncate text-[15px] font-bold text-ink-primary">
          {eng.name}
        </div>

        {/* coverage bar — only when we have a real number */}
        {stat?.coverage !== null && stat?.coverage !== undefined ? (
          <div className="mb-3">
            <div className="mb-1.5 flex items-center justify-between text-[11px] font-medium text-ink-dim">
              <span>Methodology coverage</span>
              <span className="data text-ink-muted">{stat.coverage}%</span>
            </div>
            <div className="h-[5px] overflow-hidden rounded-full bg-bg-base">
              <div
                className="h-full rounded-full bg-accent transition-[width]"
                style={{ width: `${stat.coverage}%` }}
              />
            </div>
          </div>
        ) : (
          <div className="mb-3 h-[5px]" aria-hidden />
        )}

        {/* finding chips */}
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          {stat ? (
            <SevChips counts={stat.counts} />
          ) : (
            <span className="text-[10.5px] text-ink-dim">loading…</span>
          )}
        </div>

        {/* footer: scope + last activity + Open */}
        <div className="mt-auto flex items-center gap-3 border-t border-divider pt-3">
          <div className="min-w-0 flex-1 text-[10.5px] text-ink-dim">
            <span className="uppercase tracking-wider">{eng.status}</span>
            <span className="mx-1.5" aria-hidden>
              ·
            </span>
            <span>updated {relTime(eng.updated_at)}</span>
            {eng.scope.length > 0 && (
              <>
                <span className="mx-1.5" aria-hidden>
                  ·
                </span>
                <span>
                  {eng.scope.length} scope{eng.scope.length === 1 ? "" : "s"}
                </span>
              </>
            )}
          </div>
          <Button
            variant={isActive ? "ghost" : "solid"}
            size="sm"
            disabled={isActive}
            onClick={() => setActiveEngagementId(eng.id)}
          >
            Open
          </Button>
        </div>
      </div>
    </GlassCard>
  );
}

// The design's prominent dashed "+ New Engagement" create card. It lives as
// the final cell of the engagement grid and carries an inline name field:
// Enter (or the Create button) → createEngagement → setActiveEngagementId.
function NewEngagementCard({
  inputRef,
}: {
  inputRef: RefObject<HTMLInputElement>;
}) {
  const { name, setName, busy, error, create } = useCreateEngagement();
  return (
    <div
      className="group flex min-h-[250px] flex-col items-center justify-center gap-3
                 rounded-xl border border-dashed border-divider p-5 text-center
                 transition-colors hover:border-accent"
    >
      <div
        className="flex h-11 w-11 items-center justify-center rounded-xl border border-divider
                   bg-bg-card text-[26px] font-light leading-none text-ink-dim
                   transition-colors group-hover:border-accent group-hover:text-accent"
        aria-hidden
      >
        +
      </div>
      <div className="text-[13px] font-bold text-ink-primary">
        Start new engagement
      </div>
      <div className="max-w-[220px] text-[11.5px] leading-relaxed text-ink-dim">
        The engagement is the project — name it, then add scope &amp; targets
        inside.
      </div>

      <div className="mt-1 w-full max-w-[260px]">
        <input
          ref={inputRef}
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void create();
          }}
          placeholder="Engagement name…"
          disabled={busy}
          spellCheck={false}
          className="w-full rounded border border-divider bg-bg-base px-2.5 py-1.5
                     text-center text-[12px] text-ink-primary placeholder:text-ink-dim
                     focus:border-accent focus:outline-none"
        />
        <Button
          variant="solid"
          size="sm"
          className="mt-2 w-full justify-center"
          loading={busy}
          disabled={!name.trim()}
          onClick={() => void create()}
        >
          <Sparkle solid /> Create engagement
        </Button>
        {error && (
          <div className="mt-2 text-[11px] text-danger">⚠ {error}</div>
        )}
      </div>
    </div>
  );
}

function EngagementGrid({
  engagements,
  stats,
  activeId,
  createInputRef,
}: {
  engagements: Engagement[];
  stats: Record<string, EngStats>;
  activeId: string | null;
  createInputRef: RefObject<HTMLInputElement>;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {engagements.map((eng) => (
        <EngagementCard
          key={eng.id}
          eng={eng}
          stat={stats[eng.id]}
          isActive={eng.id === activeId}
        />
      ))}
      <NewEngagementCard inputRef={createInputRef} />
    </div>
  );
}

// ── Tools Used — horizontal bars aggregated from findings' `tool` field ─────

function ToolsUsedCard({
  engagements,
  findingsByEng,
}: {
  engagements: Engagement[];
  findingsByEng: FindingsByEng;
}) {
  // Each finding's `tool` field is the only real signal we have for "which
  // tool was used". We tally findings per tool across every engagement whose
  // findings have loaded; a tool's bar is sized by its finding share. The
  // mock's separate "runs vs findings" split isn't derivable, so we show finds.
  const loadedCount = engagements.filter(
    (e) => findingsByEng[e.id] !== undefined,
  ).length;
  const ready = engagements.length === 0 || loadedCount > 0;

  const tally = new Map<string, number>();
  for (const eng of engagements) {
    const fs = findingsByEng[eng.id];
    if (!fs) continue;
    for (const f of fs) {
      const key = (f.tool || "unknown").trim() || "unknown";
      tally.set(key, (tally.get(key) ?? 0) + 1);
    }
  }
  const tools = [...tally.entries()]
    .map(([name, findings]) => ({ name, findings }))
    .sort((a, b) => b.findings - a.findings)
    .slice(0, 8);

  const max = tools.length ? Math.max(...tools.map((t) => t.findings)) : 1;

  return (
    <GlassCard className="p-0" glowOnHover>
      <div className="p-5">
        <h2 className="mb-4 text-[13px] font-bold text-ink-primary">
          <GradientText static>Tools used</GradientText>
        </h2>
        {!ready ? (
          <div className="flex items-center gap-2 text-[11px] text-ink-dim">
            <WibblingSpinner /> tallying findings…
          </div>
        ) : tools.length === 0 ? (
          <div className="text-[11px] text-ink-dim">
            No findings recorded yet — tool usage appears here once findings land.
          </div>
        ) : (
          <div className="space-y-3">
            {tools.map((t) => (
              <div key={t.name}>
                <div className="mb-1.5 flex items-center gap-2">
                  <span className="flex-1 truncate text-[12.5px] font-medium text-ink-primary">
                    {t.name}
                  </span>
                  <span
                    className="data text-[11.5px] font-semibold"
                    style={{
                      color:
                        t.findings >= 3
                          ? SEV_COLOR.critical
                          : t.findings >= 1
                            ? SEV_COLOR.high
                            : C_DIM,
                    }}
                  >
                    {t.findings} find{t.findings === 1 ? "" : "s"}
                  </span>
                </div>
                <div className="h-[7px] overflow-hidden rounded-full bg-bg-base">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.round((t.findings / max) * 100)}%`,
                      background: "color-mix(in srgb, var(--accent) 55%, transparent)",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </GlassCard>
  );
}

// ── Activity feed — most-recent findings, severity-colored, timestamped ─────

function ActivityCard({
  engagements,
  findingsByEng,
}: {
  engagements: Engagement[];
  findingsByEng: FindingsByEng;
}) {
  // Merge every loaded engagement's findings into one recency-sorted feed,
  // severity-colored and timestamped. Derived from the same single fetch.
  const loadedCount = engagements.filter(
    (e) => findingsByEng[e.id] !== undefined,
  ).length;
  const ready = engagements.length === 0 || loadedCount > 0;

  const rows: {
    sev: FindingSeverity;
    text: string;
    ts: string;
    eng: string;
  }[] = [];
  for (const eng of engagements) {
    const fs = findingsByEng[eng.id];
    if (!fs) continue;
    for (const f of fs) {
      rows.push({
        sev: f.severity,
        text: f.title,
        ts: f.updated_at || f.ts,
        eng: eng.name,
      });
    }
  }
  rows.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
  const items = rows.slice(0, 6);

  return (
    <GlassCard className="p-0" glowOnHover>
      <div className="p-5">
        <h2 className="mb-2 text-[13px] font-bold text-ink-primary">
          <GradientText static>Recent activity</GradientText>
        </h2>
        {!ready ? (
          <div className="flex items-center gap-2 text-[11px] text-ink-dim">
            <WibblingSpinner /> loading activity…
          </div>
        ) : items.length === 0 ? (
          <div className="text-[11px] text-ink-dim">
            No findings yet — activity appears here as findings are recorded.
          </div>
        ) : (
          <div>
            {items.map((it, i) => (
              <div
                key={i}
                className="flex items-start gap-3 border-b border-divider py-2.5 last:border-0"
              >
                <span
                  className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
                  style={{ background: SEV_COLOR[it.sev] }}
                  aria-hidden
                />
                <div className="min-w-0 flex-1">
                  <div className="text-[12.5px] leading-snug text-ink-primary">
                    {it.text}
                  </div>
                  <div className="mt-0.5 truncate text-[10.5px] text-ink-dim">
                    {it.eng}
                  </div>
                </div>
                <div className="data shrink-0 text-[11px] text-ink-dim">
                  {relTime(it.ts)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </GlassCard>
  );
}

// ── Section shell ────────────────────────────────────────────────────────────

// Shared section shell (mirrors SettingsView.Section) — used by Quick links.
function Section({
  eyebrow,
  title,
  hint,
  status,
  children,
}: {
  eyebrow: string;
  title: string;
  hint: string;
  status?: ReactNode;
  children: ReactNode;
}) {
  return (
    <GlassCard className="p-0" glowOnHover>
      <header className="flex items-start gap-3 border-b border-divider px-5 py-3.5">
        <div className="flex-1">
          <EyebrowPill icon={false} className="text-[10px]">
            {eyebrow}
          </EyebrowPill>
          <h2 className="mt-1.5 text-[15px] font-bold text-ink-primary">
            <GradientText static>{title}</GradientText>
          </h2>
          <p className="mt-0.5 text-[11px] text-ink-dim">{hint}</p>
        </div>
        {status && <div className="shrink-0 pt-1">{status}</div>}
      </header>
      <div className="p-5">{children}</div>
    </GlassCard>
  );
}

// ── Quick links ─────────────────────────────────────────────────────────────

const QUICK_LINKS: {
  view: "learn" | "reports" | "settings";
  label: string;
  hint: string;
}[] = [
  { view: "learn", label: "Learning", hint: "labs, hints & methodology" },
  { view: "reports", label: "Reports", hint: "export & snapshots" },
  { view: "settings", label: "Settings", hint: "theme, copilot, capabilities" },
];

function QuickLinksSection() {
  return (
    <Section
      eyebrow="Jump to"
      title="Quick links"
      hint="The rest of the workspace. These open as tabs in the editor area."
    >
      <div className="flex flex-wrap gap-2">
        {QUICK_LINKS.map((l) => (
          <Button
            key={l.view}
            variant="ghost"
            size="sm"
            onClick={() => emit("openView", { view: l.view })}
          >
            {l.label}
            <span className="ml-1.5 text-[10px] opacity-70">{l.hint}</span>
          </Button>
        ))}
      </div>
    </Section>
  );
}
