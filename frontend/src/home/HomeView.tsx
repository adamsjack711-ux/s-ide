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
//   6. Quick links   — a lead "Run a tool →" (opens the ⌘K tool search) +
//                       Workbench, then emit("openView", …) to Learning /
//                       Reports / Settings.
//
// First-run: when there are no engagements (and the user hasn't dismissed it),
// a focused getting-started hero replaces the wall-of-zeros — "create your
// first engagement" then "run a tool". Re-summonable via the ⌘K "Show Getting
// Started" command (bus: command:show-onboarding). ⌘N (bus: command:focus-create)
// opens the create modal. Dismiss persists to localStorage (onboarding_done).
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
import type { ReactNode } from "react";
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
  deleteEngagement,
  isLabEngagement,
  getActiveEngagementId,
  setActiveEngagementId,
  useActiveEngagementId,
  type Engagement,
  type CreatedEngagement,
  type Finding,
  type FindingSeverity,
} from "../lib/engagement";
import { setActiveTarget } from "../lib/targets";
import { openEngagementTab } from "../lib/engagementTabs";
import NewEngagementModal from "../engagement/NewEngagementModal";
import { emit, useBus } from "../shell/bus";
import { notify } from "../shell/toast";
import ViewModeToggle from "../shell/ViewModeToggle";
import { useViewMode } from "../lib/viewMode";
import MatrixRain from "./MatrixRain";

// localStorage flag: once the user has dismissed (or completed) the first-run
// getting-started hero we don't nag returning users. The ⌘K "Show Getting
// Started" command can always re-surface it regardless of this flag.
const ONBOARDING_DONE_KEY = "s-ide:onboarding_done:v1";

function readOnboardingDone(): boolean {
  try {
    return localStorage.getItem(ONBOARDING_DONE_KEY) === "1";
  } catch {
    return false;
  }
}

function writeOnboardingDone(done: boolean): void {
  try {
    if (done) localStorage.setItem(ONBOARDING_DONE_KEY, "1");
    else localStorage.removeItem(ONBOARDING_DONE_KEY);
  } catch {
    /* quota / unavailable */
  }
}

// Focus the palette's tool search (mirrors the keymap's `open-tool` command),
// so a "Run a tool →" CTA on Home behaves identically to ⌘T / ⌘K.
function openToolSearch(): void {
  window.dispatchEvent(
    new CustomEvent("s-ide:palette", { detail: { mode: "tool" } }),
  );
}

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

// ── Opening an engagement ────────────────────────────────────────────────────
// An engagement is a workspace *scope*, not its own view: opening it pins it
// active (every backend call then carries its X-MHP-Engagement-Id) AND drops
// the user into the Workbench — the tab where tools + playbooks live and run.
// Without the second step, clicking "Open" only re-pinned and looked like a
// no-op (especially for the already-active engagement).

// Opening an engagement now opens it as a primary TAB: its workspace holds the
// Workbench / Map / Findings / Reporting / Terminal sub-tabs, and activating the
// tab pins the engagement so every tool auto-scopes to it.
function openEngagement(id: string, name: string): void {
  openEngagementTab({ id, name });
}

// Called once the typed-create modal returns a new engagement. Pins it active,
// makes its primary target / source root the default target for tools (via the
// active-target snapshot), broadcasts so the dashboard refreshes, and opens the
// Workbench so the operator lands where they can immediately run playbooks.

function onEngagementCreated(created: CreatedEngagement): void {
  if (created.primary_target) {
    // web-app target URL / local-app source root becomes the default target.
    setActiveTarget({
      // web-app registers a real target row; local-app's root has no row, so
      // synthesize a stable id (the snapshot is read directly by useLabIntent).
      id: created.primary_target_id ?? `eng-root:${created.id}`,
      address: created.primary_target,
      name: created.name,
      kind: created.provenance === "lab" ? "lab" : "manual",
    });
  }
  window.dispatchEvent(new CustomEvent("side:engagements-changed"));
  // Surface success — creation was previously silent.
  notify({ kind: "success", message: "Engagement created · opening workbench" });
  // Pin it active and land in the Workbench (tools + playbooks).
  openEngagement(created.id, created.name);
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
      // Lab-provenance engagements (local sandbox + lab spin-ups) belong to the
      // Learn → Labs area, not the engagements dashboard.
      const list = (await listEngagements()).filter((e) => !isLabEngagement(e));
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

  // The header button and the dashed grid card both open the typed-create
  // modal (single canonical creation point).
  const [showCreate, setShowCreate] = useState(false);
  const openCreate = useCallback(() => setShowCreate(true), []);

  // Id of the just-created engagement — its card briefly flashes once the
  // refreshed list renders it.
  const [flashId, setFlashId] = useState<string | null>(null);
  useEffect(() => {
    if (!flashId) return;
    const h = setTimeout(() => setFlashId(null), 1600);
    return () => clearTimeout(h);
  }, [flashId]);

  const handleCreated = useCallback((created: CreatedEngagement) => {
    setShowCreate(false);
    onEngagementCreated(created);
    setFlashId(created.id);
  }, []);

  // ── Getting-started hero visibility ───────────────────────────────────────
  // Re-shown on demand via the ⌘K "Show Getting Started" command (bus event),
  // and auto-shown on a true first run (no engagements + not yet dismissed).
  const [showOnboarding, setShowOnboarding] = useState(false);
  const dismissOnboarding = useCallback(() => {
    writeOnboardingDone(true);
    setShowOnboarding(false);
  }, []);

  // Foundation bus: ⌘N "New Engagement" → focus/open the create affordance.
  useBus("command:focus-create", openCreate);
  // Foundation bus: "Show Getting Started" → re-surface the hero (ignores the
  // persisted dismiss flag — an explicit request always wins).
  useBus(
    "command:show-onboarding",
    useCallback(() => setShowOnboarding(true), []),
  );

  // First run: no engagements + never dismissed → auto-show the hero once the
  // list has actually loaded (engagements !== null).
  const firstRun = engagements !== null && engagements.length === 0;
  useEffect(() => {
    if (firstRun && !readOnboardingDone()) setShowOnboarding(true);
  }, [firstRun]);

  // Delete an engagement (the card's × → inline confirm). If it was the
  // active/pinned one, clear the active pin. Broadcast so the dashboard
  // refreshes (and any other window re-reads the list).
  const handleDelete = useCallback(async (eng: Engagement) => {
    try {
      await deleteEngagement(eng.id);
      if (getActiveEngagementId() === eng.id) setActiveEngagementId(null);
      window.dispatchEvent(new CustomEvent("side:engagements-changed"));
    } catch (e) {
      if (mounted.current) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }
  }, []);

  return (
    <div className="h-full overflow-y-auto">
      <NewEngagementModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={handleCreated}
      />
      <DashboardHeader engagements={engagements} onNew={openCreate} />
      <div className="mx-auto max-w-6xl space-y-4 px-6 pt-5 pb-12">
        {engagements === null ? (
          <GlassCard className="p-0" glowOnHover>
            <div className="flex items-center gap-2 p-5 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
              <WibblingSpinner /> loading engagements…
            </div>
          </GlassCard>
        ) : error ? (
          <GlassCard className="p-0" glowOnHover>
            <div className="p-5 text-[calc(11px_*_var(--text-scale))] text-danger">⚠ {error}</div>
          </GlassCard>
        ) : (
          <>
            {showOnboarding && (
              <GettingStartedHero
                firstRun={firstRun}
                onCreate={openCreate}
                onDismiss={dismissOnboarding}
              />
            )}
            {firstRun ? (
              // First run: skip the wall-of-zeros metric/tool/activity cards —
              // the hero above already points the user at their first action.
              // The dashed create card stays available below it.
              <EngagementGrid
                engagements={engagements}
                stats={stats}
                activeId={activeId}
                flashId={flashId}
                onOpenCreate={openCreate}
                onDelete={handleDelete}
              />
            ) : (
              <>
                <MetricCards engagements={engagements} stats={stats} />
                <EngagementGrid
                  engagements={engagements}
                  stats={stats}
                  activeId={activeId}
                  flashId={flashId}
                  onOpenCreate={openCreate}
                  onDelete={handleDelete}
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
          </>
        )}
        <QuickLinksSection />
      </div>
    </div>
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
            <EyebrowPill icon={false} className="text-[calc(10px_*_var(--text-scale))]">
              security engagement IDE
            </EyebrowPill>
            <h1 className="mt-2 flex items-center gap-2 text-2xl font-bold tracking-tight">
              <GradientText>Engagements</GradientText>
              <Sparkle />
            </h1>
            {summary && (
              <p className="mt-1.5 max-w-2xl text-[calc(12px_*_var(--text-scale))] text-ink-primary">{summary}</p>
            )}
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
        <div className="text-[calc(11px_*_var(--text-scale))] font-medium text-ink-dim">{label}</div>
        <div
          className="data mt-2.5 text-[calc(30px_*_var(--text-scale))] font-bold leading-none"
          style={{ color: valueColor ?? "rgb(var(--ink-primary-rgb))" }}
        >
          {value}
        </div>
        <div
          className="mt-2 text-[calc(11px_*_var(--text-scale))] font-medium"
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
      <span className="text-[calc(10.5px_*_var(--text-scale))] text-ink-dim">no findings yet</span>
    );
  }
  return (
    <>
      {present.map((s) => (
        <span
          key={s}
          className="data inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[calc(10.5px_*_var(--text-scale))] font-semibold"
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

// A simple delete affordance: an "×" that turns into a two-click inline
// confirm (no native dialog). `stopPropagation` so clicking it never trips
// the card's other click targets.
function DeleteX({
  onConfirm,
  label,
}: {
  onConfirm: () => void;
  label: string;
}) {
  const [confirming, setConfirming] = useState(false);
  if (confirming) {
    return (
      <span className="inline-flex shrink-0 items-center gap-1">
        <button
          onClick={(e) => { e.stopPropagation(); onConfirm(); }}
          className="rounded px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] font-semibold text-danger ring-1 ring-danger/40 hover:bg-danger/10"
        >
          Delete
        </button>
        <button
          onClick={(e) => { e.stopPropagation(); setConfirming(false); }}
          className="rounded px-1 py-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim hover:text-ink-primary"
          aria-label="cancel delete"
        >
          ✕
        </button>
      </span>
    );
  }
  return (
    <button
      onClick={(e) => { e.stopPropagation(); setConfirming(true); }}
      className="shrink-0 rounded px-1 py-0.5 text-[calc(13px_*_var(--text-scale))] leading-none text-ink-dim hover:text-danger"
      aria-label={label}
      title={label}
    >
      ✕
    </button>
  );
}

function EngagementCard({
  eng,
  stat,
  isActive,
  compact,
  flash,
  onDelete,
}: {
  eng: Engagement;
  stat: EngStats | undefined;
  isActive: boolean;
  compact?: boolean;
  flash?: boolean;
  onDelete: (eng: Engagement) => void;
}) {
  const sm = STATUS_META[eng.status];
  // A freshly-created engagement briefly glows so the user sees where it landed.
  const flashRing = flash ? "ring-1 ring-accent" : "";

  // List mode — a slim single row.
  if (compact) {
    return (
      <GlassCard className={`p-0 ${flashRing}`} glowOnHover>
        <div className="flex items-center gap-3 px-[var(--row-px)] py-[var(--row-py)]">
          <StatusDot color={sm.color} static={!sm.pulse} />
          <span className="min-w-0 flex-1 truncate text-[length:var(--row-name)] font-semibold text-ink-primary">{eng.name}</span>
          {stat ? <div className="hidden items-center gap-1 sm:flex"><SevChips counts={stat.counts} /></div> : null}
          {stat?.coverage != null && (
            <span className="data hidden w-12 text-right text-[calc(11px_*_var(--text-scale))] text-ink-muted md:inline">{stat.coverage}%</span>
          )}
          <span className="hidden text-[calc(10.5px_*_var(--text-scale))] text-ink-dim lg:inline">{relTime(eng.updated_at)}</span>
          <Button variant={isActive ? "ghost" : "solid"} size="sm" onClick={() => openEngagement(eng.id, eng.name)}>
            Open
          </Button>
          <DeleteX onConfirm={() => onDelete(eng)} label={`Delete ${eng.name}`} />
        </div>
      </GlassCard>
    );
  }

  return (
    <GlassCard className={`p-0 ${flashRing}`} glowOnHover>
      <div className="flex h-full flex-col p-[var(--card-pad)]">
        {/* top row: status pill */}
        <div className="mb-2.5 flex items-center gap-2">
          {isActive && (
            <span className="inline-flex items-center gap-1 rounded-md border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[calc(9px_*_var(--text-scale))] font-bold uppercase tracking-wider text-accent">
              <Sparkle solid /> pinned
            </span>
          )}
          <span
            className="ml-auto inline-flex items-center gap-1.5 text-[calc(10.5px_*_var(--text-scale))] font-semibold"
            style={{ color: sm.color }}
          >
            <StatusDot color={sm.color} static={!sm.pulse} />
            {sm.label}
          </span>
          <DeleteX onConfirm={() => onDelete(eng)} label={`Delete ${eng.name}`} />
        </div>

        {/* name */}
        <div className="mb-2.5 truncate text-[length:var(--card-name)] font-bold text-ink-primary">
          {eng.name}
        </div>

        {/* coverage bar — only when we have a real number */}
        {stat?.coverage !== null && stat?.coverage !== undefined ? (
          <div className="mb-2">
            <div className="mb-1 flex items-center justify-between text-[calc(10.5px_*_var(--text-scale))] font-medium text-ink-dim">
              <span>Methodology coverage</span>
              <span className="data text-ink-muted">{stat.coverage}%</span>
            </div>
            <div className="h-[4px] overflow-hidden rounded-full bg-bg-base">
              <div
                className="h-full rounded-full bg-accent transition-[width]"
                style={{ width: `${stat.coverage}%` }}
              />
            </div>
          </div>
        ) : (
          <div className="mb-2 h-[4px]" aria-hidden />
        )}

        {/* finding chips */}
        <div className="mb-2 flex flex-wrap items-center gap-1.5">
          {stat ? (
            <SevChips counts={stat.counts} />
          ) : (
            <span className="text-[calc(10.5px_*_var(--text-scale))] text-ink-dim">loading…</span>
          )}
        </div>

        {/* footer: scope + last activity + Open */}
        <div className="mt-auto flex items-center gap-3 border-t border-divider pt-2.5">
          <div className="min-w-0 flex-1 text-[calc(10px_*_var(--text-scale))] text-ink-dim">
            <span className="uppercase tracking-wider">{eng.status}</span>
            <span className="mx-1.5" aria-hidden>
              ·
            </span>
            <span>updated {relTime(eng.updated_at)}</span>
          </div>
          <Button
            variant={isActive ? "ghost" : "solid"}
            size="sm"
            onClick={() => openEngagement(eng.id, eng.name)}
          >
            Open
          </Button>
        </div>
      </div>
    </GlassCard>
  );
}

// The design's prominent dashed "+ New Engagement" create card. It lives as
// the final cell of the engagement grid and opens the typed-create modal,
// which branches the form by engagement type (local-app / web-app).
function NewEngagementCard({ onOpenCreate }: { onOpenCreate: () => void }) {
  return (
    <button
      onClick={onOpenCreate}
      className="group flex min-h-[250px] flex-col items-center justify-center gap-3
                 rounded-xl border border-dashed border-divider p-5 text-center
                 transition-colors hover:border-accent"
    >
      <div
        className="flex h-11 w-11 items-center justify-center rounded-xl border border-divider
                   bg-bg-card text-[calc(26px_*_var(--text-scale))] font-light leading-none text-ink-dim
                   transition-colors group-hover:border-accent group-hover:text-accent"
        aria-hidden
      >
        +
      </div>
      <div className="text-[calc(13px_*_var(--text-scale))] font-bold text-ink-primary">
        Start new engagement
      </div>
      <div className="max-w-[260px] text-[calc(11px_*_var(--text-scale))] text-ink-dim">
        Choose a type — a local codebase or a web application — and we'll collect
        the right details.
      </div>
    </button>
  );
}

function EngagementGrid({
  engagements,
  stats,
  activeId,
  flashId,
  onOpenCreate,
  onDelete,
}: {
  engagements: Engagement[];
  stats: Record<string, EngStats>;
  activeId: string | null;
  flashId?: string | null;
  onOpenCreate: () => void;
  onDelete: (eng: Engagement) => void;
}) {
  const [mode] = useViewMode("engagements");
  const grid =
    mode === "list"
      ? "grid grid-cols-1 gap-2.5"
      : "grid gap-3 sm:grid-cols-2 lg:grid-cols-3";
  return (
    <div className="space-y-2.5">
      <div className="flex items-center justify-between">
        <span className="text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">Engagements</span>
        <ViewModeToggle storageKey="engagements" />
      </div>
      <div className={grid}>
        {engagements.map((eng) => (
          <EngagementCard
            key={eng.id}
            eng={eng}
            stat={stats[eng.id]}
            isActive={eng.id === activeId}
            compact={mode === "list"}
            flash={eng.id === flashId}
            onDelete={onDelete}
          />
        ))}
        <NewEngagementCard onOpenCreate={onOpenCreate} />
      </div>
    </div>
  );
}

// ── Getting-started hero ─────────────────────────────────────────────────────
// Shown on a true first run (no engagements yet) and re-summonable via the ⌘K
// "Show Getting Started" command. Replaces the wall-of-zeros with a focused
// next-action: create your first engagement, then run a tool.

function GettingStartedHero({
  firstRun,
  onCreate,
  onDismiss,
}: {
  firstRun: boolean;
  onCreate: () => void;
  onDismiss: () => void;
}) {
  return (
    <GlassCard className="p-0" glowOnHover>
      <div className="relative overflow-hidden p-6">
        <AsciiHero
          variant="bare"
          className="pointer-events-none absolute inset-0 opacity-[0.10]"
          aria-hidden
        />
        <div className="relative">
          <div className="flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <EyebrowPill icon={false} className="text-[calc(10px_*_var(--text-scale))]">
                {firstRun ? "welcome" : "getting started"}
              </EyebrowPill>
              <h2 className="mt-2 flex items-center gap-2 text-xl font-bold tracking-tight">
                <GradientText>Create your first engagement</GradientText>
                <Sparkle />
              </h2>
              <p className="mt-1.5 max-w-xl text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-primary">
                An engagement is your workspace — scope, targets, findings and
                coverage on one spine. Spin one up, then point a tool at it.
              </p>
            </div>
            <button
              onClick={onDismiss}
              className="shrink-0 rounded px-1.5 py-0.5 text-[calc(13px_*_var(--text-scale))] leading-none text-ink-dim hover:text-ink-primary"
              aria-label="Dismiss getting started"
              title="Dismiss"
            >
              ✕
            </button>
          </div>

          {/* Two ordered next-steps. */}
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <StepCard
              step={1}
              title="New engagement"
              hint="Choose a local codebase or a web app — we'll collect the right details."
              cta={
                <Button variant="solid" size="sm" onClick={onCreate}>
                  <Sparkle solid /> New Engagement
                </Button>
              }
            />
            <StepCard
              step={2}
              title="Run a tool"
              hint="Open the arsenal — ~38 tools share one panel; results stream live."
              cta={
                <Button variant="ghost" size="sm" onClick={openToolSearch}>
                  Run a tool →
                </Button>
              }
            />
          </div>
        </div>
      </div>
    </GlassCard>
  );
}

function StepCard({
  step,
  title,
  hint,
  cta,
}: {
  step: number;
  title: string;
  hint: string;
  cta: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-divider bg-bg-card p-4">
      <div className="flex items-center gap-2">
        <span
          className="data flex h-6 w-6 items-center justify-center rounded-full border border-accent/40 bg-accent/10 text-[calc(11px_*_var(--text-scale))] font-bold text-accent"
          aria-hidden
        >
          {step}
        </span>
        <span className="text-[calc(13px_*_var(--text-scale))] font-bold text-ink-primary">{title}</span>
      </div>
      <p className="text-[calc(11px_*_var(--text-scale))] leading-relaxed text-ink-dim">{hint}</p>
      <div className="mt-1">{cta}</div>
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
        <h2 className="mb-4 text-[calc(13px_*_var(--text-scale))] font-bold text-ink-primary">
          <GradientText static>Tools used</GradientText>
        </h2>
        {!ready ? (
          <div className="flex items-center gap-2 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
            <WibblingSpinner /> tallying findings…
          </div>
        ) : tools.length === 0 ? (
          <div className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">
            No findings yet.
          </div>
        ) : (
          <div className="space-y-3">
            {tools.map((t) => (
              <div key={t.name}>
                <div className="mb-1.5 flex items-center gap-2">
                  <span className="flex-1 truncate text-[calc(12.5px_*_var(--text-scale))] font-medium text-ink-primary">
                    {t.name}
                  </span>
                  <span
                    className="data text-[calc(11.5px_*_var(--text-scale))] font-semibold"
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
        <h2 className="mb-2 text-[calc(13px_*_var(--text-scale))] font-bold text-ink-primary">
          <GradientText static>Recent activity</GradientText>
        </h2>
        {!ready ? (
          <div className="flex items-center gap-2 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
            <WibblingSpinner /> loading activity…
          </div>
        ) : items.length === 0 ? (
          <div className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">
            No activity yet.
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
                  <div className="text-[calc(12.5px_*_var(--text-scale))] leading-snug text-ink-primary">
                    {it.text}
                  </div>
                  <div className="mt-0.5 truncate text-[calc(10.5px_*_var(--text-scale))] text-ink-dim">
                    {it.eng}
                  </div>
                </div>
                <div className="data shrink-0 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
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
          <EyebrowPill icon={false} className="text-[calc(10px_*_var(--text-scale))]">
            {eyebrow}
          </EyebrowPill>
          <h2 className="mt-1.5 text-[calc(15px_*_var(--text-scale))] font-bold text-ink-primary">
            <GradientText static>{title}</GradientText>
          </h2>
          <p className="mt-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim">{hint}</p>
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
        {/* Most-likely next action — run a tool — leads as a solid pill. */}
        <Button variant="solid" size="sm" onClick={openToolSearch}>
          Run a tool →
          <span className="ml-1.5 text-[calc(10px_*_var(--text-scale))] opacity-70">open the arsenal</span>
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => emit("openView", { view: "build" })}
        >
          Workbench
          <span className="ml-1.5 text-[calc(10px_*_var(--text-scale))] opacity-70">tools & playbooks</span>
        </Button>
        {QUICK_LINKS.map((l) => (
          <Button
            key={l.view}
            variant="ghost"
            size="sm"
            onClick={() => emit("openView", { view: l.view })}
          >
            {l.label}
            <span className="ml-1.5 text-[calc(10px_*_var(--text-scale))] opacity-70">{l.hint}</span>
          </Button>
        ))}
      </div>
    </Section>
  );
}
