/**
 * F1 — Engagement-wide search.
 *
 * A search surface scoped to the ACTIVE engagement. It fetches (through the
 * read-only model API only) the engagement's findings, assets, evidence steps,
 * run output, and — when the engagement has a source_root — SAST code hits, then
 * groups + ranks them against a debounced query using the pure logic in
 * ./searchLogic. Every row is clickable and BROADCASTS the matching canonical
 * selection event (`source: "search"`); it never calls into another panel.
 *
 * Read-only by contract: search never arms a sub-target and never triggers a
 * tool run. The only network call it makes that touches source is POST
 * /codescan, which is a pure local pattern scan (no code execution).
 *
 * Self-registers its view + command at import time (mirrors echo/EchoPanel).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import {
  getActiveEngagementId, useActiveEngagementId,
} from "../../lib/engagement";
import { severityTextClass } from "../../lib/severity";
import {
  getEngagement, listFindings, listAssets, getEvidenceChain, listRuns, scanSource,
  type PairingFinding, type Asset, type Step, type PairingRun,
} from "../../shell/model";
import {
  groupSearch, countRows,
  type SearchGroup, type SearchRow, type CodeHit, type SearchGroupKind,
} from "./searchLogic";

const SOURCE = "search";
const DEBOUNCE_MS = 200;
const MAX_EVIDENCE_FINDINGS = 40; // cap evidence-chain fanout on huge engagements

// The already-fetched corpus for the active engagement. Re-fetched when the
// engagement changes or the model mutates — never cached across engagements.
type Corpus = {
  findings: PairingFinding[];
  assets: Asset[];
  evidence: { findingId: string; step: Step }[];
  runs: PairingRun[];
  code: CodeHit[] | undefined; // undefined = no source_root (Code group omitted)
};

const EMPTY_CORPUS: Corpus = { findings: [], assets: [], evidence: [], runs: [], code: undefined };

// ── Fetch the engagement's searchable corpus ──────────────────────────────────

async function fetchCorpus(eid: string): Promise<Corpus> {
  // Findings drive everything else (assets are scoped per sub-target; evidence
  // is per finding), so fetch them first.
  const findings = await listFindings(eid);

  // Sub-target set from the findings' provenance (stays within the model API;
  // assets are always scope-relative to a sub-target).
  const subIds = Array.from(
    new Set(findings.map((f) => f.sub_target_id).filter(Boolean)),
  );

  const [assetsPerSub, runs] = await Promise.all([
    Promise.all(
      subIds.map((sid) => listAssets({ subTargetId: sid }).catch(() => [] as Asset[])),
    ),
    listRuns(eid).catch(() => [] as PairingRun[]),
  ]);
  const assets = assetsPerSub.flat();

  // Evidence chains, fanned out over the engagement's findings (capped).
  const evidence: { findingId: string; step: Step }[] = [];
  const evFindings = findings.slice(0, MAX_EVIDENCE_FINDINGS);
  const chains = await Promise.all(
    evFindings.map((f) =>
      getEvidenceChain(f.id).then((c) => ({ fid: f.id, steps: c.steps })).catch(() => ({ fid: f.id, steps: [] as Step[] })),
    ),
  );
  for (const { fid, steps } of chains) {
    for (const step of steps) evidence.push({ findingId: fid, step });
  }

  // Code: only when the engagement declares a source_root. A pure local SAST
  // walk (read-only, no code execution) via the model seam. Absent source_root
  // OR a reachable-but-failed scan → Code group omitted gracefully (undefined);
  // a successful-but-empty scan → [] (group shown, no hits).
  let code: CodeHit[] | undefined;
  const eng = await getEngagement(eid).catch(() => null);
  const root = eng?.source_root?.trim();
  if (root) code = (await scanSource(root)) ?? undefined;

  return { findings, assets, evidence, runs, code };
}

// ── Selection publisher ───────────────────────────────────────────────────────

function publish(row: SearchRow): void {
  const s = row.select;
  switch (s.kind) {
    case "finding":
      emit("selectFinding", { ref: s.ref, source: SOURCE });
      break;
    case "asset":
      emit("selectAsset", { ref: s.ref, source: SOURCE });
      break;
    case "step":
      emit("selectStep", { ref: { findingId: s.findingId, stepId: s.stepId }, source: SOURCE });
      break;
    case "anchor":
      if (s.file) {
        emit("selectAnchor", { ref: { kind: "file", file: s.file, line: s.line }, source: SOURCE });
      }
      break;
  }
}

// ── Panel ─────────────────────────────────────────────────────────────────────

type LoadState = "idle" | "loading" | "ready" | "error";

function SearchPanel(_props: { params: ViewParams }) {
  const activeId = useActiveEngagementId();
  const [raw, setRaw] = useState("");
  const [query, setQuery] = useState(""); // debounced
  const [corpus, setCorpus] = useState<Corpus>(EMPTY_CORPUS);
  const [state, setState] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  // Bumped by modelChanged so we re-fetch the corpus on any mutation.
  const [rev, setRev] = useState(0);

  // Debounce the raw input into `query` (~200ms).
  useEffect(() => {
    const h = setTimeout(() => setQuery(raw), DEBOUNCE_MS);
    return () => clearTimeout(h);
  }, [raw]);

  // Fetch the corpus whenever the active engagement (or model revision) changes.
  useEffect(() => {
    let alive = true;
    if (!activeId) {
      setCorpus(EMPTY_CORPUS);
      setState("idle");
      setError(null);
      return;
    }
    setState("loading");
    setError(null);
    (async () => {
      try {
        const c = await fetchCorpus(activeId);
        if (alive) {
          setCorpus(c);
          setState("ready");
        }
      } catch (e) {
        if (alive) {
          setError(e instanceof Error ? e.message : String(e));
          setState("error");
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeId, rev]);

  // Re-read on any model mutation (no private cache of shared state).
  useBus("modelChanged", () => setRev((n) => n + 1));

  // Compute groups purely from the fetched corpus + debounced query.
  const groups: SearchGroup[] = useMemo(
    () =>
      groupSearch(query, {
        findings: corpus.findings,
        assets: corpus.assets,
        evidence: corpus.evidence,
        runs: corpus.runs,
        code: corpus.code,
      }),
    [query, corpus],
  );

  const onRowClick = useCallback((row: SearchRow) => publish(row), []);

  // Focus the input when the panel opens.
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const hasQuery = query.trim().length > 0;
  const total = countRows(groups);

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      {/* Search bar */}
      <div className="border-b border-divider px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
            Search
          </span>
          {state === "loading" && (
            <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">indexing…</span>
          )}
        </div>
        <input
          ref={inputRef}
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          placeholder="Search findings, assets, evidence, output, code…"
          disabled={!activeId}
          className="mt-2 w-full rounded-md border border-divider bg-bg-card px-3 py-2 text-[calc(13px_*_var(--text-scale))] text-ink-primary placeholder:text-ink-dim outline-none focus:border-accent disabled:opacity-50"
        />
        {activeId && hasQuery && state === "ready" && (
          <div className="mt-1 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
            {total} result{total === 1 ? "" : "s"} across {groups.length} group
            {groups.length === 1 ? "" : "s"}
          </div>
        )}
      </div>

      {/* Body */}
      <div className="min-h-0 flex-1 overflow-auto">
        {!activeId ? (
          <Prompt
            title="No engagement selected"
            body="Pick an active engagement first — search is scoped to the engagement under test."
          />
        ) : state === "error" ? (
          <Prompt
            title="Search failed"
            body={error ?? "Could not load the engagement's searchable data."}
            danger
          />
        ) : !hasQuery ? (
          <Prompt
            title="Type to search this engagement"
            body="Matches across Findings, Assets, Evidence, Output, and Code (when a source root is set)."
          />
        ) : state === "loading" ? (
          <Prompt title="Indexing engagement…" body="Loading findings, assets, evidence, and output." />
        ) : total === 0 ? (
          <Prompt title="No results" body={`Nothing matched “${query.trim()}”.`} />
        ) : (
          <div className="p-3">
            {groups.map((g) => (
              <GroupSection key={g.kind} group={g} onRowClick={onRowClick} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Presentational bits ───────────────────────────────────────────────────────

function Prompt({ title, body, danger }: { title: string; body: string; danger?: boolean }) {
  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center gap-2 p-8 text-center">
      <div
        className={
          "text-[calc(14px_*_var(--text-scale))] " +
          (danger ? "text-danger" : "text-ink-primary")
        }
      >
        {title}
      </div>
      <p className="max-w-md text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-dim">
        {body}
      </p>
    </div>
  );
}

const GROUP_ICON: Record<SearchGroupKind, string> = {
  findings: "◆",
  assets: "▣",
  evidence: "◇",
  output: "▷",
  code: "‹›",
};

function GroupSection({
  group,
  onRowClick,
}: {
  group: SearchGroup;
  onRowClick: (row: SearchRow) => void;
}) {
  return (
    <div className="mb-4">
      <div className="mb-1 flex items-center gap-2 px-1 text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
        <span className="text-ink-muted">{GROUP_ICON[group.kind]}</span>
        <span>{group.label}</span>
        <span className="text-ink-dim">({group.rows.length})</span>
      </div>
      <div className="flex flex-col gap-1">
        {group.rows.map((row) => (
          <ResultRow key={row.id} row={row} onClick={() => onRowClick(row)} />
        ))}
      </div>
    </div>
  );
}

function ResultRow({ row, onClick }: { row: SearchRow; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full rounded-md border border-transparent bg-bg-card px-3 py-2 text-left hover:border-divider hover:bg-bg-card/80"
    >
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-[calc(13px_*_var(--text-scale))] text-ink-primary">
          {row.title}
        </span>
        {row.badge && (
          <span
            className={
              "shrink-0 rounded px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide " +
              (row.group === "findings" || row.group === "code"
                ? severityTextClass(row.badge)
                : "text-ink-muted")
            }
          >
            {row.badge}
          </span>
        )}
        {row.conf && (
          <span
            className={
              "shrink-0 rounded px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide " +
              (row.conf === "confirmed" ? "text-success" : "text-medium")
            }
            title={row.conf === "confirmed" ? "Confirmed" : "Suspected (not confirmed)"}
          >
            {row.conf}
          </span>
        )}
      </div>
      {row.subtitle && (
        <div className="mt-0.5 truncate font-mono text-[calc(11px_*_var(--text-scale))] text-ink-muted">
          {row.subtitle}
        </div>
      )}
      {row.snippet && (
        <div className="mt-1 line-clamp-2 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-dim">
          {row.snippet}
        </div>
      )}
    </button>
  );
}

// ── Registration (runs at import; mirrors echo/EchoPanel) ─────────────────────

registerView({ id: "search", component: SearchPanel });
registerCommand({
  id: "search.engagement",
  title: "Search this engagement",
  keywords: ["search", "find", "engagement"],
  binding: "⌘⇧F", // display-only per contract; Foundation owns the real keymap
  context: "View",
  run: () => {
    // Read-only: opening the panel never runs a tool. Guard is informational —
    // the panel itself handles the no-engagement state gracefully.
    void getActiveEngagementId();
    emit("openView", { view: "search" });
  },
});

export default SearchPanel;
