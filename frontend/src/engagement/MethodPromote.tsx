import { useEffect, useMemo, useState } from "react";
import { on } from "../shell/bus";
import { authFetch } from "../api";
import {
  getActiveEngagementId,
  promoteToFinding,
  type FindingSeverity,
} from "../lib/engagement";
import { useSessionLog, type SessionEvent } from "../lib/sessionLog";

const SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

/**
 * MethodPromote — promote a contiguous run of session-log events into an
 * ordered, hash-chained Step chain on a freshly-created finding.
 *
 * INTEGRATION (integrator must wire):
 *   This modal opens on the bus event **`promoteSteps`** (no payload).
 *   `bus.ts` does not yet declare it. Add to the `Events` map in
 *   `src/shell/bus.ts`:
 *
 *       promoteSteps: Record<string, never>;
 *
 *   and emit it from wherever the "Promote steps to finding" affordance lives
 *   (e.g. a session-log toolbar button):  emit("promoteSteps", {}).
 *
 *   Until that key exists this file subscribes via a locally-typed cast so it
 *   stays `tsc --noEmit` clean on its own. Once the key is added, the cast is
 *   harmless. Mount <MethodPromote /> once near the app root (sibling of
 *   <PromoteModal />).
 *
 * Flow on confirm:
 *   1. promoteToFinding(...) against the active engagement → finding id.
 *   2. POST each selected event IN ORDER to /method/findings/{fid}/steps:
 *        action       = { tool_id: <event.category>, params: {} }
 *        evidence     = { raw_output: <event.summary>, timestamp: <event.ts> }
 *        interpretation = null            (left for Stage 4)
 *        links_from   = previous created step id  (chains 0..n)
 *        anchored     = false
 *   Backend assigns ordinals 0..n and hash-chains each row.
 */

// Locally-typed bus subscribe for the not-yet-declared `promoteSteps` event.
function onPromoteSteps(handler: () => void): () => void {
  return (on as unknown as (e: string, h: (p: unknown) => void) => () => void)(
    "promoteSteps",
    () => handler(),
  );
}

type StepResult = { id: string; ordinal: number };

export default function MethodPromote() {
  const log = useSessionLog();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<FindingSeverity>("medium");
  // Anchor selection: a contiguous [lo, hi] index range over the log snapshot
  // taken when the modal opened (so live record() churn doesn't shift it).
  const [frozen, setFrozen] = useState<SessionEvent[]>([]);
  const [lo, setLo] = useState<number | null>(null);
  const [hi, setHi] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [progress, setProgress] = useState("");

  useEffect(
    () =>
      onPromoteSteps(() => {
        setErr("");
        setProgress("");
        setTitle("");
        setSeverity("medium");
        setLo(null);
        setHi(null);
        // Freeze the current log (oldest→newest) for stable indexing.
        setFrozen(log.slice());
        setOpen(true);
      }),
    [log],
  );

  const selected = useMemo<SessionEvent[]>(() => {
    if (lo == null || hi == null) return [];
    const a = Math.min(lo, hi);
    const b = Math.max(lo, hi);
    return frozen.slice(a, b + 1);
  }, [frozen, lo, hi]);

  if (!open) return null;

  function toggle(i: number) {
    // Build a contiguous selection: first click sets an anchor; subsequent
    // clicks extend the range to the clicked row.
    if (lo == null || hi == null) {
      setLo(i);
      setHi(i);
      return;
    }
    if (i === lo && i === hi) {
      setLo(null);
      setHi(null);
      return;
    }
    setHi(i);
  }

  function inRange(i: number): boolean {
    if (lo == null || hi == null) return false;
    return i >= Math.min(lo, hi) && i <= Math.max(lo, hi);
  }

  async function confirm() {
    setErr("");
    const eid = getActiveEngagementId();
    if (!eid) {
      setErr("No active engagement — select or create one first.");
      return;
    }
    if (!title.trim()) {
      setErr("Give the finding a title.");
      return;
    }
    if (selected.length === 0) {
      setErr("Select at least one session event.");
      return;
    }
    setBusy(true);
    try {
      setProgress("Creating finding…");
      const first = selected[0];
      const finding = await promoteToFinding({
        engagement_id: eid,
        title: title.trim(),
        severity,
        description: `Method reconstructed from ${selected.length} session step(s).`,
        tool: first.category,
        target: "",
        evidence: selected.map((e) => `[${e.ts}] ${e.category}: ${e.summary}`).join("\n"),
      });

      // POST each event IN ORDER, chaining links_from to the prior step id.
      let prevStepId: string | null = null;
      for (let i = 0; i < selected.length; i++) {
        const ev = selected[i];
        setProgress(`Appending step ${i + 1}/${selected.length}…`);
        const res = await authFetch(`/method/findings/${finding.id}/steps`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: { tool_id: ev.category, params: {} },
            evidence: { raw_output: ev.summary, timestamp: ev.ts },
            interpretation: null,
            links_from: prevStepId,
            anchored: false,
          }),
        });
        if (!res.ok) {
          throw new Error(`step ${i} failed: HTTP ${res.status}`);
        }
        const step = (await res.json()) as StepResult;
        prevStepId = step.id;
      }
      setProgress("");
      setOpen(false);
    } catch (e: any) {
      setErr(e?.message || "failed to promote steps");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={() => !busy && setOpen(false)}
    >
      <div
        className="flex max-h-[80vh] w-[40rem] flex-col rounded-lg bg-bg-card p-4 shadow-2xl ring-1 ring-divider"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 text-sm font-semibold text-ink-primary">
          Promote steps to finding
        </div>
        <div className="mb-3 text-xs text-ink-dim">
          Select a contiguous run of session events; each becomes an ordered, hash-chained Step.
        </div>

        <div className="mb-3 flex gap-3">
          <label className="flex-1 text-xs text-ink-muted">
            Title
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Finding title"
              className="mt-1 w-full rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
            />
          </label>
          <label className="text-xs text-ink-muted">
            Severity
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as FindingSeverity)}
              className="mt-1 block rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>
        </div>

        <div className="mb-2 text-xs text-ink-muted">
          Session log ({selected.length} selected)
        </div>
        <div className="mb-3 min-h-0 flex-1 overflow-auto rounded ring-1 ring-divider">
          {frozen.length === 0 ? (
            <div className="p-3 text-xs text-ink-dim">No session events recorded yet.</div>
          ) : (
            <ul className="divide-y divide-divider">
              {frozen.map((e, i) => {
                const sel = inRange(i);
                return (
                  <li
                    key={`${e.ts}-${i}`}
                    onClick={() => toggle(i)}
                    className={
                      "cursor-pointer px-2 py-1.5 text-xs " +
                      (sel ? "bg-accent/10 text-ink-primary" : "text-ink-muted hover:bg-bg-base")
                    }
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={
                          "inline-block h-2 w-2 shrink-0 rounded-full " +
                          (sel ? "bg-accent" : "bg-divider")
                        }
                      />
                      <span className="font-mono text-ink-dim">{e.ts}</span>
                      <span className="truncate font-medium text-ink-primary">{e.category}</span>
                    </div>
                    <div className="ml-4 truncate font-mono text-[11px] text-ink-dim">
                      {e.summary}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {err && <div className="mb-2 text-xs text-danger">{err}</div>}
        {progress && !err && <div className="mb-2 text-xs text-ink-muted">{progress}</div>}

        <div className="flex justify-end gap-2">
          <button
            onClick={() => !busy && setOpen(false)}
            className="rounded px-3 py-1.5 text-sm text-ink-muted hover:text-ink-primary"
          >
            Cancel
          </button>
          <button
            onClick={confirm}
            disabled={busy || selected.length === 0}
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:bg-accentBright disabled:opacity-50"
          >
            {busy ? "Promoting…" : `Promote ${selected.length || ""} step${selected.length === 1 ? "" : "s"}`}
          </button>
        </div>
      </div>
    </div>
  );
}
