// Workbench tab — where an armed pairing (engagement × sub-target) runs.
//
// Pick a sub-target, run a tool, watch the output. Only an armed sub-target
// runs: an un-armed one is refused server-side (the run still goes to the
// backend, which returns 403 SUBTARGET_UNARMED — we surface that message rather
// than hiding the affordance, so the gate is visibly server-enforced).
//
// A confirmed run can be promoted into a finding, which is born tagged with the
// engagement × sub-target pairing.
import { useEffect, useMemo, useRef, useState } from "react";
import { Button, Sparkle, StatusDot } from "performative-ui";
import Icon from "../shell/Icon";
import { isApiError } from "../api";
import { failStamp, inkConfirm, radarSweep } from "../lib/dopamine";
import { FINDING_SEVERITIES, type FindingSeverity } from "../lib/engagement";
import {
  createPairingFinding,
  runPairing,
  type SubTarget,
  type Target,
} from "../lib/spine";

type FlatSub = SubTarget & { targetName: string; targetId: string };

type ConsoleLine = { level: "cmd" | "out" | "err" | "ok"; text: string };

export default function WorkbenchTab({
  targets,
  onError,
}: {
  targets: Target[];
  onError: (m: string) => void;
}) {
  const allSubs = useMemo<FlatSub[]>(
    () =>
      targets.flatMap((t) =>
        (t.sub_targets ?? []).map((s) => ({ ...s, targetName: t.name, targetId: t.id })),
      ),
    [targets],
  );
  const armed = allSubs.filter((s) => s.armed);

  const [selId, setSelId] = useState<string | null>(armed[0]?.id ?? null);
  useEffect(() => {
    if (!allSubs.some((s) => s.id === selId)) setSelId(armed[0]?.id ?? allSubs[0]?.id ?? null);
  }, [allSubs, armed, selId]);

  const sel = allSubs.find((s) => s.id === selId) ?? null;
  const [tool, setTool] = useState("connect");
  const [lines, setLines] = useState<ConsoleLine[]>([]);
  const [running, setRunning] = useState(false);
  const [lastOk, setLastOk] = useState(false);
  const runBtn = useRef<HTMLButtonElement>(null);

  // Reset the console when the selection changes.
  useEffect(() => {
    setLines([]);
    setLastOk(false);
  }, [selId]);

  async function onRun() {
    if (!sel) return;
    setRunning(true);
    setLastOk(false);
    void radarSweep(runBtn.current ?? undefined); // sweeping the target
    setLines((l) => [...l, { level: "cmd", text: `> run ${tool} @ ${sel.address}` }]);
    try {
      const run = await runPairing(sel, tool);
      const outLines = (run.output || "").split("\n").filter(Boolean);
      setLines((l) => [
        ...l,
        ...outLines.map((t) => ({ level: "out" as const, text: t })),
        { level: "ok", text: `— ${run.status}: ${run.summary} (engagement ${run.engagement_id.slice(0, 8)})` },
      ]);
      setLastOk(run.status === "completed");
    } catch (e) {
      const msg = isApiError(e) ? e.message : e instanceof Error ? e.message : String(e);
      const refused = isApiError(e) && e.status === 403;
      void failStamp(runBtn.current ?? undefined); // gate said no
      setLines((l) => [
        ...l,
        { level: "err", text: refused ? `REFUSED (server-side): ${msg}` : `error: ${msg}` },
      ]);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex h-full min-h-0">
      {/* Left — runnable sub-targets */}
      <aside className="flex w-72 shrink-0 flex-col border-r border-divider">
        <div className="shrink-0 border-b border-divider px-3 py-2.5 text-[11px] uppercase tracking-wide text-ink-dim">
          Armed pairings
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {allSubs.length === 0 && (
            <div className="p-4 text-[12px] text-ink-dim">
              No sub-targets. Declare some in Targets, then arm them.
            </div>
          )}
          {allSubs.map((s) => {
            const active = s.id === selId;
            return (
              <button
                key={s.id}
                onClick={() => setSelId(s.id)}
                className={`flex w-full flex-col gap-1 border-b border-divider/60 px-3 py-2.5 text-left ${
                  active ? "bg-bg-hover" : "hover:bg-bg-hover/50"
                } ${s.armed ? "" : "opacity-60"}`}
              >
                <div className="flex items-center gap-2">
                  <Icon name={s.armed ? "shield" : "box"} size={13} />
                  <span className="truncate font-mono text-[12px] text-ink-primary">{s.address}</span>
                </div>
                <span className="text-[11px] text-ink-dim">
                  {s.targetName} · {s.armed ? <span className="text-accent">armed</span> : "un-armed"}
                </span>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Right — run console */}
      <section className="flex min-w-0 flex-1 flex-col">
        {!sel ? (
          <div className="p-6 text-sm text-ink-dim">Select a sub-target.</div>
        ) : (
          <>
            <div className="shrink-0 border-b border-divider p-4">
              <div className="flex items-center gap-2">
                <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[10px] text-ink-muted ring-1 ring-divider">
                  {sel.type}
                </span>
                <span className="font-mono text-[13px] text-ink-primary">{sel.address}</span>
                {sel.armed ? (
                  <span className="flex items-center gap-1.5 text-[11px] text-accent">
                    <StatusDot color="var(--accent)" /> armed by {sel.arming?.engagement_name ?? "engagement"}
                  </span>
                ) : (
                  <span className="text-[11px] text-high">un-armed — running will be refused</span>
                )}
              </div>
              <div className="mt-3 flex items-center gap-2">
                <input
                  value={tool}
                  onChange={(e) => setTool(e.target.value)}
                  className="w-40 rounded-md border border-divider bg-bg-base px-2 py-1.5 text-[12px] text-ink-primary outline-none focus:border-accent/50"
                />
                <Button ref={runBtn} variant="solid" size="sm" onClick={onRun} disabled={running}>
                  <Icon name="terminal" size={13} /> {running ? "Running…" : "Run"}
                </Button>
              </div>
            </div>

            {/* Console */}
            <div className="min-h-0 flex-1 overflow-auto bg-bg-base p-4 font-mono text-[12px] leading-relaxed">
              {lines.length === 0 ? (
                <div className="text-ink-dim">No output yet — run the pairing.</div>
              ) : (
                lines.map((l, i) => (
                  <div
                    key={i}
                    className={
                      l.level === "cmd"
                        ? "text-ink-muted"
                        : l.level === "err"
                          ? "text-critical"
                          : l.level === "ok"
                            ? "text-accent"
                            : "text-ink-primary"
                    }
                  >
                    {l.text}
                  </div>
                ))
              )}
            </div>

            {/* Promote to finding (only meaningful for an armed pairing) */}
            {sel.armed && lastOk && (
              <PromoteFinding
                sub={sel}
                onError={onError}
                onDone={() =>
                  setLines((l) => [...l, { level: "ok", text: "✓ finding created from this pairing" }])
                }
              />
            )}
          </>
        )}
      </section>
    </div>
  );
}

function PromoteFinding({
  sub,
  onError,
  onDone,
}: {
  sub: FlatSub;
  onError: (m: string) => void;
  onDone: () => void;
}) {
  const [title, setTitle] = useState("");
  const [sev, setSev] = useState<FindingSeverity>("medium");
  const [busy, setBusy] = useState(false);

  async function onCreate() {
    if (!title.trim()) return;
    setBusy(true);
    try {
      await createPairingFinding({
        sub_target_id: sub.id,
        title: title.trim(),
        severity: sev,
        tool: "spine-workbench",
        evidence: `Pairing run against ${sub.address}`,
      });
      setTitle("");
      onDone();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="shrink-0 border-t border-divider bg-bg-surface p-3">
      <div className="mb-2 flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-ink-dim">
        <Icon name="flag" size={13} /> Promote to finding
      </div>
      <div className="flex items-center gap-2">
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onCreate()}
          placeholder="Finding title"
          className="flex-1 rounded-md border border-divider bg-bg-base px-2 py-1.5 text-[12px] text-ink-primary outline-none focus:border-accent/50"
        />
        <select
          value={sev}
          onChange={(e) => setSev(e.target.value as FindingSeverity)}
          className="rounded-md border border-divider bg-bg-base px-2 py-1.5 text-[12px] text-ink-primary outline-none focus:border-accent/50"
        >
          {FINDING_SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <Button
          variant="solid"
          size="sm"
          disabled={busy || !title.trim()}
          onClick={(e) => { void inkConfirm(e.currentTarget); onCreate(); }}
        >
          <Sparkle solid /> Create
        </Button>
      </div>
    </div>
  );
}
