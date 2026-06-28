import { useRef, useState } from "react";
import { StatCounter, WibblingSpinner } from "performative-ui";
import { authFetch, openWs, watchWsLiveness } from "../api";
import { getActiveEngagementId, recordResultIfActive } from "../lib/engagement";
import { record as recordSession } from "../lib/sessionLog";
import { pulse, failStamp } from "../lib/dopamine";
import { emit } from "../shell/bus";
import type { ResultRow, ToolDescriptor } from "../shell/tools";
import SectionLabel from "../shell/SectionLabel";

type RunState = "idle" | "running" | "done" | "error";

/**
 * The generic, descriptor-driven tool surface — one component for every Tier-1
 * tool, WS-streaming or one-shot HTTP. Form header on top, live result table
 * below. Replaces HackingPal's 79 bespoke page components.
 */
export default function ToolPanel({ tool }: { tool: ToolDescriptor }) {
  const initialForm: Record<string, string> = {};
  for (const f of tool.fields) initialForm[f.name] = f.default ?? "";

  const [form, setForm] = useState<Record<string, string>>(initialForm);
  const [state, setState] = useState<RunState>("idle");
  const [rows, setRows] = useState<ResultRow[]>([]);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [status, setStatus] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const watchRef = useRef<ReturnType<typeof watchWsLiveness> | null>(null);
  const runBtn = useRef<HTMLButtonElement | null>(null);

  const target = String(Object.values(form)[0] ?? "");

  function cleanup() {
    watchRef.current?.stop();
    watchRef.current = null;
    wsRef.current?.close();
    wsRef.current = null;
  }

  function stop() {
    try {
      wsRef.current?.send(JSON.stringify({ action: "stop" }));
    } catch {
      /* socket already closing */
    }
  }

  function finishOk(summary: string, raw: unknown) {
    setState("done");
    setStatus(summary);
    void pulse(runBtn.current ?? undefined);
    recordSession(tool.id, `${target}: ${summary}`);
    void recordResultIfActive(tool.id, target, summary, raw);
  }

  function finishErr(detail: string) {
    setState("error");
    setStatus(detail);
    void failStamp(runBtn.current ?? undefined);
  }

  /** Parse this run's output into asset-graph records → bus + backend (per scope). */
  function emitAssets(events: any[]) {
    if (!tool.parseAssets) return;
    let assets;
    try {
      assets = tool.parseAssets(events, target);
    } catch {
      return;
    }
    if (!assets?.length) return;
    const eid = getActiveEngagementId();
    const scopeKey = eid ? `eng:${eid}` : null;
    emit("assetDiscovered", { scopeKey, tool: tool.id, assets });
    if (scopeKey) {
      void authFetch("/method/assets/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scope_key: scopeKey, source_tool: tool.id, assets }),
      }).catch(() => {});
    }
  }

  async function runHttp(t: Extract<ToolDescriptor, { transport: "http" }>) {
    try {
      const json = await t.run(form);
      setRows(t.toRows(json));
      for (const o of t.toOutputs?.(json) ?? []) emit("output", { ...o, ts: Date.now(), tool: tool.id });
      emitAssets([json]);
      finishOk(t.doneText?.(json) ?? `${t.toRows(json).length} results`, json);
    } catch (e: any) {
      finishErr(e?.message || "request failed");
    }
  }

  function runWs(t: Extract<ToolDescriptor, { transport: "ws" }>) {
    const ws = openWs(t.wsPath);
    wsRef.current = ws;
    const events: any[] = [];
    ws.onopen = () =>
      ws.send(JSON.stringify({ ...t.buildInit(form), engagement_id: getActiveEngagementId() ?? undefined }));

    ws.onmessage = (e) => {
      let ev: any;
      try {
        ev = JSON.parse(e.data);
      } catch {
        return;
      }
      events.push(ev);
      const row = t.toRow(ev);
      if (row) setRows((r) => [...r, row]);
      const out = t.toOutput(ev);
      if (out) emit("output", { ...out, ts: Date.now(), tool: tool.id });
      if (ev.type === "progress") setProgress({ done: ev.done, total: ev.total });

      if (ev.type === "done") {
        emitAssets(events);
        finishOk(t.doneText?.(ev) ?? `${rows.length} results`, ev);
        cleanup();
      } else if (ev.type === "error") {
        finishErr(ev.detail || "error");
        cleanup();
      }
    };

    ws.onerror = () => {
      finishErr("connection error");
      cleanup();
    };

    watchRef.current = watchWsLiveness(ws, {
      connectMs: 5_000,
      idleMs: 60_000,
      onTimeout: (phase) => {
        finishErr(`timed out (${phase})`);
        cleanup();
      },
    });
  }

  function run() {
    const missing = tool.fields.find((f) => f.required && !form[f.name]?.trim());
    if (missing) {
      setStatus(`${missing.label} is required`);
      return;
    }
    setRows([]);
    setProgress(null);
    setStatus("");
    setState("running");
    if (tool.transport === "http") void runHttp(tool);
    else runWs(tool);
  }

  const streaming = tool.transport === "ws" && state === "running";

  return (
    <div className="flex h-full flex-col bg-bg-base text-ink-primary">
      <div className="flex flex-wrap items-end gap-3 border-b border-divider px-4 py-3">
        <SectionLabel>{tool.group}</SectionLabel>
        {tool.fields.map((f) =>
          f.type === "path" ? (
            <label key={f.name} className="flex flex-col gap-1 text-xs text-ink-muted">
              {f.label}
              <div className="flex gap-1.5">
                <input
                  className="w-64 rounded bg-bg-card px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
                  placeholder={f.placeholder}
                  value={form[f.name]}
                  onChange={(e) => setForm({ ...form, [f.name]: e.target.value })}
                />
                <button
                  type="button"
                  onClick={async () => {
                    const p = await (window as any).nt?.pickDirectory?.();
                    if (p) setForm({ ...form, [f.name]: p });
                  }}
                  className="rounded bg-bg-hover px-2 py-1 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary"
                >
                  Browse…
                </button>
              </div>
            </label>
          ) : f.type === "checkbox" ? (
            <label key={f.name} className="flex items-center gap-1.5 text-xs text-ink-muted">
              <input
                type="checkbox"
                checked={form[f.name] === "true"}
                onChange={(e) => setForm({ ...form, [f.name]: e.target.checked ? "true" : "" })}
              />
              {f.label}
            </label>
          ) : (
          <label key={f.name} className="flex flex-col gap-1 text-xs text-ink-muted">
            {f.label}
            {f.type === "select" ? (
              <select
                className="rounded bg-bg-card px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
                value={form[f.name]}
                onChange={(e) => setForm({ ...form, [f.name]: e.target.value })}
              >
                {f.options?.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            ) : (
              <input
                className="w-56 rounded bg-bg-card px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent"
                placeholder={f.placeholder}
                value={form[f.name]}
                onChange={(e) => setForm({ ...form, [f.name]: e.target.value })}
                onKeyDown={(e) => e.key === "Enter" && state !== "running" && run()}
              />
            )}
          </label>
        ))}
        <div className="ml-auto flex items-center gap-2">
          {streaming ? (
            <button ref={runBtn} onClick={stop} className="rounded bg-danger/20 px-3 py-1.5 text-sm font-medium text-danger ring-1 ring-danger/40 hover:bg-danger/30">
              Stop
            </button>
          ) : (
            <button ref={runBtn} onClick={run} disabled={state === "running"} className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:bg-accentBright disabled:opacity-50">
              Run
            </button>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3 px-4 py-1.5 text-xs text-ink-muted">
        {state === "running" && <WibblingSpinner />}
        <span>
          {rows.length > 0 && (
            <>
              <StatCounter target={rows.length} durationMs={500} /> result{rows.length === 1 ? "" : "s"}
            </>
          )}
        </span>
        {progress && <span className="text-ink-dim">{progress.done}/{progress.total}</span>}
        {status && <span className={state === "error" ? "text-danger" : "text-ink-dim"}>{status}</span>}
        {state === "done" && rows.length > 0 && (
          <button
            onClick={() =>
              emit("promote", {
                tool: tool.label,
                target,
                title: `${tool.label}: ${target}`,
                description: status,
                evidence: rows.map((r) => r.cols.join("  ")).join("\n").slice(0, 8000),
              })
            }
            className="ml-auto rounded px-2 py-0.5 text-xs text-accent ring-1 ring-accent/40 hover:bg-accent/10"
          >
            Promote → finding
          </button>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-auto px-2">
        {rows.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-ink-dim">
            {state === "running" ? "running…" : "Run to stream results."}
          </div>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 bg-bg-base text-xs uppercase text-ink-dim">
              <tr>
                {tool.columns.map((c) => (
                  <th key={c} className="px-2 py-1 font-medium">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="odd:bg-bg-card/40 hover:bg-bg-hover">
                  {r.cols.map((c, j) => (
                    <td key={j} className="px-2 py-1 font-mono text-ink-primary">{c}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
