import { useRef, useState } from "react";
import { sidecarExec, type LabMeta, type SidecarResult } from "./labApi";

type Entry = { cmd: string; result?: SidecarResult; running?: boolean; error?: string };

/**
 * A command console bound to a lab's scanner sidecar. This is NOT a PTY — the
 * backend (POST /labs/{id}/sidecar/exec) runs one whitelisted, positional-only
 * command per call via `docker exec` (no shell), so this is a request/response
 * command log. Option flags (`-x`) and shell metacharacters are rejected
 * server-side; we surface those rejections verbatim rather than pretend.
 */
export default function LabConsole({ lab }: { lab: LabMeta }) {
  const [line, setLine] = useState("");
  const [log, setLog] = useState<Entry[]>([]);
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement | null>(null);

  async function run(raw?: string) {
    const text = (raw ?? line).trim();
    if (!text || busy) return;
    const parts = text.split(/\s+/);
    const cmd = parts[0];
    const args = parts.slice(1);
    setLine("");
    setBusy(true);
    const idx = log.length;
    setLog((l) => [...l, { cmd: text, running: true }]);
    try {
      const result = await sidecarExec(lab.id, cmd, args);
      setLog((l) => l.map((e, i) => (i === idx ? { cmd: text, result } : e)));
    } catch (e: any) {
      setLog((l) => l.map((e2, i) => (i === idx ? { cmd: text, error: e?.message || "request failed" } : e2)));
    } finally {
      setBusy(false);
      setTimeout(() => endRef.current?.scrollIntoView({ block: "end" }), 0);
    }
  }

  return (
    <div className="flex h-full flex-col rounded-lg border border-divider bg-bg-base">
      <div className="flex items-center gap-2 border-b border-divider px-3 py-1.5 text-[11px] text-ink-dim">
        <span className="font-mono text-accent">sidecar</span>
        <span>positional commands only — flags &amp; shell metacharacters are blocked</span>
      </div>

      {/* Allowed-command chips. */}
      {lab.sidecar_cmds.length > 0 && (
        <div className="flex flex-wrap gap-1.5 border-b border-divider px-3 py-2">
          {lab.sidecar_cmds.map((c) => (
            <button
              key={c}
              onClick={() => setLine((s) => (s ? s : c + " "))}
              className="rounded-md border border-divider bg-bg-surface px-2 py-0.5 font-mono text-[11px] text-ink-muted hover:border-accent hover:text-accent"
            >
              {c}
            </button>
          ))}
        </div>
      )}

      {/* Scrollback. */}
      <div className="min-h-0 flex-1 overflow-auto px-3 py-2 font-mono text-[12px] leading-relaxed">
        {log.length === 0 ? (
          <div className="text-ink-dim">No commands run yet.</div>
        ) : (
          log.map((e, i) => (
            <div key={i} className="mb-2">
              <div className="text-accent">$ {e.cmd}</div>
              {e.running && <div className="text-ink-dim">running…</div>}
              {e.error && <div className="text-danger">⚠ {e.error}</div>}
              {e.result && (
                <>
                  {e.result.stdout && <pre className="whitespace-pre-wrap text-ink-primary">{e.result.stdout}</pre>}
                  {e.result.stderr && <pre className="whitespace-pre-wrap text-amber">{e.result.stderr}</pre>}
                  {e.result.rc !== 0 && (
                    <div className="text-ink-dim">exit {e.result.rc}</div>
                  )}
                </>
              )}
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>

      {/* Input. */}
      <div className="flex items-center gap-2 border-t border-divider px-3 py-2">
        <span className="font-mono text-accent">$</span>
        <input
          value={line}
          onChange={(e) => setLine(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder={lab.sidecar_cmds[0] ? `${lab.sidecar_cmds[0]} <target>` : "command target"}
          disabled={busy}
          className="flex-1 bg-transparent font-mono text-[12px] text-ink-primary outline-none placeholder:text-ink-dim"
        />
        <button
          onClick={() => run()}
          disabled={busy}
          className="rounded-md bg-accent px-2.5 py-1 text-[11px] font-semibold text-bg-base disabled:opacity-50"
        >
          Run
        </button>
      </div>
    </div>
  );
}
