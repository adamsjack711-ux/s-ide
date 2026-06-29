// TerminalView — a basic single-shot terminal (opened from the bottom-left
// terminal icon in the ActivityBar).
//
// One command per request via POST /terminal/exec (backend: routers/terminal.py
// — localhost + token + engagement/lab gated; NOT a PTY, no interactive state).
// `cd` is handled server-side and updates the working directory.
//
// "Baked-in tools": a row of quick-run chips drops a ready-to-edit command for
// the common recon binaries into the prompt so they're one keystroke from
// running. Edit the target, hit Enter.

import { useEffect, useRef, useState } from "react";

import { authFetch } from "../api";
import Icon from "./Icon";

type Line = { kind: "cmd" | "out" | "err" | "info"; text: string };

type ExecResponse = {
  cwd: string;
  cmd: string;
  returncode: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
};

// Baked-in tools — real CLI binaries, ready to edit + run. The backend runs ONE
// program per command (no shell), so every entry is a single invocation — no
// pipes, redirects, or && chaining.
const QUICK: { label: string; cmd: string }[] = [
  { label: "whois", cmd: "whois example.com" },
  { label: "dig", cmd: "dig +short example.com" },
  { label: "host", cmd: "host example.com" },
  { label: "ping", cmd: "ping -c 4 1.1.1.1" },
  { label: "nmap", cmd: "nmap -F 127.0.0.1" },
  { label: "curl headers", cmd: "curl -sSI https://example.com" },
  { label: "tls cert", cmd: "nmap -p 443 --script ssl-cert example.com" },
];

export default function TerminalView() {
  const [cwd, setCwd] = useState("~");
  const [lines, setLines] = useState<Line[]>([
    { kind: "info", text: "s-ide terminal — runs one program per command (not a shell: no pipes, &&, or redirects). Try a baked-in tool below, or type a command. `clear` to reset." },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [hIdx, setHIdx] = useState(-1);

  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Initial working directory.
  useEffect(() => {
    let alive = true;
    authFetch("/terminal/cwd")
      .then((r) => (r.ok ? r.json() : null))
      .then((b) => alive && b?.cwd && setCwd(b.cwd))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  // Keep the view pinned to the latest output.
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [lines]);

  function push(...l: Line[]) {
    setLines((prev) => [...prev, ...l]);
  }

  async function run(raw: string) {
    const command = raw.trim();
    if (!command || busy) return;
    setHistory((h) => [command, ...h].slice(0, 100));
    setHIdx(-1);
    setInput("");

    if (command === "clear" || command === "cls") {
      setLines([]);
      return;
    }

    push({ kind: "cmd", text: `${shortCwd(cwd)} $ ${command}` });
    setBusy(true);
    try {
      const r = await authFetch("/terminal/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command, cwd }),
      });
      if (!r.ok) {
        let detail = `HTTP ${r.status}`;
        try {
          const b = await r.json();
          detail = b?.error || b?.detail || detail;
        } catch {
          /* keep status */
        }
        const hint =
          r.status === 403 || /engagement/i.test(detail)
            ? " — an active engagement (or lab mode) is required to run commands."
            : "";
        push({ kind: "err", text: `${detail}${hint}` });
        return;
      }
      const res = (await r.json()) as ExecResponse;
      setCwd(res.cwd);
      if (res.stdout) push(...res.stdout.replace(/\n$/, "").split("\n").map((t) => ({ kind: "out" as const, text: t })));
      if (res.stderr) push(...res.stderr.replace(/\n$/, "").split("\n").map((t) => ({ kind: "err" as const, text: t })));
      if (!res.stdout && !res.stderr) push({ kind: "info", text: res.returncode === 0 ? "(no output)" : `exited ${res.returncode}` });
      if (res.truncated) push({ kind: "info", text: "… output truncated (256 KB cap)" });
    } catch (e) {
      push({ kind: "err", text: e instanceof Error ? e.message : "request failed (is the backend running?)" });
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  }

  function loadQuick(cmd: string) {
    setInput(cmd);
    inputRef.current?.focus();
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.min(hIdx + 1, history.length - 1);
      if (next >= 0) {
        setHIdx(next);
        setInput(history[next]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = hIdx - 1;
      setHIdx(next);
      setInput(next >= 0 ? history[next] : "");
    }
  }

  return (
    <div className="flex h-full flex-col bg-bg-base" onClick={() => inputRef.current?.focus()}>
      <header className="flex shrink-0 items-center gap-2 border-b border-divider px-4 py-2.5">
        <Icon name="terminal" size={16} />
        <span className="text-sm font-bold tracking-tight text-ink-primary">Terminal</span>
        <span className="shrink-0 rounded bg-amber/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-amber ring-1 ring-amber/30">
          WIP
        </span>
        <span className="truncate font-mono text-[11px] text-ink-dim">{cwd}</span>
        <button
          onClick={(e) => {
            e.stopPropagation();
            setLines([]);
          }}
          className="ml-auto rounded bg-bg-card px-2 py-1 text-[11px] text-ink-muted ring-1 ring-divider hover:text-ink-primary"
        >
          Clear
        </button>
      </header>

      {/* Baked-in tools */}
      <div className="flex shrink-0 flex-wrap items-center gap-1.5 border-b border-divider px-4 py-2">
        <span className="mr-1 text-[10px] uppercase tracking-wide text-ink-dim">Tools</span>
        {QUICK.map((q) => (
          <button
            key={q.label}
            onClick={(e) => {
              e.stopPropagation();
              loadQuick(q.cmd);
            }}
            title={q.cmd}
            className="rounded bg-bg-card px-2 py-0.5 font-mono text-[11px] text-ink-muted ring-1 ring-divider hover:text-accent hover:ring-accent/40"
          >
            {q.label}
          </button>
        ))}
      </div>

      {/* Scrollback */}
      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto px-4 py-2 font-mono text-[12px] leading-relaxed">
        {lines.map((l, i) => (
          <div
            key={i}
            className={
              l.kind === "cmd"
                ? "text-accent"
                : l.kind === "err"
                  ? "whitespace-pre-wrap text-danger"
                  : l.kind === "info"
                    ? "text-ink-dim"
                    : "whitespace-pre-wrap text-ink-muted"
            }
          >
            {l.text}
          </div>
        ))}
        {busy && <div className="text-ink-dim">running…</div>}
      </div>

      {/* Prompt */}
      <div className="flex shrink-0 items-center gap-2 border-t border-divider px-4 py-2.5 font-mono text-[12px]">
        <span className="shrink-0 text-accent">{shortCwd(cwd)} $</span>
        <input
          ref={inputRef}
          value={input}
          autoFocus
          spellCheck={false}
          disabled={busy}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void run(input);
            else onKeyDown(e);
          }}
          placeholder="type a command and press Enter"
          className="min-w-0 flex-1 bg-transparent text-ink-primary outline-none placeholder:text-ink-dim"
        />
      </div>
    </div>
  );
}

function shortCwd(cwd: string): string {
  const home = cwd.match(/^\/Users\/[^/]+/)?.[0] ?? cwd.match(/^\/home\/[^/]+/)?.[0];
  const short = home ? cwd.replace(home, "~") : cwd;
  const parts = short.split("/");
  return parts.length > 3 ? `…/${parts.slice(-2).join("/")}` : short;
}
