import { useEffect, useRef, useState } from "react";
import { emit, on, type OutputLine } from "../shell/bus";

const COLOR: Record<OutputLine["level"], string> = {
  info: "text-ink-muted",
  hit: "text-accent",
  done: "text-success",
  error: "text-danger",
};

/** Bottom-dock live log — every tool panel's stream lands here, newest last. */
export default function OutputPanel() {
  const [lines, setLines] = useState<OutputLine[]>([]);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => on("output", (l) => setLines((prev) => [...prev.slice(-499), l])), []);
  useEffect(() => endRef.current?.scrollIntoView({ block: "end" }), [lines]);

  return (
    <div className="flex h-full flex-col bg-bg-base">
      <div className="flex items-center justify-end border-b border-divider px-3 py-1">
        <button
          onClick={() => emit("promoteSteps", {})}
          title="Promote a session-log subsequence into an ordered Step chain"
          className="rounded px-2 py-0.5 text-[11px] text-accent ring-1 ring-accent/40 hover:bg-accent/10"
        >
          Promote → steps
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto px-3 py-2 font-mono text-xs">
      {lines.length === 0 ? (
        <div className="text-ink-dim">Output from running tools appears here.</div>
      ) : (
        lines.map((l, i) => (
          <div key={i} className="whitespace-pre-wrap">
            <span className="text-ink-dim">{new Date(l.ts).toLocaleTimeString()} </span>
            <span className="text-ink-dim">[{l.tool}] </span>
            <span className={COLOR[l.level]}>{l.text}</span>
          </div>
        ))
      )}
      <div ref={endRef} />
      </div>
    </div>
  );
}
