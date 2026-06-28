import { useEffect, useMemo, useRef, useState } from "react";
import { TOOLS } from "./tools";
import { emit } from "./bus";
import {
  listEngagements,
  setActiveEngagementId,
  type Engagement,
} from "../lib/engagement";

type Command = { id: string; label: string; hint: string; run: () => void };

/**
 * The spine: ⌘K / Ctrl-K universal launcher. Run any tool, jump to any
 * engagement. (Findings/actions join the list as later phases add them.)
 */
export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(0);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    const onTrigger = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("s-ide:palette", onTrigger);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("s-ide:palette", onTrigger);
    };
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSel(0);
      listEngagements().then(setEngagements).catch(() => {});
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const commands = useMemo<Command[]>(() => {
    const toolCmds: Command[] = TOOLS.map((t) => ({
      id: `tool:${t.id}`,
      label: t.label,
      hint: `Tool · ${t.group}`,
      run: () => emit("openTool", { toolId: t.id }),
    }));
    const engCmds: Command[] = engagements.map((e) => ({
      id: `eng:${e.id}`,
      label: e.name,
      hint: "Switch engagement",
      run: () => setActiveEngagementId(e.id),
    }));
    return [...toolCmds, ...engCmds];
  }, [engagements]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) => (c.label + " " + c.hint).toLowerCase().includes(q));
  }, [commands, query]);

  if (!open) return null;

  function choose(c?: Command) {
    if (!c) return;
    c.run();
    setOpen(false);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 pt-24" onClick={() => setOpen(false)}>
      <div className="w-[34rem] overflow-hidden rounded-lg bg-bg-card shadow-2xl ring-1 ring-divider" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => { setQuery(e.target.value); setSel(0); }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
            else if (e.key === "Enter") { e.preventDefault(); choose(filtered[sel]); }
          }}
          placeholder="Run a tool, jump to an engagement…"
          className="w-full bg-transparent px-4 py-3 text-sm text-ink-primary outline-none"
        />
        <div className="max-h-80 overflow-auto border-t border-divider">
          {filtered.length === 0 ? (
            <div className="px-4 py-3 text-sm text-ink-dim">No matches.</div>
          ) : (
            filtered.map((c, i) => (
              <button
                key={c.id}
                onMouseEnter={() => setSel(i)}
                onClick={() => choose(c)}
                className={`flex w-full items-center justify-between px-4 py-2 text-left text-sm ${i === sel ? "bg-nav-active text-ink-primary" : "text-ink-muted"}`}
              >
                <span>{c.label}</span>
                <span className="text-xs text-ink-dim">{c.hint}</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
