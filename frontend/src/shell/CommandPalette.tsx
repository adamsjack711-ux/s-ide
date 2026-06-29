import { useEffect, useMemo, useRef, useState } from "react";
import { TOOLS } from "./tools";
import { emit } from "./bus";
import {
  getCommands,
  getRecentCommands,
  markUsed,
  subscribeCommands,
  type Command as RegCommand,
} from "./commands";
import { bindingFor } from "./keymap";
import {
  getActiveEngagementId,
  listEngagements,
  setActiveEngagementId,
  type Engagement,
} from "../lib/engagement";

// A palette row. Registry commands, tools, and engagements are all normalised
// into this shape before rendering.
type Row = {
  id: string;
  label: string;
  hint: string;
  binding?: string;
  run: () => void;
};

/**
 * The spine: ⌘K / Ctrl-K universal launcher. Renders from the command registry
 * (shell/commands.ts) so any lane can contribute commands at mount, plus the
 * tool registry and engagement switcher. Recent/most-used float to the top when
 * the query is empty; each row shows its keybinding; the header shows the
 * active engagement so the user knows what commands will act on.
 */
export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(0);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  // Re-render when the registry changes (lanes register on mount).
  const [, setRegTick] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => subscribeCommands(() => setRegTick((n) => n + 1)), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    const onTrigger = (e: Event) => {
      setOpen(true);
      // "Open Tool…" prefills the search to surface tools immediately.
      const detail = (e as CustomEvent).detail as { mode?: string } | undefined;
      if (detail?.mode === "tool") setQuery("");
    };
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

  const activeEngagement = useMemo(() => {
    const id = getActiveEngagementId();
    return engagements.find((e) => e.id === id) ?? null;
  }, [engagements, open]);

  // All commands, normalised to rows. Registry commands first (they carry the
  // shell + contextual actions), then tools, then engagement switches.
  const allRows = useMemo<Row[]>(() => {
    const reg: Row[] = getCommands().map((c: RegCommand) => ({
      id: c.id,
      label: c.title,
      hint: c.context ?? "Command",
      binding: c.binding ?? bindingFor(c.id),
      run: () => {
        markUsed(c.id);
        c.run();
      },
    }));
    const toolRows: Row[] = TOOLS.map((t) => ({
      id: `tool:${t.id}`,
      label: t.label,
      hint: `Tool · ${t.group}`,
      run: () => emit("openTool", { toolId: t.id }),
    }));
    const engRows: Row[] = engagements.map((e) => ({
      id: `eng:${e.id}`,
      label: e.name,
      hint: "Switch engagement",
      run: () => setActiveEngagementId(e.id),
    }));
    return [...reg, ...toolRows, ...engRows];
  }, [engagements]);

  // Recent rows (registry-tracked) for the empty-query view.
  const recentRows = useMemo<Row[]>(() => {
    return getRecentCommands(6).map((c) => ({
      id: `recent:${c.id}`,
      label: c.title,
      hint: "Recent",
      binding: c.binding ?? bindingFor(c.id),
      run: () => {
        markUsed(c.id);
        c.run();
      },
    }));
  }, [allRows, open]);

  const q = query.trim().toLowerCase();

  // Lightweight fuzzy match: every query char appears in order in the haystack.
  const fuzzy = (hay: string): boolean => {
    if (!q) return true;
    let i = 0;
    for (const ch of hay) {
      if (ch === q[i]) i++;
      if (i === q.length) return true;
    }
    return false;
  };

  const sections = useMemo<{ title: string | null; rows: Row[] }[]>(() => {
    if (!q) {
      const recents = recentRows;
      const recentIds = new Set(recents.map((r) => r.id.replace(/^recent:/, "")));
      const rest = allRows.filter((r) => !recentIds.has(r.id));
      const out: { title: string | null; rows: Row[] }[] = [];
      if (recents.length) out.push({ title: "Recent", rows: recents });
      out.push({ title: recents.length ? "All commands" : null, rows: rest });
      return out;
    }
    const matched = allRows.filter((r) =>
      `${r.label} ${r.hint}`.toLowerCase().includes(q) || fuzzy(r.label.toLowerCase()),
    );
    return [{ title: null, rows: matched }];
  }, [allRows, recentRows, q]);

  // Flat list for keyboard nav + index lookup.
  const flat = useMemo(() => sections.flatMap((s) => s.rows), [sections]);

  if (!open) return null;

  function choose(r?: Row) {
    if (!r) return;
    r.run();
    setOpen(false);
  }

  let runningIndex = -1;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 pt-24"
      onClick={() => setOpen(false)}
    >
      <div
        className="w-[34rem] overflow-hidden rounded-lg bg-bg-card shadow-2xl ring-1 ring-divider"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Active-engagement context header */}
        <div className="flex items-center gap-2 border-b border-divider px-4 py-1.5 text-xs">
          <span className="text-ink-dim">Acting on</span>
          {activeEngagement ? (
            <span className="flex items-center gap-1.5 text-ink-muted">
              <span className="h-1.5 w-1.5 rounded-full bg-accent" />
              <span className="text-ink-primary">{activeEngagement.name}</span>
            </span>
          ) : (
            <span className="text-ink-dim">no active engagement</span>
          )}
        </div>
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setSel(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setSel((s) => Math.min(s + 1, flat.length - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setSel((s) => Math.max(s - 1, 0));
            } else if (e.key === "Enter") {
              e.preventDefault();
              choose(flat[sel]);
            }
          }}
          placeholder="Run a command, open a tool, jump to an engagement…"
          className="w-full bg-transparent px-4 py-3 text-sm text-ink-primary outline-none"
        />
        <div className="max-h-80 overflow-auto border-t border-divider">
          {flat.length === 0 ? (
            <div className="px-4 py-3 text-sm text-ink-dim">No matches.</div>
          ) : (
            sections.map((section, si) =>
              section.rows.length === 0 ? null : (
                <div key={si}>
                  {section.title && (
                    <div className="px-4 pb-1 pt-2 text-[10px] font-medium uppercase tracking-wider text-ink-dim">
                      {section.title}
                    </div>
                  )}
                  {section.rows.map((r) => {
                    runningIndex += 1;
                    const i = runningIndex;
                    return (
                      <button
                        key={r.id}
                        onMouseEnter={() => setSel(i)}
                        onClick={() => choose(r)}
                        className={`flex w-full items-center justify-between gap-3 px-4 py-2 text-left text-sm ${
                          i === sel ? "bg-nav-active text-ink-primary" : "text-ink-muted"
                        }`}
                      >
                        <span className="min-w-0 flex-1 truncate">{r.label}</span>
                        <span className="flex shrink-0 items-center gap-2">
                          <span className="text-xs text-ink-dim">{r.hint}</span>
                          {r.binding && (
                            <kbd className="rounded border border-border bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
                              {r.binding}
                            </kbd>
                          )}
                        </span>
                      </button>
                    );
                  })}
                </div>
              ),
            )
          )}
        </div>
      </div>
    </div>
  );
}
