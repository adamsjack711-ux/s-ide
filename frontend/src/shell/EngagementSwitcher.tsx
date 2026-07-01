import type { CSSProperties } from "react";
import { useEffect, useRef, useState } from "react";
import Icon from "./Icon";
import {
  listEngagements,
  isLabEngagement,
  setActiveEngagementId,
  useActiveEngagementId,
  type Engagement,
} from "../lib/engagement";
import { listTargets, type Target } from "../lib/targets";
import { openEngagementWindow } from "../lib/windowEngagement";

/**
 * The active-engagement switcher in the title bar.
 *
 * Replaces the old read-only engagement label: the button opens a popover that
 * lists every engagement and the targets inside each one, so you can switch the
 * window's active engagement (and see its scope) without leaving the current
 * view. Targets are fetched lazily the first time the popover opens, then cached
 * per engagement for the session.
 *
 * Switching pins the chosen engagement active (api.ts then attaches it to every
 * backend write via X-MHP-Engagement-Id); the per-engagement "open in new
 * window" affordance mirrors the Explorer's EngagementTree.
 */
export default function EngagementSwitcher() {
  const activeId = useActiveEngagementId();
  const [open, setOpen] = useState(false);
  const [engagements, setEngagements] = useState<Engagement[] | null>(null);
  const [targets, setTargets] = useState<Record<string, Target[]>>({});
  const ref = useRef<HTMLDivElement>(null);

  const active = engagements?.find((e) => e.id === activeId) ?? null;

  // Load the engagement list + each engagement's targets the first time the
  // popover opens. Best-effort: a failure leaves the list empty rather than
  // throwing into the title bar.
  useEffect(() => {
    if (!open || engagements !== null) return;
    let alive = true;
    (async () => {
      try {
        // Labs live in Learn → Labs; the switcher lists real engagements only.
        const es = (await listEngagements()).filter((e) => !isLabEngagement(e));
        if (!alive) return;
        setEngagements(es);
        const entries = await Promise.all(
          es.map(async (e) => {
            try {
              return [e.id, await listTargets({ engagementId: e.id })] as const;
            } catch {
              return [e.id, [] as Target[]] as const;
            }
          }),
        );
        if (alive) setTargets(Object.fromEntries(entries));
      } catch {
        if (alive) setEngagements([]);
      }
    })();
    return () => {
      alive = false;
    };
  }, [open, engagements]);

  // Dismiss on outside-click or Escape.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function choose(id: string) {
    setActiveEngagementId(id);
    setOpen(false);
  }

  const noDrag = { WebkitAppRegion: "no-drag" } as CSSProperties;

  return (
    <div ref={ref} className="relative" style={noDrag}>
      <button
        onClick={() => setOpen((o) => !o)}
        title="Switch engagement"
        className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-ink-muted hover:border-borderBright ${
          open ? "border-borderBright bg-bg-base" : "border-divider"
        }`}
      >
        {active ? (
          <>
            <span className="text-accent">⛬</span>
            <span className="max-w-[200px] truncate">{active.name}</span>
          </>
        ) : (
          <span className="text-ink-dim">no engagement</span>
        )}
        <Icon name="chevron-down" size={12} />
      </button>

      {open && (
        <div className="absolute right-0 top-[calc(100%+6px)] z-50 w-80 overflow-hidden rounded-lg border border-divider bg-bg-sidebar shadow-xl">
          <div className="border-b border-divider px-3 py-2 text-[calc(10px_*_var(--text-scale))] font-semibold uppercase tracking-wide text-ink-dim">
            Switch engagement
          </div>
          <div className="max-h-[60vh] overflow-y-auto py-1">
            {engagements === null ? (
              <div className="px-3 py-2 text-[calc(11px_*_var(--text-scale))] text-ink-dim">loading…</div>
            ) : engagements.length === 0 ? (
              <div className="px-3 py-2 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
                No engagements — create one in the Explorer.
              </div>
            ) : (
              engagements.map((e) => {
                const ts = targets[e.id] ?? [];
                const isActive = e.id === activeId;
                return (
                  <div
                    key={e.id}
                    className={`group px-2 py-1.5 ${isActive ? "bg-nav-active" : "hover:bg-nav-hover"}`}
                  >
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => choose(e.id)}
                        className="flex min-w-0 flex-1 items-center gap-1.5 text-left"
                      >
                        <span className={`shrink-0 ${isActive ? "text-accent" : "text-ink-dim"}`}>
                          {isActive ? "▸" : "·"}
                        </span>
                        <span
                          className={`truncate text-[calc(12.5px_*_var(--text-scale))] ${
                            isActive ? "font-medium text-ink-primary" : "text-ink-muted"
                          }`}
                        >
                          {e.name}
                        </span>
                        <span className="ml-auto shrink-0 rounded bg-bg-base px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] text-ink-dim">
                          {ts.length} {ts.length === 1 ? "target" : "targets"}
                        </span>
                      </button>
                      <button
                        onClick={() => openEngagementWindow(e.id)}
                        title="Open in new window"
                        className="shrink-0 px-1 text-ink-dim opacity-0 hover:text-ink-primary group-hover:opacity-100"
                      >
                        ⧉
                      </button>
                    </div>

                    {ts.length > 0 && (
                      <ul className="ml-5 mt-1 space-y-0.5">
                        {ts.slice(0, 5).map((t) => (
                          <li
                            key={t.id}
                            className="flex items-center gap-1.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim"
                          >
                            <span className="text-accent/60">›</span>
                            <span className="truncate font-mono">{t.address}</span>
                            {t.name && t.name !== t.address && (
                              <span className="truncate text-ink-dim/70">{t.name}</span>
                            )}
                          </li>
                        ))}
                        {ts.length > 5 && (
                          <li className="text-[calc(10px_*_var(--text-scale))] text-ink-dim/70">
                            +{ts.length - 5} more
                          </li>
                        )}
                      </ul>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
