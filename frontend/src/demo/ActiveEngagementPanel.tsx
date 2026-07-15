/**
 * ACCEPTANCE-TEST PANEL for the architecture contract.
 *
 * This file exists to PROVE the three-pillar decoupling: a brand-new panel that
 * reacts to an existing bus event was added WITHOUT editing any existing panel.
 * It only ever:
 *
 *   1. READS THE MODEL        — useActiveEngagementId() + listEngagements()
 *                               (the single source of truth in lib/engagement).
 *   2. SUBSCRIBES TO THE BUS   — activeEngagementChanged. Nothing calls this
 *                               panel; it reacts to the broadcast like every
 *                               other view (code view, graph, copilot) does.
 *   3. REGISTERS A VIEW + COMMAND — so ⌘K and openView can reach it. One
 *                               command, many surfaces.
 *
 * The ONLY wiring outside this file is a single import line in the view
 * registration manifest (shell/views.builtin.tsx) — mirroring exactly how a new
 * tool is added via one line in shell/tools/index.ts. No existing panel's code
 * was touched, no publisher was edited, no central switch was extended.
 *
 * It is deliberately trivial. Its value is architectural, not functional: if
 * this panel can be deleted by removing just this file and its one manifest
 * line, the shell is decoupled. If it couldn't have been added without editing
 * other panels, it wouldn't be.
 */
import { useCallback, useEffect, useState } from "react";
import { registerView, type ViewParams } from "../shell/views";
import { registerCommand } from "../shell/commands";
import { emit, useBus } from "../shell/bus";
import { useActiveEngagementId, listEngagements } from "../lib/engagement";

function ActiveEngagementPanel(_props: { params: ViewParams }) {
  // 1. Read the model. useActiveEngagementId re-renders us whenever the active
  //    engagement changes — we hold NO duplicate copy of that state.
  const activeId = useActiveEngagementId();
  const [name, setName] = useState<string | null>(null);
  const [changes, setChanges] = useState(0);

  // Resolve the active engagement's display name from the model. Re-runs when
  // the active id changes.
  useEffect(() => {
    let alive = true;
    (async () => {
      if (!activeId) {
        if (alive) setName(null);
        return;
      }
      try {
        const list = await listEngagements(true);
        if (alive) setName(list.find((e) => e.id === activeId)?.name ?? null);
      } catch {
        if (alive) setName(null);
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeId]);

  // 2. Subscribe to the bus. Visible proof of reactivity: count every broadcast.
  const onChange = useCallback(() => setChanges((n) => n + 1), []);
  useBus("activeEngagementChanged", onChange);

  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center gap-4 bg-bg-base p-8">
      <div className="w-full max-w-md rounded-lg border border-divider bg-bg-card p-6">
        <div className="text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
          Active engagement
        </div>
        <div className="mt-2 text-[calc(20px_*_var(--text-scale))] text-ink-primary">
          {activeId ? name ?? activeId : "— none pinned —"}
        </div>
        <div className="mt-4 flex items-center gap-2 text-[calc(12px_*_var(--text-scale))] text-ink-dim">
          <span className="h-1.5 w-1.5 rounded-full bg-accent" />
          reacted to {changes} <code>activeEngagementChanged</code> event
          {changes === 1 ? "" : "s"} on the bus
        </div>
      </div>
      <p className="max-w-md text-center text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-dim">
        This panel reads the engagement model and reacts to the bus without
        importing, or being imported by, any other panel — the acceptance test
        for the shell's decoupling.
      </p>
    </div>
  );
}

// ── Registration (runs at import; mirrors tools/index.ts wiring) ─────────────
registerView({ id: "active-engagement", component: ActiveEngagementPanel });
registerCommand({
  id: "open-active-engagement",
  title: "Open Active Engagement panel",
  keywords: ["engagement", "active", "demo", "acceptance"],
  context: "View",
  run: () => emit("openView", { view: "active-engagement" }),
});
