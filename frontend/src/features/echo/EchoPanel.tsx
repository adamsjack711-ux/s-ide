/**
 * PHASE-0 PROOF PANEL — the gate for the feature suite's shared contract.
 *
 * The contract's pass/fail test (task Phase 0.5): "add a throwaway panel that
 * subscribes to `selectFinding` and displays the ref, WITHOUT editing any
 * existing panel file. Publish a `selectFinding` from anywhere and confirm the
 * panel updates."
 *
 * This panel does exactly and only that. It:
 *   1. SUBSCRIBES to the NEW `selectFinding` bus event (shell/bus.ts) — added in
 *      Phase 0 — and shows the canonical FindingRef it carried (shell/refs.ts).
 *   2. Registers its own view + command so ⌘K / openView can reach it.
 *   3. Is wired in by ONE import line in the feature manifest (features/index.ts),
 *      exactly like every real feature — no existing panel is touched.
 *
 * It mirrors demo/ActiveEngagementPanel (the pre-existing decoupling proof), but
 * against the new selection contract rather than activeEngagementChanged. If
 * this panel can be added and can react to selectFinding without editing another
 * panel, the Phase-0 contract is decoupled and Phase 1 may fan out. It is
 * deliberately trivial; its value is architectural, not functional.
 */
import { useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import type { FindingRef } from "../../shell/refs";

function EchoPanel(_props: { params: ViewParams }) {
  const [last, setLast] = useState<{ ref: FindingRef; source: string } | null>(null);
  const [count, setCount] = useState(0);

  // Subscribe to the bus. No panel calls us; we react to the broadcast like any
  // other view. We hold NO shared state — only what the event handed us.
  useBus("selectFinding", (p) => {
    setLast(p);
    setCount((n) => n + 1);
  });

  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center gap-4 bg-bg-base p-8">
      <div className="w-full max-w-md rounded-lg border border-divider bg-bg-card p-6">
        <div className="text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
          Last selected finding
        </div>
        <div className="mt-2 font-mono text-[calc(13px_*_var(--text-scale))] text-ink-primary break-all">
          {last ? last.ref.findingId : "— none selected —"}
        </div>
        {last && (
          <div className="mt-1 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-muted break-all">
            sub-target {last.ref.subTargetId} · target {last.ref.targetId} · via{" "}
            {last.source}
          </div>
        )}
        <div className="mt-4 flex items-center gap-2 text-[calc(12px_*_var(--text-scale))] text-ink-dim">
          <span className="h-1.5 w-1.5 rounded-full bg-accent" />
          reacted to {count} <code>selectFinding</code> event{count === 1 ? "" : "s"} on the bus
        </div>
      </div>
      <p className="max-w-md text-center text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-dim">
        Phase-0 proof: this panel subscribes to the new <code>selectFinding</code>{" "}
        contract and reacts without importing, or being imported by, any other
        panel.
      </p>
    </div>
  );
}

// ── Registration (runs at import; mirrors demo/ActiveEngagementPanel) ─────────
registerView({ id: "echo-selection", component: EchoPanel });
registerCommand({
  id: "open-echo-selection",
  title: "Open Selection Echo panel (Phase-0 proof)",
  keywords: ["echo", "selection", "finding", "phase0", "proof", "acceptance"],
  context: "View",
  run: () => emit("openView", { view: "echo-selection" }),
});
