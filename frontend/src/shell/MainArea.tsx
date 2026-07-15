import { useCallback, useEffect, useState } from "react";
import OutputPanel from "../panels/OutputPanel";
import TerminalView from "./TerminalView";
import { useActiveEngagementId, listEngagements, isLabEngagement } from "../lib/engagement";
import { on, emit } from "./bus";
import { getView, isSubTabView } from "./views";
import "./views.builtin"; // registers the shell's stock views (side effect)
import {
  useEngagementTabs,
  activateEngagementTab,
  closeEngagementTab,
  setEngagementSubTab,
  getActiveEngagementTabId,
  type EngagementSubTab,
} from "../lib/engagementTabs";

type View = { kind: string; params?: Record<string, any> };

/**
 * The main area. An engagement opens as a TAB (top strip); its body is the
 * EngagementWorkspace (Workbench / Map / Findings / Terminal sub-tabs). Global,
 * untabbable destinations from the bottom of the rail — Engagements list,
 * Reporting, Learn, Settings, Labs — render full-screen in the same slot. A
 * collapsible Output dock sits below.
 */
function initialView(): View {
  // Engagements is the front door of the app once there ARE engagements. On a
  // true first run (empty DB) we route to Home instead so the new user lands on
  // the polished getting-started hero + rich create modal rather than the bare
  // Engagements list; the async count check below performs that redirect.
  return { kind: "spine" };
}

export default function MainArea() {
  const [view, setView] = useState<View>(initialView);
  const [outputOpen, setOutputOpen] = useState(false);
  const [dockTab, setDockTab] = useState<"output" | "terminal">("output");
  const activeEngagementId = useActiveEngagementId();
  const { tabs: engTabs, activeId: activeEngId } = useEngagementTabs();

  // First-run redirect: if the (non-lab) engagement list is empty on launch,
  // land on HomeView — which auto-shows the onboarding steps + create modal —
  // instead of the bare Engagements spine. Only fires while the user is still on
  // the default spine landing (any explicit navigation before it resolves wins),
  // and SpineView stays the natural front door once engagements exist.
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = (await listEngagements()).filter((e) => !isLabEngagement(e));
        if (!alive || list.length > 0) return;
        setView((v) => (v.kind === "spine" ? { kind: "home" } : v));
      } catch {
        /* leave the default spine landing on error */
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => on("openView", ({ view: v, params }) => {
    // Sub-surfaces route into the active engagement tab rather than replacing it.
    // Whether a view is a sub-tab is data on its registry descriptor, so this
    // handler never needs editing when a new view is added.
    if (isSubTabView(v)) {
      const eid = getActiveEngagementTabId();
      if (eid) {
        setEngagementSubTab(eid, v as EngagementSubTab);
        setView({ kind: "engagement" });
      } else {
        // No engagement open — nothing to scope the surface to; show the list.
        setView({ kind: "home" });
      }
      return;
    }
    setView({ kind: v, params });
  }), []);
  useEffect(() => on("openTool", ({ toolId }) => setView({ kind: "tool", params: { toolId } })), []);
  // An engagement tab becoming active swaps the main view to its workspace.
  useEffect(() => on("engagementTabActivated", () => setView({ kind: "engagement" })), []);
  // Auto-reveal the output dock when a tool streams.
  useEffect(() => on("output", () => setOutputOpen(true)), []);

  // Tab-strip actions. Back returns to the Engagements list without closing any
  // tab; "+" runs the canonical create action (same as ⌘N: go Home, then open
  // the create modal on the next tick once the Home lane has mounted to hear it).
  const goBackToList = useCallback(() => emit("openView", { view: "spine" }), []);
  const newEngagement = useCallback(() => {
    // Navigate Home with a fresh nonce; HomeView opens the create modal on mount
    // (race-free — no reliance on the Home lane already being subscribed).
    emit("openView", { view: "home", params: { createNonce: Date.now() } });
  }, []);

  const inEngagement = view.kind === "engagement";

  // The main slot renders whichever view the registry maps `view.kind` to.
  // Adding a destination is a registerView() call in its own file — this host
  // never changes. Unknown kinds fall back to Home, but warn so a typo or an
  // openView to an unregistered id surfaces instead of silently landing on Home.
  const found = getView(view.kind);
  if (!found && view.kind !== "home") {
    console.warn(`[shell] no view registered for "${view.kind}" — falling back to Home`);
  }
  const Active = found?.component ?? getView("home")?.component;

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      {/* Primary MDI tab strip — open engagements. (Labs are NOT here; active
          labs live only in Learning → Labs.) */}
      {engTabs.length > 0 && (
        <div className="flex shrink-0 items-stretch gap-px overflow-x-auto border-b border-divider bg-bg-sidebar">
          {/* Back to the Engagements list (leaves tabs open). Shown while a tab's
              workspace fills the main area. */}
          {inEngagement && (
            <button
              onClick={goBackToList}
              title="Back to engagements"
              aria-label="Back to engagements"
              className="flex items-center border-r border-divider px-2.5 text-[calc(13px_*_var(--text-scale))] text-ink-dim hover:bg-bg-base hover:text-ink-primary"
            >
              ‹
            </button>
          )}
          {engTabs.map((t) => {
            const active = inEngagement && t.id === activeEngId;
            return (
              <div
                key={t.id}
                className={`group flex items-center gap-2 border-r border-divider px-3 py-1.5 text-[calc(12px_*_var(--text-scale))] ${
                  active ? "bg-bg-base text-ink-primary" : "text-ink-dim hover:text-ink-primary"
                }`}
              >
                {active && <span className="h-1.5 w-1.5 rounded-full bg-accent" />}
                <button onClick={() => activateEngagementTab(t.id)} title={t.name} className="max-w-[180px] truncate">
                  {t.name}
                </button>
                <button
                  onClick={() => closeEngagementTab(t.id)}
                  title="Close engagement tab"
                  className="text-ink-dim opacity-0 hover:text-danger group-hover:opacity-100"
                >
                  ×
                </button>
              </div>
            );
          })}
          {/* Add a new engagement (opens the create flow). */}
          <button
            onClick={newEngagement}
            title="New engagement"
            aria-label="New engagement"
            className="flex items-center px-3 text-[calc(15px_*_var(--text-scale))] leading-none text-ink-dim hover:bg-bg-base hover:text-accent"
          >
            +
          </button>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-hidden">
        {Active ? <Active params={view.params ?? {}} /> : <div className="p-4 text-ink-dim">No view.</div>}
      </div>

      {/* Bottom dock — collapsible, tabbed: Output + the integrated Terminal.
          The Terminal tab is present whenever an engagement is active; it runs
          engagement-scoped (authFetch attaches X-MHP-Engagement-Id) and the
          server-side arm gate + target_policy still apply to every command. */}
      <div className={`flex shrink-0 flex-col border-t border-divider ${outputOpen ? "h-60" : ""}`}>
        <div className="flex items-center gap-1 px-2">
          <DockTab id="output" label="Output" active={outputOpen && dockTab === "output"} onClick={() => { setDockTab("output"); setOutputOpen(true); }} />
          {activeEngagementId && (
            <DockTab id="terminal" label="Terminal" active={outputOpen && dockTab === "terminal"} onClick={() => { setDockTab("terminal"); setOutputOpen(true); }} />
          )}
          <button
            onClick={() => setOutputOpen((o) => !o)}
            title={outputOpen ? "Collapse" : "Expand"}
            className="ml-auto px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-ink-dim hover:text-ink-primary"
          >
            {outputOpen ? "▾" : "▸"}
          </button>
        </div>
        {outputOpen && (
          <div className="min-h-0 flex-1">
            {dockTab === "terminal" && activeEngagementId ? <TerminalView /> : <OutputPanel />}
          </div>
        )}
      </div>
    </div>
  );
}

function DockTab({ label, active, onClick }: { id: string; label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide transition-colors ${
        active ? "text-ink-primary" : "text-ink-dim hover:text-ink-primary"
      }`}
    >
      {label}
    </button>
  );
}
