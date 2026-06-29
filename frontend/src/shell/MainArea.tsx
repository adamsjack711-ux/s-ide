import { useEffect, useState } from "react";
import HomeView from "../home/HomeView";
import LearningView from "../learn/LearningView";
import SettingsView from "../settings/SettingsView";
import WorkbenchView from "../build/WorkbenchView";
import SpineView from "../spine/SpineView";
import LabsView from "../labs/LabsView";
import LabTabView from "../labs/LabTabView";
import ToolPanel from "../panels/ToolPanel";
import EditorPanel from "../panels/EditorPanel";
import OutputPanel from "../panels/OutputPanel";
import PlaybookEditor from "../build/PlaybookEditor";
import EngagementWorkspace from "./EngagementWorkspace";
import { useIsolationOk } from "../labs/useIsolationOk";
import { toolById } from "./tools";
import { on } from "./bus";
import { useLabTabs, activateLabTab, closeLabTab } from "../lib/labTabs";
import {
  useEngagementTabs,
  activateEngagementTab,
  closeEngagementTab,
  setEngagementSubTab,
  getActiveEngagementTabId,
  type EngagementSubTab,
} from "../lib/engagementTabs";

type View = { kind: string; params?: Record<string, any> };

// The four engagement sub-surfaces are not top-level views any more — an
// `openView` for one of them means "switch the active engagement tab to that
// sub-tab" instead of swapping the whole main area.
const SUB_TAB_KINDS = new Set(["build", "graph", "findings", "reports", "terminal"]);

/**
 * The main area. An engagement opens as a TAB (top strip); its body is the
 * EngagementWorkspace (Workbench / Map / Findings / Terminal sub-tabs). Global,
 * untabbable destinations from the bottom of the rail — Engagements list,
 * Reporting, Learn, Settings, Labs — render full-screen in the same slot. A
 * collapsible Output dock sits below.
 */
function initialView(): View {
  // Targets is the front door of the app.
  return { kind: "spine" };
}

export default function MainArea() {
  const [view, setView] = useState<View>(initialView);
  const [outputOpen, setOutputOpen] = useState(false);
  const isolationOk = useIsolationOk();
  const { tabs: labTabs } = useLabTabs();
  const { tabs: engTabs, activeId: activeEngId, subTab } = useEngagementTabs();

  useEffect(() => on("openView", ({ view: v, params }) => {
    // Sub-surfaces route into the active engagement tab rather than replacing it.
    if (SUB_TAB_KINDS.has(v)) {
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
  useEffect(() => on("openEditor", ({ labId, path }) => setView({ kind: "editor", params: { labId, path } })), []);
  useEffect(() => on("labTabActivated", ({ labId }) => setView({ kind: "lab", params: { labId } })), []);
  // An engagement tab becoming active swaps the main view to its workspace.
  useEffect(() => on("engagementTabActivated", () => setView({ kind: "engagement" })), []);
  // Auto-reveal the output dock when a tool streams.
  useEffect(() => on("output", () => setOutputOpen(true)), []);

  const activeLabId = view.kind === "lab" ? view.params?.labId : null;
  const inEngagement = view.kind === "engagement";

  function render() {
    const p = view.params ?? {};
    switch (view.kind) {
      case "engagement":
        return activeEngId
          ? <EngagementWorkspace engagementId={activeEngId} subTab={subTab} />
          : <HomeView />;
      case "home": return <HomeView />;
      case "spine": return <SpineView />;
      case "learn": return <LearningView />;
      case "settings": return <SettingsView />;
      case "labs": return <LabsView />;
      case "lab": return <LabTabView labId={p.labId} />;
      case "playbook": return <PlaybookEditor playbookId={p.id} isolationOk={isolationOk} />;
      case "editor": return <EditorPanel labId={p.labId} path={p.path} />;
      case "build": return <WorkbenchView />; // fallback if reached without an engagement
      case "tool": {
        const t = toolById(p.toolId);
        return t ? <ToolPanel tool={t} /> : <div className="p-4 text-ink-dim">Unknown tool.</div>;
      }
      default: return <HomeView />;
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
      {/* Primary MDI tab strip — open engagements (+ open labs). */}
      {(engTabs.length > 0 || labTabs.length > 0) && (
        <div className="flex shrink-0 items-stretch gap-px overflow-x-auto border-b border-divider bg-bg-sidebar">
          {engTabs.map((t) => {
            const active = inEngagement && t.id === activeEngId;
            return (
              <div
                key={t.id}
                className={`group flex items-center gap-2 border-r border-divider px-3 py-1.5 text-[12px] ${
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
          {labTabs.map((t) => {
            const active = t.id === activeLabId;
            return (
              <div
                key={t.id}
                className={`group flex items-center gap-2 border-r border-divider px-3 py-1.5 text-[12px] ${
                  active ? "bg-bg-base text-ink-primary" : "text-ink-dim hover:text-ink-primary"
                }`}
              >
                {active && <span className="h-1.5 w-1.5 rounded-full bg-accent" />}
                <button onClick={() => activateLabTab(t.id)} title={t.primaryUrl || t.name} className="max-w-[160px] truncate">
                  {t.name}
                </button>
                <button
                  onClick={() => closeLabTab(t.id)}
                  title="Close lab tab"
                  className="text-ink-dim opacity-0 hover:text-danger group-hover:opacity-100"
                >
                  ×
                </button>
              </div>
            );
          })}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-hidden">{render()}</div>

      {/* Output dock — collapsible bottom strip. */}
      <div className={`flex shrink-0 flex-col border-t border-divider ${outputOpen ? "h-52" : ""}`}>
        <button
          onClick={() => setOutputOpen((o) => !o)}
          className="flex items-center gap-2 px-3 py-1 text-[11px] uppercase tracking-wide text-ink-dim hover:text-ink-primary"
        >
          <span>{outputOpen ? "▾" : "▸"}</span> Output
        </button>
        {outputOpen && (
          <div className="min-h-0 flex-1">
            <OutputPanel />
          </div>
        )}
      </div>
    </div>
  );
}
