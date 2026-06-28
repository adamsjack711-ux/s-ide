import { useEffect, useState } from "react";
import HomeView from "../home/HomeView";
import FindingsView from "../engagement/FindingsView";
import ReportsView from "../engagement/ReportsView";
import LearningView from "../learn/LearningView";
import SettingsView from "../settings/SettingsView";
import GraphView from "../graph/GraphView";
import BuildPanel from "../build/BuildPanel";
import LabsView from "../labs/LabsView";
import ToolPanel from "../panels/ToolPanel";
import EditorPanel from "../panels/EditorPanel";
import OutputPanel from "../panels/OutputPanel";
import PlaybookEditor from "../build/PlaybookEditor";
import { useIsolationOk } from "../labs/useIsolationOk";
import { toolById } from "./tools";
import { on } from "./bus";

type View = { kind: string; params?: Record<string, any> };

/**
 * The single main view (the design's flow): the left rail / nav swaps ONE view
 * at a time here — no stacking editor tabs. Tools, the playbook editor and the
 * Monaco editor open in the same slot. A collapsible Output dock sits below.
 */
export default function MainArea() {
  const [view, setView] = useState<View>({ kind: "home" });
  const [outputOpen, setOutputOpen] = useState(false);
  const isolationOk = useIsolationOk();

  useEffect(() => on("openView", ({ view: v, params }) => setView({ kind: v, params })), []);
  useEffect(() => on("openTool", ({ toolId }) => setView({ kind: "tool", params: { toolId } })), []);
  useEffect(() => on("openEditor", ({ labId, path }) => setView({ kind: "editor", params: { labId, path } })), []);
  // Auto-reveal the output dock when a tool streams.
  useEffect(() => on("output", () => setOutputOpen(true)), []);

  function render() {
    const p = view.params ?? {};
    switch (view.kind) {
      case "home": return <HomeView />;
      case "findings": return <FindingsView />;
      case "reports": return <ReportsView />;
      case "learn": return <LearningView />;
      case "settings": return <SettingsView />;
      case "graph": return <GraphView />;
      case "build": return <BuildPanel />;
      case "labs": return <LabsView />;
      case "playbook": return <PlaybookEditor playbookId={p.id} isolationOk={isolationOk} />;
      case "editor": return <EditorPanel labId={p.labId} path={p.path} />;
      case "tool": {
        const t = toolById(p.toolId);
        return t ? <ToolPanel tool={t} /> : <div className="p-4 text-ink-dim">Unknown tool.</div>;
      }
      default: return <HomeView />;
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base">
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
