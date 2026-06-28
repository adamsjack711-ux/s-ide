import { useEffect, useRef } from "react";
import {
  DockviewReact,
  themeAbyss,
  type DockviewApi,
  type DockviewReadyEvent,
  type IDockviewPanelProps,
} from "dockview-react";
import ToolPanel from "../panels/ToolPanel";
import OutputPanel from "../panels/OutputPanel";
import EditorPanel from "../panels/EditorPanel";
import FindingsView from "../engagement/FindingsView";
import ReportsView from "../engagement/ReportsView";
import LearningView from "../learn/LearningView";
import SettingsView from "../settings/SettingsView";
import HomeView from "../home/HomeView";
import GraphView from "../graph/GraphView";
import PlaybookEditor from "../build/PlaybookEditor";
import { useIsolationOk } from "../labs/useIsolationOk";
import { toolById } from "./tools";
import { on } from "./bus";
import { getActiveEngagementId } from "../lib/engagement";

/** Per-engagement layout persistence (v2 — IDE tabbed-editor restructure). */
function layoutKey(): string {
  return `s-ide:layout:v2:${getActiveEngagementId() ?? "default"}`;
}

/** Views that open as editor tabs (everything that isn't a tool/output/editor). */
const VIEWS: Record<string, () => JSX.Element> = {
  home: () => <HomeView />,
  findings: () => <FindingsView />,
  reports: () => <ReportsView />,
  learn: () => <LearningView />,
  settings: () => <SettingsView />,
  graph: () => <GraphView />,
};

const VIEW_TITLE: Record<string, string> = {
  home: "Engagements", findings: "Findings", reports: "Reporting", learn: "Learn", settings: "Settings", playbook: "Playbook", graph: "Graph",
};

/** dockview component map. Panels are mounted by dockview, not our React tree. */
const components = {
  tool: (props: IDockviewPanelProps<{ toolId: string }>) => {
    const tool = toolById(props.params.toolId);
    return tool ? <ToolPanel tool={tool} /> : <div className="p-4 text-ink-dim">Unknown tool.</div>;
  },
  output: () => <OutputPanel />,
  editor: (props: IDockviewPanelProps<{ labId: string; path: string }>) => (
    <EditorPanel labId={props.params.labId} path={props.params.path} />
  ),
  view: (props: IDockviewPanelProps<{ view: string }>) => (VIEWS[props.params.view]?.() ?? <div className="p-4 text-ink-dim">Unknown view.</div>),
  playbook: (props: IDockviewPanelProps<{ id?: string }>) => <PlaybookTab id={props.params.id} />,
};

/** Wraps the playbook editor with live isolation state for the Run gate. */
function PlaybookTab({ id }: { id?: string }) {
  const isolationOk = useIsolationOk();
  return <PlaybookEditor playbookId={id} isolationOk={isolationOk} />;
}

const HOME_ID = "view-home";

/**
 * The editor area: a dockview surface hosting tabbed panels — Home, tools, the
 * playbook editor, findings/reports/learn/settings views, and the Monaco
 * fix-in-place editor — with a bottom Output dock. Tabs open via bus events.
 */
export default function Workspace() {
  const apiRef = useRef<DockviewApi | null>(null);

  function openInEditor(api: DockviewApi, id: string, component: string, title: string, params: Record<string, unknown>) {
    const existing = api.getPanel(id);
    if (existing) return existing.api.setActive();
    const ref = api.getPanel(HOME_ID) ?? api.panels.find((p) => p.id !== "output");
    api.addPanel({ id, component, title, params, position: ref ? { referencePanel: ref.id, direction: "within" } : undefined });
  }

  function buildDefault(api: DockviewApi) {
    api.addPanel({ id: HOME_ID, component: "view", title: "Home", params: { view: "home" } });
    api.addPanel({ id: "output", component: "output", title: "Output", position: { direction: "below" } });
    api.getPanel(HOME_ID)?.api.setActive();
  }

  function onReady(event: DockviewReadyEvent) {
    const api = event.api;
    apiRef.current = api;
    const saved = localStorage.getItem(layoutKey());
    let restored = false;
    if (saved) {
      try { api.fromJSON(JSON.parse(saved)); restored = true; } catch { restored = false; }
    }
    if (!restored) buildDefault(api);
    api.onDidLayoutChange(() => {
      try { localStorage.setItem(layoutKey(), JSON.stringify(api.toJSON())); } catch { /* non-fatal */ }
    });
  }

  useEffect(() => on("openTool", ({ toolId }) => {
    const api = apiRef.current; if (!api) return;
    openInEditor(api, `tool-${toolId}`, "tool", toolById(toolId)?.label ?? toolId, { toolId });
  }), []);

  useEffect(() => on("openView", ({ view, params }) => {
    const api = apiRef.current; if (!api) return;
    if (view === "playbook") {
      const pid = (params?.id as string) ?? "new";
      openInEditor(api, `playbook-${pid}`, "playbook", "Playbook", { id: params?.id });
    } else {
      openInEditor(api, `view-${view}`, "view", VIEW_TITLE[view] ?? view, { view });
    }
  }), []);

  useEffect(() => on("openEditor", ({ labId, path }) => {
    const api = apiRef.current; if (!api) return;
    openInEditor(api, `editor:${labId}:${path}`, "editor", path.split("/").pop() ?? "edit", { labId, path });
  }), []);

  return (
    <DockviewReact
      components={components}
      onReady={onReady}
      theme={themeAbyss}
      className="s-ide-dockview h-full w-full"
    />
  );
}
