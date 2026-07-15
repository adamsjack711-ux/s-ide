/**
 * Built-in view registrations — the manifest that populates the view registry
 * with the shell's stock destinations. MainArea imports this once for its
 * side effects; after that MainArea renders purely from the registry and never
 * needs editing to add a panel.
 *
 * This is the exact analogue of shell/tools/index.ts for tools: a thin file
 * whose only job is to stitch feature modules into the registry the shell
 * consumes. Adding a contributed panel = one new file + one import line here.
 */
import HomeView from "../home/HomeView";
import LearningView from "../learn/LearningView";
import SettingsView from "../settings/SettingsView";
import WorkbenchView from "../build/WorkbenchView";
import SpineView from "../spine/SpineView";
import PlaybookEditor from "../build/PlaybookEditor";
import ToolPanel from "../panels/ToolPanel";
import EngagementWorkspace from "./EngagementWorkspace";
import { toolById } from "./tools";
import { useIsolationOk } from "../labs/useIsolationOk";
import { useEngagementTabs } from "../lib/engagementTabs";
import { registerView, type ViewParams } from "./views";

// The engagement tab body reads its own MDI state (active tab + sub-tab) from
// the store, so it stays self-contained as a registered view.
function EngagementBody() {
  const { activeId, subTab } = useEngagementTabs();
  return activeId ? (
    <EngagementWorkspace engagementId={activeId} subTab={subTab} />
  ) : (
    <HomeView />
  );
}

function PlaybookHost({ params }: { params: ViewParams }) {
  const isolationOk = useIsolationOk();
  return <PlaybookEditor playbookId={params.id} isolationOk={isolationOk} />;
}

function ToolHost({ params }: { params: ViewParams }) {
  const t = toolById(params.toolId);
  return t ? <ToolPanel tool={t} /> : <div className="p-4 text-ink-dim">Unknown tool.</div>;
}

// ── Full-screen destinations ────────────────────────────────────────────────
registerView({ id: "home", component: HomeView });
registerView({ id: "spine", component: SpineView });
registerView({ id: "learn", component: () => <LearningView /> });
registerView({ id: "settings", component: SettingsView });
// Labs live ONLY inside Learning — any "open labs" routes there.
registerView({ id: "labs", component: () => <LearningView initialTab="labs" /> });
registerView({ id: "playbook", component: PlaybookHost });
registerView({ id: "tool", component: ToolHost });
registerView({ id: "engagement", component: EngagementBody });

// ── Engagement sub-tab markers ──────────────────────────────────────────────
// These surfaces are rendered by EngagementWorkspace, not the main slot; the
// registry only needs to know that `openView(id)` routes into the active
// engagement tab. `build` also carries a fallback component for the (currently
// unreachable) no-engagement case, preserving prior behaviour.
registerView({ id: "build", component: WorkbenchView, subTab: true });
registerView({ id: "graph", subTab: true });
registerView({ id: "findings", subTab: true });
registerView({ id: "reports", subTab: true });
registerView({ id: "terminal", subTab: true });

// ── Contributed panels ──────────────────────────────────────────────────────
// Feature panels self-register on import. Each is one self-contained file that
// reads the model, subscribes to the bus, and registers its own view + command
// — no existing panel is edited. Add a panel by adding its import below.
import "../demo/ActiveEngagementPanel";
// The feature suite (F1–F9) + the Phase-0 selection-echo proof. Each feature is
// a self-registering module behind this single manifest import; see
// features/index.ts. Adding a feature never edits this file.
import "../features";
