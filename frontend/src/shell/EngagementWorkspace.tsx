import WorkbenchView from "../build/WorkbenchView";
import GraphView from "../graph/GraphView";
import FindingsView from "../engagement/FindingsView";
import ReportsView from "../engagement/ReportsView";
import TerminalView from "./TerminalView";
import Icon from "./Icon";
import { ENGAGEMENT_SUB_TABS, setEngagementSubTab, type EngagementSubTab } from "../lib/engagementTabs";

/**
 * The body of an engagement tab: a secondary sub-tab strip
 * (Workbench / Map / Findings / Terminal) over one visible surface at a time.
 * All four surfaces read the active engagement id internally — activating the
 * engagement tab pins it — so they're already scoped to THIS engagement.
 */

const SUB_TABS: { id: EngagementSubTab; icon: string; label: string }[] = [
  { id: "build", icon: "wrench", label: "Workbench" },
  { id: "graph", icon: "nodes", label: "Map" },
  { id: "findings", icon: "flag", label: "Findings" },
  { id: "reports", icon: "chart", label: "Reporting" },
  { id: "terminal", icon: "terminal", label: "Terminal" },
];

export default function EngagementWorkspace({
  engagementId,
  subTab,
}: {
  engagementId: string;
  subTab: EngagementSubTab;
}) {
  const active: EngagementSubTab = ENGAGEMENT_SUB_TABS.includes(subTab) ? subTab : "build";

  function surface() {
    switch (active) {
      case "build": return <WorkbenchView />;
      case "graph": return <GraphView />;
      case "findings": return <FindingsView />;
      case "reports": return <ReportsView />;
      case "terminal": return <TerminalView />;
      default: return <WorkbenchView />;
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Sub-tab strip — engagement-scoped surfaces. */}
      <div className="flex shrink-0 items-stretch gap-1 border-b border-divider bg-bg-sidebar px-2 py-1">
        {SUB_TABS.map((t) => {
          const on = t.id === active;
          return (
            <button
              key={t.id}
              onClick={() => setEngagementSubTab(engagementId, t.id)}
              className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[calc(12px_*_var(--text-scale))] transition-colors ${
                on
                  ? "bg-accent/[0.12] text-accent"
                  : "text-ink-dim hover:bg-nav-hover hover:text-ink-primary"
              }`}
            >
              <Icon name={t.icon} size={14} />
              {t.label}
            </button>
          );
        })}
      </div>
      <div className="min-h-0 flex-1 overflow-hidden">{surface()}</div>
    </div>
  );
}
