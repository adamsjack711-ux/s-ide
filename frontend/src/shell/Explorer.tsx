import SectionLabel from "./SectionLabel";
import { emit } from "./bus";
import EngagementTree from "../engagement/EngagementTree";
import AssetsTree from "./AssetsTree";

/**
 * Left Explorer — the engagement's project tree: the active engagement, the
 * discovered asset graph, and quick links into the workspace views. Tools moved
 * to the Build panel (the activity-bar "Build" navigator).
 */
const LINKS = [
  { view: "findings", label: "Findings" },
  { view: "reports", label: "Reports" },
  { view: "learn", label: "Learn" },
] as const;

export default function Explorer() {
  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-sidebar text-sm">
      <EngagementTree />
      <AssetsTree />
      <div className="px-3 pb-1 pt-3">
        <SectionLabel>Workspace</SectionLabel>
      </div>
      {LINKS.map((l) => (
        <button
          key={l.view}
          onClick={() => emit("openView", { view: l.view })}
          className="block w-full px-4 py-1 text-left text-ink-muted hover:bg-nav-hover hover:text-ink-primary"
        >
          {l.label}
        </button>
      ))}
    </div>
  );
}
