import Icon from "./Icon";

/**
 * Left icon rail (the design's 58px nav column). Top: Explorer / Build side-panel
 * navigators. Middle: view destinations (open editor tabs). Bottom: Settings.
 * Active icon is accent-tinted with an accent ring, matching the design.
 */
export type ActivityItem = { id: string; icon: string; label: string; kind: "panel" | "tab" };

export const VIEW_ITEMS: ActivityItem[] = [
  { id: "home", icon: "target", label: "Engagements", kind: "tab" },
  { id: "labs", icon: "box", label: "Labs", kind: "tab" },
  { id: "build", icon: "sliders", label: "Build", kind: "tab" },
  { id: "findings", icon: "filter", label: "Findings", kind: "tab" },
  { id: "graph", icon: "share", label: "Graph", kind: "tab" },
  { id: "reports", icon: "chart", label: "Reporting", kind: "tab" },
  { id: "learn", icon: "book", label: "Learn", kind: "tab" },
];
export const BOTTOM_ITEMS: ActivityItem[] = [
  { id: "settings", icon: "gear", label: "Settings", kind: "tab" },
];

function RailBtn({ it, active, onSelect }: { it: ActivityItem; active: boolean; onSelect: (it: ActivityItem) => void }) {
  return (
    <button
      title={it.label}
      onClick={() => onSelect(it)}
      className={`relative flex h-[42px] w-[42px] items-center justify-center rounded-[11px] border transition-colors ${
        active ? "border-accent/25 bg-accent/[0.12] text-accent" : "border-transparent text-ink-dim hover:bg-nav-hover hover:text-ink-primary"
      }`}
    >
      {active && <span className="absolute -left-[10px] h-5 w-[3px] rounded-r bg-accent" />}
      <Icon name={it.icon} size={20} />
    </button>
  );
}

export default function ActivityBar({
  active,
  onSelect,
}: {
  active: string;
  onSelect: (it: ActivityItem) => void;
}) {
  return (
    <div className="flex w-[58px] shrink-0 flex-col items-center gap-1.5 border-r border-divider bg-bg-sidebar py-2.5">
      {VIEW_ITEMS.map((it) => (
        <RailBtn key={it.id} it={it} active={active === it.id} onSelect={onSelect} />
      ))}
      <div className="flex-1" />
      {BOTTOM_ITEMS.map((it) => (
        <RailBtn key={it.id} it={it} active={active === it.id} onSelect={onSelect} />
      ))}
    </div>
  );
}
