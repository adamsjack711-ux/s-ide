import Icon from "./Icon";

/**
 * Left icon rail (58px). Icon-only. The rail splits into two halves by what the
 * destination *is*:
 *   TOP — engagement-scoped entries. "Engagements" opens an engagement as a TAB
 *         whose workspace holds the Workbench / Map / Findings / Reporting /
 *         Terminal sub-tabs; "Labs" spins up targets to point those tools at.
 *   BOTTOM (below the spacer) — global, untabbable surfaces that replace the
 *         main area full-screen: Reporting, Learn, Settings.
 * Active icon is accent-tinted with an accent ring, matching the design.
 */
export type ActivityItem = { id: string; icon: string; label: string; kind: "panel" | "tab" };

// Clustered top groups (rendered top-to-bottom with dividers between them).
// Targets is the top of the app: the front door is the Targets list, and each
// Target nests its own Engagements / Workbench / Findings / Reporting. Labs now
// live inside Learn, so they're no longer a rail destination.
export const VIEW_GROUPS: ActivityItem[][] = [
  [{ id: "spine", icon: "target", label: "Targets", kind: "tab" }],
];
// Flat view (compat / lookups).
export const VIEW_ITEMS: ActivityItem[] = VIEW_GROUPS.flat();
// Global, untabbable destinations — pinned to the bottom of the rail. Reporting
// is no longer global (it lives inside each Target); Learn now carries Labs.
export const BOTTOM_ITEMS: ActivityItem[] = [
  { id: "learn", icon: "book", label: "Learn", kind: "tab" },
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
      {VIEW_GROUPS.map((group, gi) => (
        <div key={gi} className="flex flex-col items-center gap-1.5">
          {gi > 0 && <span className="my-1 h-px w-6 bg-divider" />}
          {group.map((it) => (
            <RailBtn key={it.id} it={it} active={active === it.id} onSelect={onSelect} />
          ))}
        </div>
      ))}
      <div className="flex-1" />
      {BOTTOM_ITEMS.map((it) => (
        <RailBtn key={it.id} it={it} active={active === it.id} onSelect={onSelect} />
      ))}
    </div>
  );
}
