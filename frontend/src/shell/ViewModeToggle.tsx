import Icon from "./Icon";
import { useViewMode, type ViewMode } from "../lib/viewMode";

/**
 * Small two-button segmented control to switch a collection between grid and
 * list. Persists under `storageKey` via useViewMode; returns the active mode to
 * the caller through the hook (read it with the same key).
 */
export default function ViewModeToggle({ storageKey }: { storageKey: string }) {
  const [mode, setMode] = useViewMode(storageKey);
  const btn = (m: ViewMode, icon: string, label: string) => (
    <button
      title={label}
      onClick={() => setMode(m)}
      className={`flex h-7 w-7 items-center justify-center rounded-md transition-colors ${
        mode === m ? "bg-accent/[0.14] text-accent" : "text-ink-dim hover:text-ink-primary"
      }`}
    >
      <Icon name={icon} size={15} />
    </button>
  );
  return (
    <div className="flex items-center gap-0.5 rounded-lg border border-divider bg-bg-base p-0.5">
      {btn("grid", "grid", "Grid view")}
      {btn("list", "list", "List view")}
    </div>
  );
}
