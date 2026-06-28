import { useState } from "react";
import LabsView from "./LabsView";
import LabAuthoring from "../learn/LabAuthoring";

/** Activity-bar "Labs" surface: run/arm/reset/solve labs, or author one. */
export default function LabsPanel() {
  const [tab, setTab] = useState<"labs" | "author">("labs");
  return (
    <div className="flex h-full flex-col overflow-hidden bg-bg-sidebar">
      <div className="flex gap-1 border-b border-divider px-2 py-1.5 text-xs">
        {(["labs", "author"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded px-2 py-0.5 ${tab === t ? "bg-nav-active text-ink-primary" : "text-ink-muted hover:text-ink-primary"}`}
          >
            {t === "labs" ? "Labs" : "Author"}
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1">{tab === "labs" ? <LabsView /> : <LabAuthoring />}</div>
    </div>
  );
}
