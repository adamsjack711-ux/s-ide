// LabsWorkspace — the ENTIRE active-lab surface, confined to Learning.
//
// Active colima labs live here and ONLY here: the catalog grid, the open-lab
// MDI strip, each lab's console/detail (LabTabView), and the lab-source editor
// all render inside this component (Learn → Labs). Labs never open as tabs in
// the main area — opening or activating a lab just swaps the pane in here.
import { useEffect, useState } from "react";
import LabsView from "./LabsView";
import LabTabView from "./LabTabView";
import EditorPanel from "../panels/EditorPanel";
import { useLabTabs, activateLabTab, closeLabTab } from "../lib/labTabs";
import { on } from "../shell/bus";

type Pane =
  | { kind: "catalog" }
  | { kind: "lab"; labId: string }
  | { kind: "editor"; labId: string; path: string };

export default function LabsWorkspace() {
  const { tabs, activeId } = useLabTabs();
  const [pane, setPane] = useState<Pane>({ kind: "catalog" });

  // Opening / activating a lab swaps the pane here — it does NOT leave Learning.
  useEffect(() => on("labTabOpened", ({ labId }) => setPane({ kind: "lab", labId })), []);
  useEffect(() => on("labTabActivated", ({ labId }) => setPane({ kind: "lab", labId })), []);
  // Lab-source "fix in place" editor — also stays inside Learning.
  useEffect(() => on("openEditor", ({ labId, path }) => setPane({ kind: "editor", labId, path })), []);

  // If the lab a pane points at is closed, fall back to the catalog.
  useEffect(() => {
    if (pane.kind === "lab" && !tabs.some((t) => t.id === pane.labId)) {
      setPane({ kind: "catalog" });
    }
  }, [tabs, pane]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Lab MDI strip — Catalog + each open lab. Confined to the Labs area. */}
      <div className="flex shrink-0 items-stretch gap-px overflow-x-auto border-b border-divider bg-bg-sidebar">
        <button
          onClick={() => setPane({ kind: "catalog" })}
          className={`flex items-center gap-2 border-r border-divider px-3 py-1.5 text-[calc(12px_*_var(--text-scale))] ${
            pane.kind === "catalog" ? "bg-bg-base text-ink-primary" : "text-ink-dim hover:text-ink-primary"
          }`}
        >
          Catalog
        </button>
        {tabs.map((t) => {
          const active = pane.kind !== "catalog" && t.id === activeId && (pane.kind !== "lab" || pane.labId === t.id);
          return (
            <div
              key={t.id}
              className={`group flex items-center gap-2 border-r border-divider px-3 py-1.5 text-[calc(12px_*_var(--text-scale))] ${
                active ? "bg-bg-base text-ink-primary" : "text-ink-dim hover:text-ink-primary"
              }`}
            >
              {active && <span className="h-1.5 w-1.5 rounded-full bg-accent" />}
              <button
                onClick={() => {
                  activateLabTab(t.id);
                  setPane({ kind: "lab", labId: t.id });
                }}
                title={t.primaryUrl || t.name}
                className="max-w-[160px] truncate"
              >
                {t.name}
              </button>
              <button
                onClick={() => closeLabTab(t.id)}
                title="Close lab"
                className="text-ink-dim opacity-0 hover:text-danger group-hover:opacity-100"
              >
                ×
              </button>
            </div>
          );
        })}
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
        {pane.kind === "catalog" ? (
          <LabsView />
        ) : pane.kind === "lab" ? (
          <LabTabView labId={pane.labId} />
        ) : (
          <EditorPanel labId={pane.labId} path={pane.path} />
        )}
      </div>
    </div>
  );
}
