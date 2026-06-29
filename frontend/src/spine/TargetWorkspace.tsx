// TargetWorkspace — everything that lives INSIDE a Target.
//
// The IA is Target-first: the front door is the Targets list; opening a Target
// drills into this workspace, where its Engagements, Workbench, Findings and
// Reporting are all scoped to that one Target.
import { useState } from "react";
import { Button, GradientText } from "performative-ui";
import Icon from "../shell/Icon";
import type { Engagement } from "../lib/engagement";
import type { Target } from "../lib/spine";
import EngagementsTab from "./EngagementsTab";
import WorkbenchTab from "./WorkbenchTab";
import FindingsTab from "./FindingsTab";
import TargetReporting from "./TargetReporting";

type Inner = "engagements" | "workbench" | "findings" | "reporting";

const TABS: { id: Inner; icon: string; label: string }[] = [
  { id: "engagements", icon: "shield", label: "Engagements" },
  { id: "workbench", icon: "wrench", label: "Workbench" },
  { id: "findings", icon: "flag", label: "Findings" },
  { id: "reporting", icon: "chart", label: "Reporting" },
];

const PROV_PILL: Record<string, string> = {
  lab: "bg-accent/[0.13] text-accent ring-1 ring-accent/30",
  owned: "bg-low/[0.13] text-low ring-1 ring-low/30",
  external: "bg-high/[0.13] text-high ring-1 ring-high/30",
};

export default function TargetWorkspace({
  target,
  engagements,
  reload,
  onError,
  onBack,
}: {
  target: Target;
  engagements: Engagement[];
  reload: () => Promise<void>;
  onError: (m: string) => void;
  onBack: () => void;
}) {
  const [tab, setTab] = useState<Inner>("engagements");
  const subCount = (target.sub_targets ?? []).length;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Target header + back to Targets */}
      <div className="flex shrink-0 items-center gap-3 border-b border-divider px-3 py-2.5">
        <Button variant="ghost" size="sm" onClick={onBack}>
          ← Targets
        </Button>
        <Icon name="box" size={16} />
        <h2 className="text-[17px] font-bold tracking-tight leading-none">
          <GradientText>{target.name}</GradientText>
        </h2>
        <span className={`rounded px-1.5 py-0.5 text-[9.5px] font-semibold ${PROV_PILL[target.provenance] ?? ""}`}>
          {target.provenance}
        </span>
        <span className="text-[11.5px] text-ink-muted"><span className="">{subCount}</span> sub-target{subCount === 1 ? "" : "s"}</span>
      </div>

      {/* Inner tabs */}
      <div className="flex shrink-0 items-center gap-1 border-b border-divider bg-bg-sidebar px-2">
        {TABS.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 border-b-2 px-3 py-2 text-[12.5px] font-medium transition-colors ${
                active ? "border-accent text-ink-primary" : "border-transparent text-ink-muted hover:text-ink-primary"
              }`}
            >
              <Icon name={t.icon} size={15} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Body — all scoped to this target */}
      <div className="min-h-0 flex-1 overflow-hidden">
        {tab === "engagements" ? (
          <EngagementsTab
            targets={[target]}
            engagements={engagements}
            reload={reload}
            onError={onError}
            onOpenWorkbench={() => setTab("workbench")}
            restrictTargetId={target.id}
          />
        ) : tab === "workbench" ? (
          <WorkbenchTab targets={[target]} onError={onError} />
        ) : tab === "findings" ? (
          <FindingsTab targets={[target]} engagements={engagements} lockTargetId={target.id} />
        ) : (
          <TargetReporting target={target} engagements={engagements} />
        )}
      </div>
    </div>
  );
}
