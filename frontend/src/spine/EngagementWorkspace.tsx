// EngagementWorkspace — everything that lives INSIDE an Engagement.
//
// The IA is Engagement-first: the front door is the Engagements list; opening an
// Engagement drills into this workspace, where its Targets, Workbench, Findings
// and Reporting all live — scoped to that one engagement. Targets are nested
// here because authorization flows from the engagement that arms them, never
// from a target existing on its own.
import { useMemo, useState } from "react";
import { Button, GradientText, StatusDot } from "performative-ui";
import Icon from "../shell/Icon";
import type { Engagement } from "../lib/engagement";
import type { Target } from "../lib/spine";
import TargetsTab from "./TargetsTab";
import WorkbenchTab from "./WorkbenchTab";
import FindingsTab from "./FindingsTab";
import EngagementReporting from "./EngagementReporting";

type Inner = "targets" | "workbench" | "findings" | "reporting";

const TABS: { id: Inner; icon: string; label: string }[] = [
  { id: "targets", icon: "target", label: "Targets" },
  { id: "workbench", icon: "wrench", label: "Workbench" },
  { id: "findings", icon: "flag", label: "Findings" },
  { id: "reporting", icon: "chart", label: "Reporting" },
];

const ARMED_COLOR = "var(--accent)";

export default function EngagementWorkspace({
  engagement,
  targets,
  engagements,
  reload,
  onError,
  onBack,
}: {
  engagement: Engagement;
  targets: Target[];
  engagements: Engagement[];
  reload: () => Promise<void>;
  onError: (m: string) => void;
  onBack: () => void;
}) {
  const [tab, setTab] = useState<Inner>("targets");

  // Targets scoped to THIS engagement: each kept target carries only the
  // sub-targets this engagement arms, so the Workbench shows just this
  // engagement's live pairings.
  const engagementTargets = useMemo<Target[]>(
    () =>
      targets
        .map((t) => ({
          ...t,
          sub_targets: (t.sub_targets ?? []).filter(
            (s) => s.armed && s.arming?.engagement_id === engagement.id,
          ),
        }))
        .filter((t) => (t.sub_targets ?? []).length > 0),
    [targets, engagement.id],
  );

  const armedCount = useMemo(
    () => engagementTargets.reduce((n, t) => n + (t.sub_targets ?? []).length, 0),
    [engagementTargets],
  );

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Engagement header + back to Engagements */}
      <div className="flex shrink-0 items-center gap-3 border-b border-divider px-3 py-2.5">
        <Button variant="ghost" size="sm" onClick={onBack}>
          ← Engagements
        </Button>
        <Icon name="shield" size={16} />
        <h2 className="text-[calc(17px_*_var(--text-scale))] font-bold tracking-tight leading-none">
          <GradientText>{engagement.name}</GradientText>
        </h2>
        <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold text-ink-muted ring-1 ring-divider">
          {engagement.provenance}
        </span>
        <span className="rounded bg-bg-hover px-1.5 py-0.5 text-[calc(9.5px_*_var(--text-scale))] font-semibold text-ink-muted ring-1 ring-divider">
          {engagement.type}
        </span>
        <span className="flex items-center gap-1.5 text-[calc(11.5px_*_var(--text-scale))] text-ink-muted">
          {armedCount > 0 && <StatusDot color={ARMED_COLOR} />}
          <span className="">{armedCount}</span> armed sub-target{armedCount === 1 ? "" : "s"}
        </span>
      </div>

      {/* Inner tabs */}
      <div className="flex shrink-0 items-center gap-1 border-b border-divider bg-bg-sidebar px-2">
        {TABS.map((t) => {
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 border-b-2 px-3 py-2 text-[calc(12.5px_*_var(--text-scale))] font-medium transition-colors ${
                active ? "border-accent text-ink-primary" : "border-transparent text-ink-muted hover:text-ink-primary"
              }`}
            >
              <Icon name={t.icon} size={15} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Body — all scoped to this engagement */}
      <div className="min-h-0 flex-1 overflow-hidden">
        {tab === "targets" ? (
          <TargetsTab
            targets={targets}
            engagements={[engagement]}
            reload={reload}
            onError={onError}
          />
        ) : tab === "workbench" ? (
          <WorkbenchTab targets={engagementTargets} onError={onError} />
        ) : tab === "findings" ? (
          <FindingsTab targets={targets} engagements={engagements} lockEngagementId={engagement.id} />
        ) : (
          <EngagementReporting engagement={engagement} targets={targets} />
        )}
      </div>
    </div>
  );
}
