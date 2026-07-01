// Workbench Walkthrough — a guided, per-lab tutorial for running the spine
// Workbench against a practice lab.
//
// This is the "doc + jump buttons" style: each step is written out, with a
// button that takes you to the right screen (Labs / Engagements). You perform
// the actions yourself; the walkthrough keeps the end-to-end path in front of
// you. Steps are tailored per lab from /labs/catalog (name, URL, creds, etc.).
import { useCallback, useEffect, useState } from "react";
import { Button, GlassCard, GradientText } from "performative-ui";
import Icon from "../shell/Icon";
import SectionLabel from "../shell/SectionLabel";
import { authFetch } from "../api";
import { emit } from "../shell/bus";

type Lab = {
  id: string;
  name: string;
  summary: string;
  category: string;
  primary_url: string;
  default_creds: string | null;
  port_map: Record<string, number>;
  enabled?: boolean;
};

type Step = {
  title: string;
  body: React.ReactNode;
  action?: { label: string; run: () => void };
};

export default function WorkbenchWalkthrough({ onGoToLabs }: { onGoToLabs: () => void }) {
  const [labs, setLabs] = useState<Lab[] | null>(null);
  const [selId, setSelId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await authFetch("/labs/catalog");
      const data = (await r.json()) as { labs?: Lab[] };
      const enabled = (data.labs ?? []).filter((l) => l.enabled !== false);
      setLabs(enabled);
      setSelId((cur) => cur ?? enabled[0]?.id ?? null);
    } catch {
      setLabs([]);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const goEngagements = () => emit("openView", { view: "spine" });

  const lab = labs?.find((l) => l.id === selId) ?? null;

  // The sub-target address you'd arm: the lab's primary URL, or host:port.
  const subAddr =
    lab?.primary_url ||
    (lab && Object.values(lab.port_map)[0]
      ? `localhost:${Object.values(lab.port_map)[0]}`
      : "the lab's address");

  const steps: Step[] = lab
    ? [
        {
          title: `Start the lab — ${lab.name}`,
          body: (
            <>
              {lab.summary && <p className="mb-1.5">{lab.summary}</p>}
              <p>
                In <b>Labs</b>, build (first time) then <b>Start</b> {lab.name} (a{" "}
                {lab.category} lab). Once it's up it serves at{" "}
                <code className="rounded bg-bg-base px-1 py-0.5 font-mono text-[calc(11px_*_var(--text-scale))] text-accent">
                  {lab.primary_url || subAddr}
                </code>
                {lab.default_creds && (
                  <>
                    {" "}
                    — default creds{" "}
                    <code className="rounded bg-bg-base px-1 py-0.5 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-primary">
                      {lab.default_creds}
                    </code>
                  </>
                )}
                .
              </p>
            </>
          ),
          action: { label: "Go to Labs", run: onGoToLabs },
        },
        {
          title: "Create an engagement",
          body: (
            <p>
              Open <b>Engagements</b> and create one — e.g.{" "}
              <i>{lab.name} practice</i>. The engagement is the authorized context:
              nothing runs against the lab until an engagement arms it.
            </p>
          ),
          action: { label: "Open Engagements", run: goEngagements },
        },
        {
          title: "Declare the lab as a target and arm it",
          body: (
            <p>
              Open your engagement → <b>Targets</b> tab. Declare a target named{" "}
              <i>{lab.name}</i>, add a sub-target with address{" "}
              <code className="rounded bg-bg-base px-1 py-0.5 font-mono text-[calc(11px_*_var(--text-scale))] text-accent">
                {subAddr}
              </code>
              , then click <b>Arm</b> to attach this engagement. Arming is the
              deliberate act that brings the lab into scope.
            </p>
          ),
          action: { label: "Open Engagements", run: goEngagements },
        },
        {
          title: "Run a tool in the Workbench",
          body: (
            <p>
              Switch to the engagement's <b>Workbench</b> tab, pick the armed
              sub-target, and run a tool — start with{" "}
              <code className="rounded bg-bg-base px-1 py-0.5 font-mono text-[calc(11px_*_var(--text-scale))] text-ink-primary">
                connect
              </code>{" "}
              to confirm reachability
              {lab.category?.toLowerCase().includes("web") ? ", then try an HTTP probe" : ""}.
              The run is refused unless the pairing is armed — that's the safety
              gate working.
            </p>
          ),
          action: { label: "Open Engagements", run: goEngagements },
        },
        {
          title: "Promote a finding",
          body: (
            <p>
              When a run confirms something, hit <b>Promote to finding</b>. It's
              born tagged to this engagement × sub-target pairing and rolls up in
              the engagement's <b>Findings</b> and <b>Reporting</b> tabs.
            </p>
          ),
        },
      ]
    : [];

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="border-b border-divider px-3 py-3">
        <SectionLabel>Workbench Walkthrough</SectionLabel>
        <p className="mt-2 text-xs text-ink-muted">
          A step-by-step run of the Workbench against a practice lab. Pick a lab,
          then follow the steps — the buttons jump you to the right screen.
        </p>
      </div>

      {labs === null ? (
        <div className="p-4 text-xs text-ink-dim">Loading labs…</div>
      ) : labs.length === 0 ? (
        <div className="p-4 text-xs text-ink-muted">
          No practice labs available. Add one in the <b>Labs</b> tab first.
        </div>
      ) : (
        <div className="flex min-h-0 flex-1">
          {/* Lab picker */}
          <aside className="flex w-56 shrink-0 flex-col border-r border-divider">
            <div className="shrink-0 border-b border-divider px-3 py-2 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
              Practice labs
            </div>
            <div className="min-h-0 flex-1 overflow-auto">
              {labs.map((l) => (
                <button
                  key={l.id}
                  onClick={() => setSelId(l.id)}
                  className={`flex w-full flex-col gap-0.5 border-b border-divider/60 px-3 py-2.5 text-left ${
                    l.id === selId ? "bg-bg-hover" : "hover:bg-bg-hover/50"
                  }`}
                >
                  <span className="text-[calc(12.5px_*_var(--text-scale))] font-semibold tracking-tight text-ink-primary">{l.name}</span>
                  <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">{l.category}</span>
                </button>
              ))}
            </div>
          </aside>

          {/* Steps for the selected lab */}
          <section className="min-w-0 flex-1 overflow-auto p-4">
            {lab && (
              <h2 className="mb-3 flex items-center gap-2 text-[calc(16px_*_var(--text-scale))] font-bold tracking-tight">
                <Icon name="wrench" size={16} />
                <GradientText>Run the Workbench on {lab.name}</GradientText>
              </h2>
            )}
            <ol className="space-y-2.5">
              {steps.map((s, i) => (
                <GlassCard key={i} className="flex gap-3 p-3">
                  <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent/[0.14] text-[calc(12px_*_var(--text-scale))] font-bold text-accent">
                    {i + 1}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[calc(13px_*_var(--text-scale))] font-semibold tracking-tight text-ink-primary">{s.title}</div>
                    <div className="mt-1 text-[calc(12px_*_var(--text-scale))] leading-relaxed text-ink-muted">{s.body}</div>
                    {s.action && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="mt-2"
                        onClick={s.action.run}
                      >
                        {s.action.label} →
                      </Button>
                    )}
                  </div>
                </GlassCard>
              ))}
            </ol>
          </section>
        </div>
      )}
    </div>
  );
}
