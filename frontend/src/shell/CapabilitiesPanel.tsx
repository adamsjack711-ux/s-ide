import SectionLabel from "./SectionLabel";

import {
  allToolGroups,
  isCapabilityEnabled,
  setCapabilityEnabled,
  useCapabilities,
  type ToolDescriptor,
} from "./tools";

/** Does this group contain any tool that is gated (not on by default)? */
function gatedTools(tools: ToolDescriptor[]): ToolDescriptor[] {
  return tools.filter((t) => t.tier !== 1 || t.intrusive);
}

/**
 * Settings → Capabilities. The "open but secure" control surface: privileged
 * (Tier 2), external-setup (Tier 3) and intrusive tool groups are OFF until
 * enabled here. Scope + authorization + audit remain the hard backend gates.
 */
export default function CapabilitiesPanel() {
  useCapabilities(); // re-render on toggle

  const groups = allToolGroups()
    .map((g) => ({ ...g, gated: gatedTools(g.tools) }))
    .filter((g) => g.gated.length > 0);

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-sidebar text-sm">
      <div className="border-b border-divider px-3 py-3">
        <SectionLabel>Capabilities</SectionLabel>
        <p className="mt-2 text-xs text-ink-muted">
          Privileged, external-setup, and intrusive tools are off until you enable their group.
          Scope enforcement, authorization, and the audit log stay active regardless.
        </p>
      </div>

      {groups.map((g) => {
        const on = isCapabilityEnabled(g.group);
        const reqs = Array.from(new Set(g.gated.map((t) => t.requires).filter(Boolean)));
        const intrusive = g.gated.some((t) => t.intrusive);
        return (
          <div key={g.group} className="border-b border-divider px-3 py-2">
            <div className="flex items-center gap-2">
              <span className="font-medium text-ink-primary">{g.group}</span>
              <span className="rounded bg-bg-hover px-1.5 text-[calc(10px_*_var(--text-scale))] text-ink-dim">{g.gated.length}</span>
              {intrusive && (
                <span className="rounded bg-amber/15 px-1.5 text-[calc(10px_*_var(--text-scale))] uppercase text-amber" title="Intrusive — authorization required">
                  intrusive
                </span>
              )}
              <button
                onClick={() => setCapabilityEnabled(g.group, !on)}
                className={`ml-auto rounded px-2 py-0.5 text-xs ring-1 ${on ? "bg-success/20 text-success ring-success/40" : "text-ink-muted ring-divider hover:text-ink-primary"}`}
              >
                {on ? "Enabled" : "Enable"}
              </button>
            </div>
            {reqs.length > 0 && (
              <div className="mt-1 truncate text-[calc(11px_*_var(--text-scale))] text-ink-dim" title={reqs.join(" · ")}>
                needs: {reqs.join(" · ")}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
