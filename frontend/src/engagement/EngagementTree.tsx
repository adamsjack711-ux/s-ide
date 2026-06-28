import { useEffect, useState } from "react";
import SectionLabel from "../shell/SectionLabel";

import {
  createEngagement,
  listEngagements,
  setActiveEngagementId,
  useActiveEngagementId,
  type Engagement,
} from "../lib/engagement";
import { openEngagementWindow } from "../lib/windowEngagement";

/**
 * The engagement-as-project spine, in the Explorer. Lists engagements, creates
 * them, and sets the active one (which `api.ts` then attaches to every backend
 * write via the X-MHP-Engagement-Id header).
 */
export default function EngagementTree() {
  const activeId = useActiveEngagementId();
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");

  async function refresh() {
    try {
      setEngagements(await listEngagements());
    } catch {
      /* backend not up yet */
    }
  }
  useEffect(() => {
    void refresh();
  }, []);

  async function create() {
    const n = name.trim();
    if (!n) return;
    const e = await createEngagement({ name: n, scope: [], exclusions: [], notes: "" });
    setName("");
    setCreating(false);
    await refresh();
    setActiveEngagementId(e.id);
  }

  return (
    <div className="border-b border-divider pb-2">
      <div className="flex items-center justify-between px-3 pb-1 pt-3">
        <SectionLabel>Engagement</SectionLabel>
        <button
          onClick={() => setCreating((c) => !c)}
          className="text-ink-dim hover:text-ink-primary"
          title="New engagement"
        >
          +
        </button>
      </div>

      {creating && (
        <div className="flex gap-1 px-3 py-1">
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && create()}
            placeholder="Engagement name"
            className="w-full rounded bg-bg-card px-2 py-1 text-xs outline-none ring-1 ring-divider focus:ring-accent"
          />
          <button onClick={create} className="rounded bg-accent px-2 text-xs text-bg-base">
            Add
          </button>
        </div>
      )}

      {engagements.length === 0 ? (
        <div className="px-4 py-1 text-xs text-ink-dim">No engagements — create one to begin.</div>
      ) : (
        engagements.map((e) => (
          <div key={e.id} className={`group flex items-center ${e.id === activeId ? "bg-nav-active" : "hover:bg-nav-hover"}`}>
            <button
              onClick={() => setActiveEngagementId(e.id)}
              className={`flex-1 truncate px-4 py-1 text-left ${e.id === activeId ? "font-medium text-ink-primary" : "text-ink-muted"}`}
            >
              <span className="mr-1.5 text-accent">{e.id === activeId ? "▸" : "·"}</span>
              {e.name}
            </button>
            <button
              onClick={() => openEngagementWindow(e.id)}
              title="Open in new window"
              className="px-2 text-ink-dim opacity-0 hover:text-ink-primary group-hover:opacity-100"
            >
              ⧉
            </button>
          </div>
        ))
      )}
    </div>
  );
}
