import { useEffect, useState } from "react";
import ActivityBar, { type ActivityItem } from "./shell/ActivityBar";
import TopBar from "./shell/TopBar";
import MainArea from "./shell/MainArea";
import StatusBar from "./shell/StatusBar";
import CommandPalette from "./shell/CommandPalette";
import PromoteModal from "./engagement/PromoteModal";
import MethodPromote from "./engagement/MethodPromote";
import AttestationModal from "./safety/AttestationModal";
import CopilotRail from "./copilot/CopilotRail";
import { emit } from "./shell/bus";
import { BACKEND_URL } from "./api";
import "./lib/theme"; // self-applies dark/light on import

/**
 * The IDE shell. Title bar on top; a slim activity bar toggles the left side
 * panel (Explorer / Build) and opens destinations as editor tabs; the center is
 * a tabbed dockview editor (Home + tools + playbook + views + Monaco) with a
 * bottom Output dock; the Copilot rides on the right; status bar at the bottom.
 */
export default function App() {
  const [activeNav, setActiveNav] = useState("home");
  const [copilot, setCopilot] = useState(true);
  const [narrow, setNarrow] = useState(typeof window !== "undefined" && window.innerWidth < 820);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const onResize = () => setNarrow(window.innerWidth < 820);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Wait for the bundled sidecar to finish booting (it takes a few seconds in
  // the packaged app) before rendering views — otherwise their first fetch
  // races the backend and shows "Failed to fetch".
  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const r = await fetch(`${BACKEND_URL}/health`);
        if (r.ok) return alive && setReady(true);
      } catch {
        /* not up yet */
      }
      if (alive) setTimeout(poll, 500);
    };
    poll();
    return () => {
      alive = false;
    };
  }, []);

  if (!ready) {
    return (
      <div className="flex h-screen w-full flex-col items-center justify-center gap-3 bg-bg-base text-ink-dim">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent ring-1 ring-accent/30 animate-pulse">✦</div>
        <div className="text-sm">Starting s-ide backend…</div>
      </div>
    );
  }

  function onActivity(it: ActivityItem) {
    setActiveNav(it.id);
    emit("openView", { view: it.id as any });
  }

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden bg-bg-base text-ink-primary">
      <TopBar />
      <div className="flex min-h-0 flex-1">
        <ActivityBar active={activeNav} onSelect={onActivity} />
        <div className="min-w-0 flex-1">
          <MainArea />
        </div>
        {!narrow &&
          (copilot ? (
            <CopilotRail onClose={() => setCopilot(false)} />
          ) : (
            <button
              onClick={() => setCopilot(true)}
              title="Show copilot"
              className="w-6 shrink-0 border-l border-divider bg-bg-sidebar text-accent hover:bg-nav-hover"
            >
              ◇
            </button>
          ))}
      </div>
      <StatusBar />
      <CommandPalette />
      <PromoteModal />
      <MethodPromote />
      <AttestationModal />
    </div>
  );
}
