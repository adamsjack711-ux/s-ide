import { useEffect, useState } from "react";
import ActivityBar, { type ActivityItem } from "./shell/ActivityBar";
import TopBar from "./shell/TopBar";
import MainArea from "./shell/MainArea";
import StatusBar from "./shell/StatusBar";
import CommandPalette from "./shell/CommandPalette";
import { ToastProvider } from "./shell/toast";
import { useGlobalKeymap } from "./shell/keymap";
import PromoteModal from "./engagement/PromoteModal";
import MethodPromote from "./engagement/MethodPromote";
import AttestationModal from "./safety/AttestationModal";
import CopilotRail from "./copilot/CopilotRail";
import { emit, on } from "./shell/bus";
import { BACKEND_URL } from "./api";
import "./lib/theme"; // self-applies dark/light on import
import "./lib/fonts"; // self-applies --text-scale / --mono-font-px on import

/**
 * The IDE shell. Title bar on top; a slim activity bar toggles the left side
 * panel (Explorer / Build) and opens destinations as editor tabs; the center is
 * a tabbed dockview editor (Home + tools + playbook + views + Monaco) with a
 * bottom Output dock; the Copilot rides on the right; status bar at the bottom.
 */
export default function App() {
  const [activeNav, setActiveNav] = useState("spine");
  // Copilot is hidden until explicitly asked for — the AI should not feel
  // ambiently present. The open/closed choice is remembered across launches.
  const [copilot, setCopilotState] = useState<boolean>(() => {
    try {
      return localStorage.getItem("s-ide:copilot-open") === "1";
    } catch {
      return false;
    }
  });
  const setCopilot = (v: boolean) => {
    setCopilotState(v);
    try {
      localStorage.setItem("s-ide:copilot-open", v ? "1" : "0");
    } catch {
      /* ignore */
    }
  };
  const [narrow, setNarrow] = useState(typeof window !== "undefined" && window.innerWidth < 820);
  const [ready, setReady] = useState(false);

  // Global keymap + shell command registration (Foundation lane). Mounted once.
  useGlobalKeymap();

  // Activating an engagement tab is a tab selection, not a rail destination —
  // clear the rail highlight so no global icon looks selected while a tab owns
  // the main area.
  useEffect(() => on("engagementTabActivated", () => setActiveNav("")), []);

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
      <ToastProvider />
      <PromoteModal />
      <MethodPromote />
      <AttestationModal />
    </div>
  );
}
