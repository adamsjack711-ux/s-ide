import type { CSSProperties } from "react";
import Icon from "./Icon";
import EngagementSwitcher from "./EngagementSwitcher";

/**
 * Full-width title bar (the design's top bar): brand on the left, a centered
 * command-palette trigger, the active engagement on the right. On macOS the
 * window is `hiddenInset`, so the bar reserves left room for the traffic lights.
 * The bar drags the window; the palette trigger opts out.
 */
export default function TopBar() {
  const isMac = (window as any).nt?.platform === "darwin";

  const drag = { WebkitAppRegion: "drag" } as CSSProperties;
  const noDrag = { WebkitAppRegion: "no-drag" } as CSSProperties;
  const mod = isMac ? "⌘" : "Ctrl";

  return (
    <div
      className="flex h-[46px] shrink-0 items-center gap-4 border-b border-divider bg-bg-sidebar text-xs"
      style={{ ...drag, paddingLeft: isMac ? 80 : 12, paddingRight: 12 }}
    >
      <div className="flex items-center gap-1.5">
        <span className="flex h-[26px] w-[26px] items-center justify-center rounded-[7px] bg-accent/15 text-accent ring-1 ring-accent/30">
          <Icon name="shield" size={15} />
        </span>
        <span className="font-semibold tracking-tight text-ink-primary">S-IDE</span>
      </div>

      <button
        onClick={() => window.dispatchEvent(new CustomEvent("s-ide:palette"))}
        style={noDrag}
        className="mx-auto flex h-[30px] w-full max-w-[520px] items-center gap-2.5 rounded-lg border border-divider bg-bg-base px-3 text-ink-dim hover:border-borderBright"
      >
        <Icon name="search" size={14} />
        <span className="text-[calc(12.5px_*_var(--text-scale))]">Search commands, tools, findings…</span>
        <span className="ml-auto font-mono text-[calc(11px_*_var(--text-scale))] text-ink-dim">{mod}K</span>
      </button>

      <EngagementSwitcher />
    </div>
  );
}
