import type { SideTheme } from "../themes/sideSchema";

/**
 * A tiny mock of the app UI rendered in a theme's own colors — so the gallery
 * shows what a theme *looks like* rather than a row of raw swatches. Pure inline
 * styles from the theme's token map (no dependency on the active theme).
 */
export default function ThemeMiniPreview({ theme }: { theme: SideTheme }) {
  const t = theme.theme;
  const c = (k: string, fallback = "#888") => t[k] ?? fallback;
  const sevs = ["--critical", "--high", "--medium", "--low", "--success"];

  return (
    <div
      className="flex h-[84px] w-full overflow-hidden rounded-md"
      style={{ background: c("--bg-base"), border: `1px solid ${c("--border")}` }}
    >
      {/* left rail */}
      <div
        className="flex w-3.5 flex-col items-center gap-1 pt-1.5"
        style={{ background: c("--bg-surface"), borderRight: `1px solid ${c("--border")}` }}
      >
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: c("--accent") }} />
        <span className="h-1 w-1 rounded-full" style={{ background: c("--text-muted") }} />
        <span className="h-1 w-1 rounded-full" style={{ background: c("--text-muted") }} />
      </div>

      {/* main */}
      <div className="flex min-w-0 flex-1 flex-col gap-1 p-1.5">
        {/* title bar */}
        <div className="flex items-center gap-1">
          <span className="h-1.5 w-8 rounded-sm" style={{ background: c("--text-primary") }} />
          <span className="ml-auto h-2.5 w-5 rounded-sm" style={{ background: c("--accent") }} />
        </div>
        {/* panel */}
        <div
          className="flex flex-1 flex-col gap-1 rounded-sm p-1"
          style={{ background: c("--bg-elevated"), border: `1px solid ${c("--border")}` }}
        >
          <span className="h-1 w-10 rounded-sm" style={{ background: c("--text-primary") }} />
          <span className="h-1 w-14 rounded-sm" style={{ background: c("--text-secondary") }} />
          {/* severity dots */}
          <div className="mt-auto flex items-center gap-1">
            {sevs.map((s) => (
              <span key={s} className="h-1.5 w-1.5 rounded-full" style={{ background: c(s) }} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
