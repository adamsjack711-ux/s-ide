// Bundled themes — the curated set shown as a gallery in Settings → Appearance.
// Midnight & Graphite are the app's own palettes (lifted from index.css) so the
// top Light/Dark/System control stays a pure base-mode switch and these live
// here as pickable themes. The rest are .side fixtures (imported raw + parsed).
import paper from "./fixtures/paper.side?raw";
import highContrast from "./fixtures/high-contrast.side?raw";
import solarized from "./fixtures/solarized.side?raw";
import terminalGreen from "./fixtures/terminal-green.side?raw";
import type { SideTheme } from "./sideSchema";

const MIDNIGHT: SideTheme = {
  version: "1.0",
  kind: "theme",
  name: "Midnight",
  author: "builtin",
  theme: {
    "--bg-base": "#0a0e15",
    "--bg-surface": "#0d1320",
    "--bg-elevated": "#131c2c",
    "--bg-hover": "#1a2433",
    "--bg-active": "#1e2c40",
    "--text-primary": "#dde3ee",
    "--text-secondary": "#8b95a8",
    "--text-muted": "#586173",
    "--border": "#1c2533",
    "--border-bright": "#26344a",
    "--accent": "#39d98a",
    "--critical": "#ff5d6c",
    "--high": "#ff9340",
    "--medium": "#ffc043",
    "--low": "#4d9fff",
    "--success": "#39d98a",
  },
};

const GRAPHITE: SideTheme = {
  version: "1.0",
  kind: "theme",
  name: "Graphite",
  author: "builtin",
  theme: {
    "--bg-base": "#16181d",
    "--bg-surface": "#1c1f26",
    "--bg-elevated": "#242832",
    "--bg-hover": "#22262f",
    "--bg-active": "#2a2f3a",
    "--text-primary": "#e6e9ef",
    "--text-secondary": "#959cab",
    "--text-muted": "#646b79",
    "--border": "#2a2e38",
    "--border-bright": "#383e4a",
    "--accent": "#39d98a",
    "--critical": "#ff5d6c",
    "--high": "#ff9340",
    "--medium": "#ffc043",
    "--low": "#4d9fff",
    "--success": "#39d98a",
  },
};

export const BUILTIN_THEMES: SideTheme[] = [
  MIDNIGHT,
  GRAPHITE,
  JSON.parse(paper) as SideTheme,
  JSON.parse(highContrast) as SideTheme,
  JSON.parse(solarized) as SideTheme,
  JSON.parse(terminalGreen) as SideTheme,
];
