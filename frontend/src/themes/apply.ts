// Apply engine — injects a validated .side token set onto <html> as inline CSS
// vars. Inline element styles win over both :root and :root.light stylesheet
// rules, so a .side theme fully overrides the bundled palette.
//
// Two var families are driven: the hex family (--bg-base, --accent, --critical…
// used by inline style={{}} colors) and the rgb-triplet family (--*-rgb,
// consumed by every Tailwind color class). A .side file only carries the hex
// family; we derive the triplets here. Optional tokens are derived from the
// required ones so a theme never has to spell out all ~50 vars.
import { hexToRgb, lighten } from "../lib/accent";
import { validateSide } from "./validate";
import { type SideTheme } from "./sideSchema";

// .side hex token → the rgb-triplet var name(s) it should drive (Tailwind side).
const RGB_MAP: Record<string, string[]> = {
  "--bg-base": ["--bg-base-rgb"],
  "--bg-surface": ["--bg-sidebar-rgb", "--bg-panel-rgb"],
  "--bg-elevated": ["--bg-card-rgb"],
  "--bg-hover": ["--bg-nav-hover-rgb", "--bg-row-alt-rgb"],
  "--bg-active": ["--bg-nav-active-rgb"],
  "--text-primary": ["--ink-primary-rgb"],
  "--text-secondary": ["--ink-muted-rgb"],
  "--text-muted": ["--ink-dim-rgb"],
  "--border": ["--border-rgb", "--divider-rgb"],
  "--border-bright": ["--border-bright-rgb"],
  "--accent": ["--accent-rgb", "--phos-rgb"],
  "--accent-bright": ["--accent-bright-rgb"],
  "--accent-dim": ["--accent-dim-rgb"],
  "--text-accent": ["--text-accent-rgb"],
  "--critical": ["--critical-rgb", "--danger-rgb"],
  "--high": ["--high-rgb"],
  "--medium": ["--medium-rgb", "--amber-rgb"],
  "--low": ["--low-rgb"],
  "--success": ["--success-rgb"],
};

function set(name: string, value: string) {
  document.documentElement.style.setProperty(name, value);
}
function rgbToHexStr(triplet: string): string {
  return "#" + triplet.split(/\s+/).map((n) => Number(n).toString(16).padStart(2, "0")).join("");
}
function relLum(hex: string): number {
  const h = hex.replace("#", "");
  const n = parseInt(h.slice(0, 6), 16);
  const ch = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}

/** Apply a .side theme. Re-validates every time (last line of defense). */
export function applySide(input: SideTheme): { ok: boolean; errors: string[] } {
  const res = validateSide(input);
  if (!res.ok || !res.theme) return { ok: false, errors: res.errors };

  const t: Record<string, string> = { ...res.theme.theme };

  // Derive optional tokens from required ones when omitted.
  const accent = t["--accent"];
  t["--accent-bright"] ??= rgbToHexStr(lighten(accent));
  t["--accent-dim"] ??= accent + "33";
  t["--accent-glow"] ??= accent + "55";
  t["--text-accent"] ??= rgbToHexStr(lighten(accent, 0.28));
  t["--border-accent"] ??= accent + "44";
  for (const sev of ["--critical", "--high", "--medium", "--low", "--success"]) {
    t[`${sev}-dim`] ??= t[sev] + "20";
  }

  // Hex family + fonts — set every provided/derived token directly (the key IS
  // the CSS var name; unknown-but-safe tokens are set verbatim, forward-compat).
  for (const [name, value] of Object.entries(t)) set(name, value);

  // RGB-triplet family — derive from the hex tokens for Tailwind classes.
  for (const [hexName, rgbNames] of Object.entries(RGB_MAP)) {
    const v = t[hexName];
    if (!v) continue;
    const triplet = hexToRgb(v);
    for (const r of rgbNames) set(r, triplet);
  }
  set("--scrollbar-thumb", hexToRgb(t["--scrollbar-thumb"] ?? t["--border-bright"]));
  set("--scrollbar-thumb-hover", hexToRgb(t["--scrollbar-thumb-hover"] ?? t["--accent"]));
  set("--scrollbar-track", hexToRgb(t["--scrollbar-track"] ?? t["--bg-base"]));

  // Derive light/dark from the base background luminance (the envelope has no
  // explicit base field) so any class-gated styling stays consistent. Inline
  // vars still win for colors.
  const root = document.documentElement;
  root.classList.remove("light", "graphite");
  if (relLum(t["--bg-base"]) > 0.5) root.classList.add("light");
  root.setAttribute("data-side-theme", res.theme.name);

  return { ok: true, errors: [] };
}

/** Remove any applied .side overrides, reverting to the bundled CSS palette. */
export function clearSide(): void {
  const root = document.documentElement;
  const style = root.style;
  for (let i = style.length - 1; i >= 0; i--) {
    const prop = style[i];
    if (prop.startsWith("--")) style.removeProperty(prop);
  }
  root.removeAttribute("data-side-theme");
}
