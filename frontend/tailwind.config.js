/** @type {import('tailwindcss').Config} */
//
// Colors are bound to CSS variables (RGB triplets, space-separated) so they
// switch between dark/light themes at runtime without rebuilding. The
// `<alpha-value>` placeholder preserves Tailwind opacity modifiers like
// `bg-bg-base/40`, `text-amber/70`, etc.
//
// Variable definitions live in src/index.css under `:root` (dark default) and
// `:root.light` (overrides). The theme hook in src/lib/theme.ts toggles the
// `.light` class on <html>.
//
// The legacy palette (bg-bg-base, text-ink-primary, accent, phos, amber,
// danger, ...) remains for backwards compat across ~90 pages. The new tokens
// below (accentBright, textAccent, critical, high, medium, low, success,
// borderBright) are spec additions used by rebuilt shared components.
//
function v(name) {
  return `rgb(var(--${name}-rgb) / <alpha-value>)`;
}

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "SF Mono",
          "Menlo",
          "Consolas",
          "ui-monospace",
          "monospace",
        ],
      },
      colors: {
        bg: {
          base:        v("bg-base"),
          sidebar:     v("bg-sidebar"),
          card:        v("bg-card"),
          panel:       v("bg-panel"),
          "row-alt":   v("bg-row-alt"),
          "nav-hover": v("bg-nav-hover"),
          "nav-active":v("bg-nav-active"),
          surface:  v("bg-sidebar"),
          elevated: v("bg-card"),
          hover:    v("bg-nav-hover"),
          active:   v("bg-nav-active"),
        },
        divider: v("divider"),
        ink: {
          primary: v("ink-primary"),
          muted:   v("ink-muted"),
          dim:     v("ink-dim"),
        },
        accent:       v("accent"),
        accentDim:    v("accent-dim"),
        accentBright: v("accent-bright"),
        textAccent:   v("text-accent"),
        phos:         v("phos"),
        amber:        v("amber"),
        danger:       v("danger"),

        critical: v("critical"),
        high:     v("high"),
        medium:   v("medium"),
        low:      v("low"),
        success:  v("success"),

        border:       v("border"),
        borderBright: v("border-bright"),
      },
      boxShadow: {
        "accent-glow":    "0 0 0 3px rgb(var(--accent-rgb) / 0.20)",
        "accent-glow-lg": "0 8px 24px -8px rgb(var(--accent-rgb) / 0.45)",
      },
    },
  },
  plugins: [],
};
