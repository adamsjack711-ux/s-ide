// Theme management: midnight / graphite / light / system, persisted to
// localStorage. `system` follows the OS (prefers-color-scheme) live. The
// resolved theme is applied as a class on <html> — midnight = no class (the
// :root default), graphite/light add their class — so index.css var overrides
// take effect.

import { useEffect, useState } from "react";
import { applySide, clearSide } from "../themes/apply";
import type { SideTheme } from "../themes/sideSchema";

export type ThemeChoice = "midnight" | "graphite" | "light" | "system";
export type ResolvedTheme = "midnight" | "graphite" | "light";

const STORAGE_KEY = "mhp:theme";

function loadChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "midnight" || v === "graphite" || v === "light" || v === "system") return v;
    if (v === "dark") return "midnight"; // legacy
  } catch { /* ignore */ }
  return "system";
}

function saveChoice(c: ThemeChoice): void {
  try { localStorage.setItem(STORAGE_KEY, c); } catch { /* ignore */ }
}

function systemPrefersLight(): boolean {
  return typeof window !== "undefined"
    && !!window.matchMedia
    && window.matchMedia("(prefers-color-scheme: light)").matches;
}

function resolve(choice: ThemeChoice): ResolvedTheme {
  if (choice === "system") return systemPrefersLight() ? "light" : "midnight";
  return choice;
}

function apply(resolved: ResolvedTheme): void {
  const root = document.documentElement;
  root.classList.remove("light", "graphite");
  if (resolved === "light") root.classList.add("light");
  else if (resolved === "graphite") root.classList.add("graphite");
}

// ── .side custom themes ──────────────────────────────────────────────────────
// A fetched/installed .side theme overrides the bundled palette. Persisted as
// its full JSON so first paint can re-apply it after reload (no flash, no
// re-fetch). Applying always re-validates (apply.ts is the authoritative gate).
const SIDE_KEY = "s-ide:side-theme";

export function getSideTheme(): SideTheme | null {
  try {
    const raw = localStorage.getItem(SIDE_KEY);
    return raw ? (JSON.parse(raw) as SideTheme) : null;
  } catch {
    return null;
  }
}

/** Validate + apply + persist a .side theme. Returns the validation result. */
export function setSideTheme(theme: SideTheme): { ok: boolean; errors: string[] } {
  const res = applySide(theme);
  if (res.ok) {
    try { localStorage.setItem(SIDE_KEY, JSON.stringify(theme)); } catch { /* quota */ }
  }
  return res;
}

/** Drop the custom theme and revert to the bundled choice + accent. */
export function clearSideTheme(): void {
  try { localStorage.removeItem(SIDE_KEY); } catch { /* ignore */ }
  clearSide();
  if (typeof document !== "undefined") apply(resolve(loadChoice()));
}

// Apply on import so the first paint is already correct (no flash on reload).
// A persisted .side theme wins over the bundled choice and is restored here.
if (typeof document !== "undefined") {
  apply(resolve(loadChoice()));
  const side = getSideTheme();
  if (side) {
    const res = applySide(side);
    // A previously-valid theme that no longer validates (e.g. schema tightened)
    // fails safe: drop it and keep the bundled palette already applied above.
    if (!res.ok) {
      try { localStorage.removeItem(SIDE_KEY); } catch { /* ignore */ }
    }
  }
}

export function useTheme(): {
  choice: ThemeChoice;
  resolved: ResolvedTheme;
  setChoice: (c: ThemeChoice) => void;
  cycle: () => void;
} {
  const [choice, setChoiceState] = useState<ThemeChoice>(() => loadChoice());
  const [resolved, setResolved] = useState<ResolvedTheme>(() => resolve(loadChoice()));

  useEffect(() => {
    const r = resolve(choice);
    setResolved(r);
    apply(r);
  }, [choice]);

  useEffect(() => {
    if (choice !== "system") return;
    const mql = window.matchMedia("(prefers-color-scheme: light)");
    const handler = () => {
      const r: ResolvedTheme = mql.matches ? "light" : "midnight";
      setResolved(r);
      apply(r);
    };
    mql.addEventListener?.("change", handler);
    return () => mql.removeEventListener?.("change", handler);
  }, [choice]);

  function setChoice(c: ThemeChoice): void {
    saveChoice(c);
    setChoiceState(c);
  }

  const order: ThemeChoice[] = ["midnight", "graphite", "light", "system"];
  function cycle(): void {
    setChoice(order[(order.indexOf(choice) + 1) % order.length]);
  }

  return { choice, resolved, setChoice, cycle };
}
