// Theme management: midnight / graphite / light / system, persisted to
// localStorage. `system` follows the OS (prefers-color-scheme) live. The
// resolved theme is applied as a class on <html> — midnight = no class (the
// :root default), graphite/light add their class — so index.css var overrides
// take effect.

import { useEffect, useState } from "react";

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

// Apply on import so the first paint is already correct (no flash on reload).
if (typeof document !== "undefined") {
  apply(resolve(loadChoice()));
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
