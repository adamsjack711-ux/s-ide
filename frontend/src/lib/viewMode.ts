// Per-view grid/list preference, persisted to localStorage. Mirrors the
// listener pattern in lib/accent.ts so any number of components can share one
// view's mode and stay in sync.
import { useEffect, useState } from "react";

export type ViewMode = "grid" | "list";

const PREFIX = "s-ide:viewmode:";
const stores: Record<string, { value: ViewMode; listeners: Set<() => void> }> = {};

function load(key: string): ViewMode {
  try {
    return localStorage.getItem(PREFIX + key) === "list" ? "list" : "grid";
  } catch {
    return "grid";
  }
}

function store(key: string) {
  if (!stores[key]) stores[key] = { value: load(key), listeners: new Set() };
  return stores[key];
}

/** Read + set a view's grid/list mode, persisted under `key`. */
export function useViewMode(key: string): [ViewMode, (m: ViewMode) => void] {
  const s = store(key);
  const [mode, setMode] = useState<ViewMode>(s.value);

  useEffect(() => {
    const l = () => setMode(s.value);
    s.listeners.add(l);
    return () => {
      s.listeners.delete(l);
    };
  }, [s]);

  const set = (m: ViewMode) => {
    s.value = m;
    try {
      localStorage.setItem(PREFIX + key, m);
    } catch {
      /* ignore */
    }
    s.listeners.forEach((l) => l());
  };

  return [mode, set];
}
