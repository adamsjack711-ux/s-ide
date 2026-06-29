// User-controlled UI scale for cards/tiles/list rows. Sets a single CSS var
// `--ui-scale` on <html>; index.css derives per-element sizes (--card-pad,
// --card-name, --row-py, …) from it via calc(), so everything scales live.
// Persisted, applied on import (no flash). Mirrors lib/accent.ts.
import { useEffect, useState } from "react";

export const SCALE_MIN = 0.8;
export const SCALE_MAX = 1.4;
const KEY = "s-ide:ui-scale";
const DEFAULT = 1;

function clamp(n: number): number {
  return Math.min(SCALE_MAX, Math.max(SCALE_MIN, n));
}
function apply(scale: number): void {
  document.documentElement.style.setProperty("--ui-scale", String(scale));
}
function load(): number {
  try {
    const v = parseFloat(localStorage.getItem(KEY) || "");
    return Number.isFinite(v) ? clamp(v) : DEFAULT;
  } catch {
    return DEFAULT;
  }
}

let current = load();
if (typeof document !== "undefined") apply(current);

const listeners = new Set<() => void>();

export function getScale(): number {
  return current;
}
export function setScale(n: number): void {
  current = clamp(n);
  try {
    localStorage.setItem(KEY, String(current));
  } catch {
    /* quota */
  }
  apply(current);
  listeners.forEach((l) => l());
}
export function useScale(): [number, (n: number) => void] {
  const [s, setS] = useState(current);
  useEffect(() => {
    const l = () => setS(current);
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  return [s, setScale];
}
