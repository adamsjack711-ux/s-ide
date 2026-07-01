// Font sizing — two real text-size tokens (NOT a UI zoom):
//
//   --text-scale     UI text scale. Every chrome font-size is authored as
//                    text-[calc(Npx * var(--text-scale))], so this resizes the
//                    TEXT only — padding, icons, fixed-width panels and overall
//                    layout stay put (no geometric zoom, no viewport reflow gap).
//   --mono-font-px   the editor/terminal monospace size, tunable independently.
//
// Both applied live on <html> and persisted. Mirrors lib/accent + lib/density.
import { useEffect, useState } from "react";

export const TEXT_MIN = 0.75;
export const TEXT_MAX = 1.2;
export const TEXT_DEFAULT = 0.9;

export const MONO_MIN = 9;
export const MONO_MAX = 16;
export const MONO_DEFAULT = 12;

const TEXT_KEY = "s-ide:text-scale";
const MONO_KEY = "s-ide:mono-font-px";

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

function loadNum(key: string, def: number, lo: number, hi: number): number {
  try {
    const v = parseFloat(localStorage.getItem(key) || "");
    return Number.isFinite(v) ? clamp(v, lo, hi) : def;
  } catch {
    return def;
  }
}

let textScale = loadNum(TEXT_KEY, TEXT_DEFAULT, TEXT_MIN, TEXT_MAX);
let mono = loadNum(MONO_KEY, MONO_DEFAULT, MONO_MIN, MONO_MAX);

function applyText(s: number): void {
  document.documentElement.style.setProperty("--text-scale", String(s));
}
function applyMono(px: number): void {
  document.documentElement.style.setProperty("--mono-font-px", `${px}px`);
}

if (typeof document !== "undefined") {
  applyText(textScale);
  applyMono(mono);
}

const listeners = new Set<() => void>();
function notify() {
  listeners.forEach((l) => l());
}

export function getTextScale(): number {
  return textScale;
}
export function setTextScale(n: number): void {
  textScale = clamp(n, TEXT_MIN, TEXT_MAX);
  try {
    localStorage.setItem(TEXT_KEY, String(textScale));
  } catch {
    /* quota */
  }
  applyText(textScale);
  notify();
}
export function getMonoSize(): number {
  return mono;
}
export function setMonoSize(n: number): void {
  mono = clamp(Math.round(n), MONO_MIN, MONO_MAX);
  try {
    localStorage.setItem(MONO_KEY, String(mono));
  } catch {
    /* quota */
  }
  applyMono(mono);
  notify();
}

export function useTextScale(): [number, (n: number) => void] {
  const [v, setV] = useState(textScale);
  useEffect(() => {
    const l = () => setV(textScale);
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  return [v, setTextScale];
}

export function useMonoSize(): [number, (n: number) => void] {
  const [v, setV] = useState(mono);
  useEffect(() => {
    const l = () => setV(mono);
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  return [v, setMonoSize];
}
