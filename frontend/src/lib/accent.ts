// Accent picker — overrides the accent CSS vars on <html> from a chosen hex,
// persisted. The design's named accents.
import { useEffect, useState } from "react";

export const ACCENTS: { name: string; hex: string }[] = [
  { name: "Matrix", hex: "#39d98a" },
  { name: "Signal", hex: "#4d9fff" },
  { name: "Vapor", hex: "#b07cff" },
  { name: "Alert", hex: "#ff5d6c" },
  { name: "Amber", hex: "#ffb020" },
];

const KEY = "s-ide:accent";
const DEFAULT = "#39d98a";

function hexToRgb(hex: string): string {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? h.split("").map((c) => c + c).join("") : h;
  const n = parseInt(full, 16);
  return `${(n >> 16) & 255} ${(n >> 8) & 255} ${n & 255}`;
}
function lighten(hex: string, amt = 0.18): string {
  const n = parseInt(hex.replace("#", ""), 16);
  const ch = (shift: number) => {
    const v = (n >> shift) & 255;
    return Math.min(255, Math.round(v + (255 - v) * amt));
  };
  return `${ch(16)} ${ch(8)} ${ch(0)}`;
}
function apply(hex: string): void {
  const s = document.documentElement.style;
  s.setProperty("--accent", hex);
  s.setProperty("--accent-rgb", hexToRgb(hex));
  s.setProperty("--accent-bright-rgb", lighten(hex));
  s.setProperty("--text-accent-rgb", lighten(hex, 0.28));
  s.setProperty("--accent-dim", hex + "33");
  s.setProperty("--accent-glow", hex + "55");
}
function load(): string {
  try { return localStorage.getItem(KEY) || DEFAULT; } catch { return DEFAULT; }
}

let current = load();
if (typeof document !== "undefined") apply(current);

const listeners = new Set<() => void>();

export function getAccent(): string {
  return current;
}
export function setAccent(hex: string): void {
  current = hex;
  try { localStorage.setItem(KEY, hex); } catch { /* ignore */ }
  apply(hex);
  listeners.forEach((l) => l());
}
export function useAccent(): [string, (hex: string) => void] {
  const [a, setA] = useState(current);
  useEffect(() => {
    const l = () => setA(current);
    listeners.add(l);
    return () => { listeners.delete(l); };
  }, []);
  return [a, setAccent];
}
