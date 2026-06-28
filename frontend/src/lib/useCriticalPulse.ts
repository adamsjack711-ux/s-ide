// Hook + helpers for the "critical finding arrived" pulse + alert tone.
// Used by streaming tool pages.
import { useEffect, useRef } from "react";

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
}

// Lazy singleton AudioContext — created on first use because some browsers
// require a user gesture before they let you instantiate one.
let audioCtx: AudioContext | null = null;
function getCtx(): AudioContext | null {
  if (typeof window === "undefined") return null;
  if (audioCtx) return audioCtx;
  const Ctor =
    (window as unknown as { AudioContext?: typeof AudioContext }).AudioContext ??
    (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  try {
    audioCtx = new Ctor();
    return audioCtx;
  } catch {
    return null;
  }
}

// Short ~200ms tone for a new critical finding. Respects prefers-reduced-motion.
export function playCriticalTone(freq = 880, durationMs = 200) {
  if (prefersReducedMotion()) return;
  const ctx = getCtx();
  if (!ctx) return;
  try {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = freq;
    const now = ctx.currentTime;
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.exponentialRampToValueAtTime(0.06, now + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + durationMs / 1000);
    osc.connect(gain).connect(ctx.destination);
    osc.start(now);
    osc.stop(now + durationMs / 1000 + 0.02);
  } catch {
    // Audio is best-effort; never throw.
  }
}

// usePulseOnCritical(rows, isCritical) — when a row becomes critical, register
// the row id so a parent component can attach the pulse class for ~2s.
//
// Returns a Set of "currently pulsing" ids that the page can use to add
// `mhp-critical-pulse` to row elements.
export function useCriticalPulseSet<T>(
  rows: T[],
  getId: (r: T) => string,
  isCritical: (r: T) => boolean,
  durationMs = 2000,
): Set<string> {
  const pulsingRef = useRef<Set<string>>(new Set());
  const seenRef = useRef<Set<string>>(new Set());
  // We don't want to re-render every tick; bump a counter so consumers can
  // observe changes when needed.
  const tickRef = useRef(0);

  useEffect(() => {
    for (const r of rows) {
      const id = getId(r);
      if (seenRef.current.has(id)) continue;
      seenRef.current.add(id);
      if (isCritical(r)) {
        pulsingRef.current.add(id);
        playCriticalTone();
        tickRef.current += 1;
        window.setTimeout(() => {
          pulsingRef.current.delete(id);
        }, durationMs);
      }
    }
  }, [rows, getId, isCritical, durationMs]);

  return pulsingRef.current;
}
