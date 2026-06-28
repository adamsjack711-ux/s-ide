// Lab vs Engagement mode.
//
// The mode flag drives two pieces of behaviour, both enforced by the
// backend; the frontend is the source of truth:
//
//   - Lab mode (default)
//       Scope checks are skipped. Auto-record to the active engagement
//       is suppressed even if one is active. Use for ad-hoc work
//       against your own targets — pop boxes in a home lab, check a
//       cert on a public site, scan your own /24.
//
//   - Engagement mode
//       Scope checks are enforced against the active engagement.
//       Target-accepting tools deny when no engagement is active.
//       Results auto-attach to the engagement's evidence timeline.
//       Use for authorized assessments.
//
// Persisted per-window in localStorage. The value is sent to the
// backend on every request: `X-MHP-Mode` header on HTTP, `?mode=`
// query string on WS upgrades (which can't carry custom headers).

import { useEffect, useState } from "react";

export type Mode = "lab" | "engagement";

const KEY = "mhp:mode:v1";
const DEFAULT: Mode = "lab";

function read(): Mode {
  try {
    const v = localStorage.getItem(KEY);
    return v === "engagement" ? "engagement" : "lab";
  } catch {
    return DEFAULT;
  }
}

let current: Mode = read();

const listeners = new Set<() => void>();
function notify() { for (const l of listeners) l(); }

export function getMode(): Mode {
  return current;
}

export function setMode(m: Mode): void {
  current = m;
  try { localStorage.setItem(KEY, m); } catch { /* quota */ }
  notify();
}

export function useMode(): Mode {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((n) => n + 1);
    listeners.add(fn);
    return () => { listeners.delete(fn); };
  }, []);
  return current;
}
