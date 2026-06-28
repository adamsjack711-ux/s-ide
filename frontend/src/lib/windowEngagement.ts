/**
 * Per-window engagement binding (engagement-as-workspace).
 *
 * A window may be launched pinned to an engagement via a `?engagement=<id>`
 * query param (Electron main passes it; see electron/main.cjs). On load we
 * adopt it as this window's active engagement. `openEngagementWindow` spawns a
 * fresh window for an engagement — a real OS window under Electron, a browser
 * tab in dev.
 *
 * NOTE (Phase 5 scope): the underlying engagement store is still the ported
 * localStorage singleton, so within ONE process all windows currently share it.
 * The query-param pin + per-engagement layout below are the seam; making the
 * store fully window-local is a focused follow-up flagged in the plan.
 */
import { setActiveEngagementId } from "./engagement";

export function pinWindowEngagement(): void {
  try {
    const eid = new URLSearchParams(window.location.search).get("engagement");
    if (eid) setActiveEngagementId(eid);
  } catch {
    /* no query string */
  }
}

export function openEngagementWindow(engagementId: string): void {
  const nt = (window as any).nt;
  if (nt?.openEngagementWindow) {
    void nt.openEngagementWindow(engagementId);
  } else {
    window.open(`/?engagement=${encodeURIComponent(engagementId)}`, "_blank");
  }
}
