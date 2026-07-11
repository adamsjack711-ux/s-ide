/**
 * Flags for Labs "learning loop" actions that are scaffolded end-to-end but
 * whose backend is not wired yet (the endpoints return 501/NOT_IMPLEMENTED —
 * see backend/routers/labfs.py + backend/routers/isolation.py).
 *
 * These gate the corresponding UI affordances OFF so an operator can't invoke
 * a button/keybinding that silently does nothing. Flip a flag to `false` (and
 * restore the endpoint) once the feature actually works.
 */

/** Fix-in-place write (`POST /labfs/{labId}/write`). */
export const FIX_IN_PLACE_COMING_SOON = true;

/** Retest = replay the recorded Step chain (`POST /labfs/{labId}/retest`). */
export const RETEST_COMING_SOON = true;

/** Shared user-facing copy for a not-yet-wired action. */
export const COMING_SOON_TOOLTIP = "Coming soon — not yet wired";
