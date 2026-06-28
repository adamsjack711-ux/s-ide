// Pure logic behind the chat "Suggest checks" approval cards
// (components/SuggestionCard.tsx). The backend proposes checks
// (api.suggestChecks); this turns a card decision into the concrete
// navigation + pre-fill plan the component executes, and owns the small
// per-card state machine. Kept pure so the consequential branch — what
// Approve actually does — is unit-testable without rendering chat.

import type { SuggestedCheck } from "../api";
import type { LabIntent } from "./labIntent";
import type { ActiveTargetSnapshot } from "./targets";

export type CardStatus = "pending" | "approved" | "skipped";

// What Approve carries out: drop the target into the active-target slot and a
// one-shot lab intent, then navigate to the tool page. The component performs
// the side effects (setActiveTarget / writeLabIntent / onNavigate); this just
// computes the payloads so they can't drift between call sites.
export type ApprovePlan = {
  navId: string;
  intent: LabIntent;
  target: ActiveTargetSnapshot;
};

export function approvePlan(check: SuggestedCheck): ApprovePlan {
  const address = check.target.trim();
  return {
    navId: check.nav_id,
    intent: { target: address },
    // Proposed targets are operator-entered hosts/URLs, so kind = manual.
    // Use the address as the id/name — the snapshot has no engagement row.
    target: { id: `suggest:${address}`, address, name: address, kind: "manual" },
  };
}

// Override the target on a check before approving (the Modify action). Trims
// and ignores empties so a blank box can't wipe a usable target.
export function withTarget(check: SuggestedCheck, target: string): SuggestedCheck {
  const t = target.trim();
  return t ? { ...check, target: t } : check;
}

// A check can be approved only while pending and with a non-empty target —
// the card gates its Approve button on this.
export function canApprove(check: SuggestedCheck, status: CardStatus): boolean {
  return status === "pending" && check.target.trim().length > 0;
}
