// Centralised GSAP wrappers used by the new UI chrome. Keeping the timings
// in one place means every motion in the app reads from the same vocabulary
// (durations + eases), and prefers-reduced-motion respects flow consistently.
//
// Continuous animations (scanning pulse, etc.) stay in CSS — GSAP is reserved
// for one-shot transitions where the easing curve matters.
import { gsap } from "gsap";

const PREFERS_REDUCED = typeof window !== "undefined"
  && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

export const EASE = {
  out: "power3.out",
  outFast: "power2.out",
  inOut: "power2.inOut",
  back: "back.out(1.4)",
};

export const DUR = {
  micro: 0.12,
  fast: 0.18,
  base: 0.24,
  slow: 0.38,
};

/** Fade + scale-in for popovers (palette, chat panel). */
export function popIn(el: Element | null, dur = DUR.fast) {
  if (!el || PREFERS_REDUCED) return;
  gsap.fromTo(
    el,
    { autoAlpha: 0, scale: 0.96, y: -8 },
    { autoAlpha: 1, scale: 1, y: 0, duration: dur, ease: EASE.out },
  );
}

/** Slide-up + fade for a single result row. */
export function rowIn(el: Element | null, dur = DUR.fast) {
  if (!el || PREFERS_REDUCED) return;
  gsap.fromTo(
    el,
    { autoAlpha: 0, y: 8 },
    { autoAlpha: 1, y: 0, duration: dur, ease: EASE.out },
  );
}

/** Stagger several rows in. Pass an array (e.g. via gsap.utils.toArray). */
export function rowsIn(els: Element[] | NodeListOf<Element>, stagger = 0.04) {
  if (!els || (els as any).length === 0 || PREFERS_REDUCED) return;
  gsap.fromTo(
    els as any,
    { autoAlpha: 0, y: 8 },
    {
      autoAlpha: 1, y: 0,
      duration: DUR.fast, ease: EASE.out,
      stagger,
    },
  );
}

/** Fade-in for a whole route. Use on the page root. */
export function pageIn(el: Element | null) {
  if (!el || PREFERS_REDUCED) return;
  gsap.fromTo(
    el,
    { autoAlpha: 0, y: 4 },
    { autoAlpha: 1, y: 0, duration: DUR.base, ease: EASE.out },
  );
}

/** Subtle press-down on the run button. */
export function press(el: Element | null) {
  if (!el || PREFERS_REDUCED) return;
  gsap.to(el, { scale: 0.97, duration: DUR.micro, ease: EASE.outFast, yoyo: true, repeat: 1 });
}

/** Bounce-in for the chat bubble first open. */
export function chatBubbleIn(el: Element | null) {
  if (!el || PREFERS_REDUCED) return;
  gsap.fromTo(
    el,
    { autoAlpha: 0, scale: 0.85, y: 12 },
    { autoAlpha: 1, scale: 1, y: 0, duration: DUR.base, ease: EASE.back },
  );
}
