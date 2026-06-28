// Tasteful wrappers around Dopamine (`@dopaminefx/effects`) so the rest of the
// app fires effects without thinking about moods or intensities. This is a
// security toolkit, not a confetti app — defaults skew restrained.
//
// The shared `@dopaminefx/effects` package is lazy-loaded on first call so the
// WebGL setup doesn't ship in the initial render bundle.
//
// User-facing settings live in localStorage under `mhp:dopamine` and drive
// every helper's mood / intensity / whimsy / kill-switch. The Settings page
// exposes a UI; call sites can also pass per-call overrides.
//
// Respects prefers-reduced-motion: every helper becomes a no-op when the user
// has reduced motion on, regardless of the explicit `enabled` setting.

const PREFERS_REDUCED = typeof window !== "undefined"
  && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

let modPromise: Promise<typeof import("@dopaminefx/effects")> | null = null;

async function load() {
  if (PREFERS_REDUCED) return null;
  if (!getSettings().enabled) return null;
  if (!modPromise) modPromise = import("@dopaminefx/effects");
  return modPromise;
}

type Origin = { x: number; y: number };

// ── Settings store ──────────────────────────────────────────────────────────

export type DopamineMood = "serene" | "celebratory" | "electric";

export type DopamineSettings = {
  /** Master kill switch — when false every helper no-ops. */
  enabled: boolean;
  /** Palette / character (Dopamine's mood enum). */
  mood: DopamineMood;
  /** Overall energy (0–1). Higher = bigger, brighter. */
  intensity: number;
  /** Playfulness (0–1). Higher = more variation per fire. */
  whimsy: number;
};

const STORAGE_KEY = "mhp:dopamine";
export const DOPAMINE_DEFAULTS: DopamineSettings = {
  enabled: true,
  mood: "electric",
  intensity: 0.55,
  whimsy: 0.30,
};

/** Quick-pick "vibe" presets. The UI surfaces these as one-click chips. */
export const DOPAMINE_PRESETS: { id: string; label: string;
  hint: string; patch: Partial<DopamineSettings> }[] = [
  { id: "off",     label: "Off",     hint: "no effects at all",
    patch: { enabled: false } },
  { id: "subtle",  label: "Subtle",  hint: "0.3 / 0.2 · barely there",
    patch: { enabled: true, intensity: 0.30, whimsy: 0.20 } },
  { id: "default", label: "Default", hint: "0.55 / 0.3 · what shipped",
    patch: { enabled: true, intensity: 0.55, whimsy: 0.30 } },
  { id: "bold",    label: "Bold",    hint: "0.8 / 0.5 · noticeable",
    patch: { enabled: true, intensity: 0.80, whimsy: 0.50 } },
  { id: "max",     label: "Max",     hint: "1.0 / 0.8 · maximum dopamine",
    patch: { enabled: true, intensity: 1.00, whimsy: 0.80 } },
];

let cached: DopamineSettings | null = null;

export function getSettings(): DopamineSettings {
  if (cached) return cached;
  if (typeof window === "undefined") return { ...DOPAMINE_DEFAULTS };
  let next: DopamineSettings = { ...DOPAMINE_DEFAULTS };
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<DopamineSettings>;
      next = { ...DOPAMINE_DEFAULTS, ...parsed };
    }
  } catch { /* ignore */ }
  cached = next;
  return next;
}

export function setSettings(patch: Partial<DopamineSettings>): DopamineSettings {
  const next: DopamineSettings = { ...getSettings(), ...patch };
  next.intensity = clamp01(next.intensity);
  next.whimsy = clamp01(next.whimsy);
  cached = next;
  try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); }
  catch { /* quota — ignore */ }
  try {
    window.dispatchEvent(new CustomEvent("mhp:dopamine-changed", { detail: next }));
  } catch { /* ignore */ }
  return next;
}

export function resetSettings(): DopamineSettings {
  return setSettings({ ...DOPAMINE_DEFAULTS });
}

function clamp01(v: number): number {
  if (!isFinite(v)) return 0;
  return Math.max(0, Math.min(1, v));
}

// ── Per-call overrides ──────────────────────────────────────────────────────

export type EffectOverride = Partial<Pick<DopamineSettings, "mood" | "intensity" | "whimsy">>;

function resolved(over?: EffectOverride): {
  mood: DopamineMood; intensity: number; whimsy: number;
} {
  const s = getSettings();
  return {
    mood:      over?.mood      ?? s.mood,
    intensity: over?.intensity ?? s.intensity,
    whimsy:    over?.whimsy    ?? s.whimsy,
  };
}

// ── Removed effects ─────────────────────────────────────────────────────────
//
// `aurora`, `halo`, and `dots` are intentionally NOT in EffectName. The static
// audit (2026-06-16) found:
//   - aurora: declares `usesOrigin: false`, renders a full-screen horizontal
//     curtain regardless of the click point. Wrong shape for a button-press
//     signal — looked like a black-screen / off-position bug.
//   - halo, dots: looping ambient effects. They require an external setTimeout
//     to stop, and visually they don't read as a one-shot press signal.
// All three remain importable from `@dopaminefx/effects` (the umbrella package
// auto-registers them) but the app no longer fires them through `playNamed`.

// ── Effect helpers ──────────────────────────────────────────────────────────

/** Electric-violet pulse — used on scan completion + run button start. */
export async function pulse(origin?: Origin | Element, over?: EffectOverride) {
  const m = await load();
  if (!m) return;
  const p = resolved(over);
  const o = toOrigin(origin);
  const opts = {
    mood: p.mood, intensity: p.intensity, whimsy: p.whimsy,
    origin: o, backdrop: currentBackdrop(),
  };
  logFire("celebrate", o, opts);
  try {
    await m.celebrate(opts as any);
  } catch (e) {
    if (DEBUG) console.warn("[dopamine] celebrate failed:", e);
  }
}

/** Stronger success — for big wins (engagement created, etc.). */
export async function celebrateBig(origin?: Origin | Element, over?: EffectOverride) {
  const m = await load();
  if (!m) return;
  const p = resolved(over);
  // Big celebration ignores the user's intensity floor — engagement-created
  // is a milestone moment, so we boost by 50% but clamp to 1.0.
  const o = toOrigin(origin);
  const opts = {
    mood: p.mood,
    intensity: clamp01(p.intensity * 1.5),
    whimsy: clamp01(p.whimsy * 1.3),
    origin: o, backdrop: currentBackdrop(),
  };
  logFire("celebrate-big", o, opts);
  try {
    await m.celebrate(opts as any);
  } catch (e) {
    if (DEBUG) console.warn("[dopamine] celebrate-big failed:", e);
  }
}

/** Calligraphic ink stroke — for authorization-confirmed checkbox toggle. */
export async function inkConfirm(origin?: Origin | Element, over?: EffectOverride) {
  const m = await load();
  if (!m) return;
  const p = resolved(over);
  const o = toOrigin(origin);
  const opts = {
    mood: p.mood, intensity: p.intensity, whimsy: p.whimsy,
    origin: o, backdrop: currentBackdrop(),
  };
  logFire("inkstroke", o, opts);
  try {
    await m.celebrateInk(opts as any);
  } catch (e) {
    if (DEBUG) console.warn("[dopamine] inkstroke failed:", e);
  }
}

/**
 * Radar sweep — concentric Ripple wavefronts expanding from a button. Fits
 * scan-start moments (LAN sweep, port scan, WiFi scan) where the "scope
 * widening outward" reads as the operator throwing a wave out and waiting.
 */
export async function radarSweep(origin?: Origin | Element, over?: EffectOverride) {
  const m = await load();
  if (!m) return;
  const p = resolved(over);
  const o = toOrigin(origin);
  const opts = {
    mood: p.mood, intensity: p.intensity, whimsy: p.whimsy,
    origin: o, backdrop: currentBackdrop(),
  };
  logFire("ripple", o, opts);
  try {
    await m.play("ripple", opts as any);
  } catch (e) {
    if (DEBUG) console.warn("[dopamine] ripple failed:", e);
  }
}

/** Error stamp — for critical findings or failed handshakes. Use sparingly. */
export async function failStamp(origin?: Origin | Element, over?: EffectOverride) {
  const m = await load();
  if (!m) return;
  const p = resolved(over);
  const o = toOrigin(origin);
  const opts = {
    intensity: p.intensity, whimsy: p.whimsy,
    origin: o, backdrop: currentBackdrop(),
  };
  logFire("fail", o, opts);
  try {
    await m.fail(opts as any);
  } catch (e) {
    if (DEBUG) console.warn("[dopamine] fail failed:", e);
  }
}

/** Built-in effect names usable by the gallery + per-tool pickers.
 *  `aurora`, `halo`, `dots` were removed — see "Removed effects" note above. */
export type EffectName =
  | "solarbloom" | "inkstroke" | "comic" | "fail" | "ripple"
  | "confetti" | "heartburst" | "lightning";

/**
 * Fire an arbitrary built-in effect by name. Used by the Settings preview
 * gallery + the per-tool scan-effect pickers. All effects in the EffectName
 * union are one-shot, viewport-pixel anchored, and backdrop-aware.
 */
export async function playNamed(
  name: EffectName,
  origin?: Origin | Element,
  over?: EffectOverride,
  opts?: { maxMs?: number },
) {
  const m = await load();
  if (!m) return;
  const p = resolved(over);
  const o = toOrigin(origin);
  const fireOpts = {
    mood: p.mood, intensity: p.intensity, whimsy: p.whimsy,
    origin: o, backdrop: currentBackdrop(),
  };
  logFire(name, o, fireOpts);
  try {
    await m.play(name, fireOpts as any);
  } catch (e) {
    if (DEBUG) console.warn("[dopamine] play(" + name + ") failed:", e);
  }
  // `opts` retained for back-compat with any caller still passing it.
  void opts;
}

// ── Per-tool scan-effect preference ─────────────────────────────────────────
//
// Each scan-style tool (LAN Scan, Port Scanner, WiFi Scan, etc.) stores its
// own preferred Dopamine effect that fires when the user presses the scan
// button. The choice is persisted under a tool-keyed localStorage entry so
// the user can pick a different vibe per tool.

const TOOL_EFFECT_PREFIX = "mhp:scan-effect:";

const ALL_EFFECT_NAMES: ReadonlySet<EffectName> = new Set<EffectName>([
  "solarbloom", "inkstroke", "comic", "fail", "ripple",
  "confetti", "heartburst", "lightning",
]);

export function getToolEffect(toolKey: string, fallback: EffectName = "ripple"): EffectName {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(TOOL_EFFECT_PREFIX + toolKey);
    if (raw && ALL_EFFECT_NAMES.has(raw as EffectName)) return raw as EffectName;
  } catch { /* ignore */ }
  return fallback;
}

export function setToolEffect(toolKey: string, effect: EffectName): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(TOOL_EFFECT_PREFIX + toolKey, effect);
    window.dispatchEvent(new CustomEvent("mhp:scan-effect-changed", {
      detail: { toolKey, effect },
    }));
  } catch { /* ignore */ }
}

// Dopamine expects `origin` in viewport PIXELS (see DopamineSuccessOptions
// in @dopaminefx/core). The previous implementation normalised to [0,1] —
// dopamine then read those as raw pixel coordinates and rendered every
// effect at the top-left corner of the viewport. Pass real pixels.
function toOrigin(o?: Origin | Element): Origin | undefined {
  if (!o) return undefined;
  if (o instanceof Element) {
    const r = o.getBoundingClientRect();
    return {
      x: r.left + r.width / 2,
      y: r.top + r.height / 2,
    };
  }
  return o;
}

// Resolve the current surface colour from --bg-base so dopamine can
// composite light onto white themes. Without this, effects in light mode
// flash black because the default `mix-blend-mode: screen` overlay is
// mathematically invisible on a white background.
function currentBackdrop(): string | undefined {
  if (typeof window === "undefined") return undefined;
  try {
    const v = getComputedStyle(document.documentElement)
      .getPropertyValue("--bg-base").trim();
    return v || undefined;
  } catch { return undefined; }
}

const DEBUG = typeof window !== "undefined"
  && window.localStorage?.getItem("mhp:dopamine-debug") === "1";

function logFire(name: string, originPx: Origin | undefined, opts: object) {
  if (!DEBUG) return;
  // eslint-disable-next-line no-console
  console.debug("[dopamine] fire", name, { origin: originPx, ...opts });
}
