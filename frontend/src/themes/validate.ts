// .side validator — declarative-only envelope + WCAG contrast + severity ΔE
// distinctness. Pure (no I/O); runs identically at fetch (backend mirror) and
// at apply (the authoritative gate in apply.ts). Mirrored in
// backend/lib/theme_validate.py.
//
// Safety model:
//   - Envelope must be {version, kind:"theme", name, author?, theme:{}}.
//     `version` is mandatory. Unknown TOP-LEVEL keys are rejected (kills a
//     smuggled `script`/`style` field).
//   - Inside `theme`, unknown token keys are IGNORED (forward-compat) — but
//     EVERY value is scanned: non-strings and any markup/executable content
//     (`<`, `>`, `javascript:`, `url(`, `script`, braces, backslash) are
//     rejected, so nothing executable can ride in even on an ignored key.
//   - Known COLOR tokens must be valid hex; font tokens may be free strings.
//   - Protected severity tokens must clear a contrast floor and stay mutually
//     distinct (ΔE) — safety meaning must survive.
import {
  COLOR_TOKENS,
  FONT_TOKENS,
  HEX_RE,
  KIND,
  MUST_DEFINE,
  PROTECTED_TOKENS,
  type SideTheme,
} from "./sideSchema";

export type ValidationResult = { ok: boolean; errors: string[]; theme?: SideTheme };

// Any value containing these is treated as executable/markup and rejected.
const UNSAFE_RE = /[<>{}\\]|javascript:|url\s*\(|script|@import|expression\s*\(/i;

// ── color math ──────────────────────────────────────────────────────────────
function toRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  const n = parseInt(h.slice(0, 6), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
function lin(c: number): number {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}
function luminance(hex: string): number {
  const [r, g, b] = toRgb(hex);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}
export function contrastRatio(a: string, b: string): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}
function toLab(hex: string): [number, number, number] {
  const [r, g, b] = toRgb(hex).map(lin) as [number, number, number];
  let x = (r * 0.4124 + g * 0.3576 + b * 0.1805) / 0.95047;
  let y = r * 0.2126 + g * 0.7152 + b * 0.0722;
  let z = (r * 0.0193 + g * 0.1192 + b * 0.9505) / 1.08883;
  const f = (t: number) => (t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116);
  x = f(x); y = f(y); z = f(z);
  return [116 * y - 16, 500 * (x - y), 200 * (y - z)];
}
export function deltaE(a: string, b: string): number {
  const [l1, a1, b1] = toLab(a);
  const [l2, a2, b2] = toLab(b);
  return Math.sqrt((l1 - l2) ** 2 + (a1 - a2) ** 2 + (b1 - b2) ** 2);
}

// ── thresholds ────────────────────────────────────────────────────────────────
const TEXT_FLOOR = 4.5;
const SECONDARY_FLOOR = 3;
const SEVERITY_FLOOR = 3;
const ACCENT_FLOOR = 3;
const DELTA_FLOOR = 15;

export function validateSide(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, errors: ["theme must be a JSON object"] };
  }
  const obj = input as Record<string, unknown>;

  // Envelope — reject unknown top-level keys (catches a smuggled script/style).
  for (const k of Object.keys(obj)) {
    if (!["version", "kind", "name", "author", "theme"].includes(k)) errors.push(`unexpected top-level key: ${k}`);
  }
  if (typeof obj.version !== "string" || !obj.version.trim()) errors.push("version is required");
  if (obj.kind !== KIND) errors.push(`kind must be "${KIND}"`);
  if (typeof obj.name !== "string" || !obj.name) errors.push("name is required");
  if (obj.author != null && typeof obj.author !== "string") errors.push("author must be a string");

  const theme = obj.theme;
  if (typeof theme !== "object" || theme === null || Array.isArray(theme)) {
    errors.push("theme map is required");
    return { ok: false, errors };
  }
  const map = theme as Record<string, unknown>;

  for (const [k, val] of Object.entries(map)) {
    // Safety scan EVERY value, known or unknown.
    if (typeof val !== "string") {
      errors.push(`token ${k} must be a string`);
      continue;
    }
    if (UNSAFE_RE.test(val)) {
      errors.push(`token ${k} contains disallowed content`);
      continue;
    }
    // Known color tokens must be valid hex. Font tokens are free strings.
    // Unknown keys are ignored (forward-compat) once they pass the safety scan.
    if (COLOR_TOKENS.has(k) && !HEX_RE.test(val)) {
      errors.push(`token ${k} must be a hex color (got ${val})`);
    } else if (!COLOR_TOKENS.has(k) && !FONT_TOKENS.includes(k)) {
      // unknown — ignored.
    }
  }
  for (const need of MUST_DEFINE) {
    if (!(need in map)) errors.push(`required token missing: ${need}`);
  }

  // Contrast + distinctness (only on valid-hex inputs).
  const hex = (k: string) => (typeof map[k] === "string" && HEX_RE.test(map[k] as string) ? (map[k] as string) : null);
  const base = hex("--bg-base");
  const surface = hex("--bg-surface");
  const tp = hex("--text-primary");
  const ts = hex("--text-secondary");
  const accent = hex("--accent");

  if (tp && base && contrastRatio(tp, base) < TEXT_FLOOR)
    errors.push(`text-primary on bg-base contrast ${contrastRatio(tp, base).toFixed(2)} < ${TEXT_FLOOR}`);
  if (tp && surface && contrastRatio(tp, surface) < TEXT_FLOOR)
    errors.push(`text-primary on bg-surface contrast ${contrastRatio(tp, surface).toFixed(2)} < ${TEXT_FLOOR}`);
  if (ts && surface && contrastRatio(ts, surface) < SECONDARY_FLOOR)
    errors.push(`text-secondary on bg-surface contrast ${contrastRatio(ts, surface).toFixed(2)} < ${SECONDARY_FLOOR}`);
  if (accent && base && contrastRatio(accent, base) < ACCENT_FLOOR)
    errors.push(`accent on bg-base contrast ${contrastRatio(accent, base).toFixed(2)} < ${ACCENT_FLOOR}`);

  const sev: Record<string, string | null> = {};
  for (const s of PROTECTED_TOKENS) {
    sev[s] = hex(s);
    if (sev[s] && surface && contrastRatio(sev[s]!, surface) < SEVERITY_FLOOR)
      errors.push(`${s} on bg-surface contrast ${contrastRatio(sev[s]!, surface).toFixed(2)} < ${SEVERITY_FLOOR}`);
  }
  for (let i = 0; i < PROTECTED_TOKENS.length; i++) {
    for (let j = i + 1; j < PROTECTED_TOKENS.length; j++) {
      const a = sev[PROTECTED_TOKENS[i]];
      const b = sev[PROTECTED_TOKENS[j]];
      if (a && b && deltaE(a, b) < DELTA_FLOOR)
        errors.push(`${PROTECTED_TOKENS[i]} and ${PROTECTED_TOKENS[j]} are too similar (ΔE ${deltaE(a, b).toFixed(1)} < ${DELTA_FLOOR})`);
    }
  }

  return errors.length ? { ok: false, errors } : { ok: true, errors: [], theme: obj as unknown as SideTheme };
}
