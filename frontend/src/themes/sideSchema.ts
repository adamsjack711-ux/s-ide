// Canonical .side theme shape.
//
// Envelope (per spec): { version, kind:"theme", name, author?, theme:{token:value} }
//   - `version` is mandatory (a theme that omits it is rejected).
//   - `theme` is a flat design-token → value map. Token keys are the app's REAL
//     CSS-var names (from index.css), e.g. "--bg-base", "--accent", "--critical".
//   - Unknown token keys are IGNORED (forward-compat), never crash the validator.
//   - Executable / markup content anywhere in a value is rejected.
//
// Color-token lists are sourced from tokens.json (single source of truth,
// mirrored in backend/lib/theme_schema.py, guarded by a parity test).
import spec from "./tokens.json";

export const KIND = "theme";
export const HEX_RE = new RegExp(spec.hexPattern);

export const REQUIRED_TOKENS: readonly string[] = spec.required;
export const PROTECTED_TOKENS: readonly string[] = spec.protected;
export const OPTIONAL_TOKENS: readonly string[] = spec.optional;

/** Free-string (non-hex) tokens the theme may set — fonts. */
export const FONT_TOKENS: readonly string[] = ["--font-sans", "--font-mono"];

/** Every COLOR token a .side file may set (hex-validated). */
export const COLOR_TOKENS: ReadonlySet<string> = new Set([
  ...spec.required,
  ...spec.protected,
  ...spec.optional,
]);

/** Color tokens a valid theme MUST define (surface palette + protected severities). */
export const MUST_DEFINE: readonly string[] = [...spec.required, ...spec.protected];

export type SideTheme = {
  version: string;
  kind: string;
  name: string;
  author?: string;
  theme: Record<string, string>;
};
