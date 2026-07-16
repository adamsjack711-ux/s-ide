/**
 * The single secret-redaction helper for the whole shell.
 *
 * "Never render a secret" is a T5 invariant. It used to live as ~6 hand-copied
 * variants inside individual feature lanes (search / scandiff / fixdiff / pivot /
 * debugger / timeline), which had already DRIFTED — the timeline copy masked
 * GitHub/Slack tokens and PRIVATE KEY blocks the others missed, and copies used
 * different mask tokens. A security invariant fragmented across drifting copies
 * is worse than one shared module, so this is the union of every copy's patterns
 * with one canonical mask. Feature lanes import from here (lib/ is shared
 * infrastructure — importing it does NOT violate the "don't import another
 * feature" rule in features/CONTRACT.md).
 *
 * Best-effort defence-in-depth on top of the backend's redacted reads. Pure and
 * idempotent: re-running over already-masked text is a no-op (the mask token
 * matches none of the patterns). Prefer over-masking; leaking is never acceptable.
 */

const MASK = "«redacted»";

type Rule = { re: RegExp; replace: string | ((m: string, ...g: string[]) => string) };

// Order matters: header / flag / key rules (which KEEP a label and mask the
// value) run before the bare-token rules, so a token INSIDE a header is
// swallowed by the header rule rather than left behind.
const RULES: Rule[] = [
  // ── Named rules: keep the label, mask the value ──────────────────────────
  // Authorization / Proxy-Authorization — mask value incl. any scheme token.
  {
    re: /\b(Authorization|Proxy-Authorization)(\s*[:=]\s*)(?:Bearer|Basic|Digest|Negotiate|Token)?\s*[^\r\n;'"]+/gi,
    replace: (_m, name: string, sep: string) => `${name}${sep}${MASK}`,
  },
  // Cookie / Set-Cookie — mask the whole value.
  {
    re: /\b(Set-Cookie|Cookie)(\s*[:=]\s*)[^\r\n]+/gi,
    replace: (_m, name: string, sep: string) => `${name}${sep}${MASK}`,
  },
  // Secret-bearing custom headers.
  {
    re: /\b(X-Api-Key|X-Auth-Token)(\s*[:=]\s*)[^\r\n]+/gi,
    replace: (_m, name: string, sep: string) => `${name}${sep}${MASK}`,
  },
  // CLI credential flags: -p / -w / --password / --pass / --token / --secret.
  {
    re: /(--password|--pass|--token|--secret|-p|-w)(\s+)(?!-)[^\s"']+/gi,
    replace: (_m, flag: string, sp: string) => `${flag}${sp}${MASK}`,
  },
  // key/token/secret/password-style pairs (json, query, headers, env).
  {
    re: /\b(api[_-]?key|apikey|access[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|session[_-]?id|sessionid|session|secret|password|passwd|pwd|token|auth|credential)s?\b(\s*["']?\s*[:=]\s*["']?)([^\s"',&}]+)/gi,
    replace: (_m, key: string, sep: string) => `${key}${sep}${MASK}`,
  },
  // Inline URL credentials — scheme://user:password@host → keep user, mask pass.
  {
    re: /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)[^\s@/]+(@)/gi,
    replace: `$1${MASK}$2`,
  },

  // ── Value rules: the match IS the secret; mask the whole thing ────────────
  // Bearer / Basic tokens standing alone (not caught by a header rule above).
  { re: /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, replace: MASK },
  // JWTs (three base64url segments).
  { re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g, replace: MASK },
  // AWS access key ids.
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: MASK },
  // GitHub / Slack prefixed tokens.
  { re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, replace: MASK },
  // PEM private-key blocks.
  { re: /-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----/g, replace: MASK },
  // Long hex / base64-ish blobs (32+ chars) — likely a key, not prose.
  { re: /\b[A-Fa-f0-9]{32,}\b/g, replace: MASK },
];

/**
 * Mask credential-shaped substrings in free text. Accepts any input; a nullish
 * or non-string value yields "". Pure + idempotent.
 */
export function redactSecrets(text: unknown): string {
  if (typeof text !== "string" || text.length === 0) return "";
  let out = text;
  for (const { re, replace } of RULES) {
    re.lastIndex = 0; // global regexes are stateful — reset before each pass
    out = out.replace(re, replace as (substring: string, ...args: any[]) => string);
  }
  return out;
}

/** Alias — some lanes historically called this `redactString`. */
export const redactString = redactSecrets;

/** The canonical mask token, exported for callers that assert on it. */
export const REDACTION_MASK = MASK;
