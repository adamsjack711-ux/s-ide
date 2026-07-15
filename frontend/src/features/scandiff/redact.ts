/**
 * Private secret-redaction helper for the scandiff feature (contract: never
 * import another feature — each lane keeps its own copy). Masks common secret
 * shapes before any run output/summary is rendered. Read-only, best-effort:
 * defence-in-depth on top of the backend's redacted reads, so a run's raw
 * `output`/`summary` never leaks a token in the diff UI.
 */

const PATTERNS: { re: RegExp; replace: (m: string, ...g: string[]) => string }[] = [
  // Authorization / Cookie / Set-Cookie headers → keep the header name, mask value.
  { re: /\b(Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:\s*[^\r\n]+/gi,
    replace: (_m, name: string) => `${name}: «redacted»` },
  // Bearer tokens.
  { re: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, replace: () => "Bearer «redacted»" },
  // JWT-ish (three dot-separated base64url segments).
  { re: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
    replace: () => "«redacted-jwt»" },
  // key=value / "password": "..." style secrets.
  { re: /\b(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\b(\s*[=:]\s*)("?)([^\s"'&]{4,})\3/gi,
    replace: (_m, k: string, sep: string) => `${k}${sep}«redacted»` },
  // AWS access key ids.
  { re: /\bAKIA[0-9A-Z]{16}\b/g, replace: () => "«redacted-aws-key»" },
];

export function redactSecrets(text: string | null | undefined): string {
  if (!text) return "";
  let out = String(text);
  for (const { re, replace } of PATTERNS) {
    out = out.replace(re, replace as (substring: string, ...args: any[]) => string);
  }
  return out;
}
