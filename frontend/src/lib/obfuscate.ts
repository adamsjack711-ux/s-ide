/**
 * Payload obfuscation engine — pure, client-side, no backend.
 *
 * Given a raw payload, produce a set of encoding/evasion variants used to slip
 * a payload past naive filters/WAFs during authorized testing. Every function
 * is a pure string transform so the set is trivially unit-testable and runs
 * entirely in the renderer (the tool has no server route).
 *
 * These are standard, well-documented encodings — not a novel evasion — and are
 * only useful against a target the operator is authorized to test (the same
 * scope/authorization/audit gates apply to whatever tool consumes the output).
 */

export type ObfContext = "any" | "url" | "html" | "js" | "sql";

export type Variant = {
  /** Stable technique id. */
  id: string;
  /** Human label shown in the results table. */
  label: string;
  /** The transformed payload. */
  value: string;
  /** Contexts where this variant is typically relevant. */
  contexts: ObfContext[];
};

const enc = new TextEncoder();

/** Percent-encode every byte (not just the RFC-3986 "unsafe" set). */
function percentEncodeAll(s: string): string {
  return Array.from(enc.encode(s))
    .map((b) => "%" + b.toString(16).toUpperCase().padStart(2, "0"))
    .join("");
}

function toBase64(s: string): string {
  // btoa needs a binary string; round-trip through UTF-8 bytes so non-ASCII
  // payloads encode correctly.
  let bin = "";
  for (const b of enc.encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** `\xNN` per UTF-8 byte — always two hex digits, correct for multi-byte input. */
function hexEscape(s: string): string {
  return Array.from(enc.encode(s))
    .map((b) => "\\x" + b.toString(16).padStart(2, "0"))
    .join("");
}

/** `\uNNNN` per UTF-16 code unit — astral chars emit their surrogate pair. */
function unicodeEscape(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    out += "\\u" + s.charCodeAt(i).toString(16).padStart(4, "0");
  }
  return out;
}

/** Numeric HTML entities per Unicode code point (correct for astral chars). */
function htmlEntities(s: string, hex: boolean): string {
  return Array.from(s)
    .map((c) => {
      const cp = c.codePointAt(0)!;
      return hex ? "&#x" + cp.toString(16) + ";" : "&#" + cp + ";";
    })
    .join("");
}

/** Alternate upper/lower — keyword-filter evasion (e.g. SeLeCt, ScRiPt). */
function mixedCase(s: string): string {
  let up = false;
  return Array.from(s)
    .map((c) => {
      if (!/[a-z]/i.test(c)) return c;
      up = !up;
      return up ? c.toUpperCase() : c.toLowerCase();
    })
    .join("");
}

/** Replace runs of whitespace with an inline SQL comment. */
function sqlCommentSpaces(s: string): string {
  return s.replace(/\s+/g, "/**/");
}

/** JS String.fromCharCode(...) reconstruction (UTF-16 code units). */
function jsFromCharCode(s: string): string {
  const units: number[] = [];
  for (let i = 0; i < s.length; i++) units.push(s.charCodeAt(i));
  return "String.fromCharCode(" + units.join(",") + ")";
}

/** Break into a concatenated JS string literal ('a'+'b'+...). */
function jsConcat(s: string): string {
  return Array.from(s)
    .map((c) => (c === "'" ? "\"'\"" : `'${c}'`))
    .join("+");
}

const TRANSFORMS: { id: string; label: string; contexts: ObfContext[]; fn: (s: string) => string }[] = [
  { id: "url", label: "URL-encode (all bytes)", contexts: ["url", "any"], fn: percentEncodeAll },
  { id: "url_double", label: "Double URL-encode", contexts: ["url", "any"], fn: (s) => percentEncodeAll(percentEncodeAll(s)) },
  { id: "base64", label: "Base64", contexts: ["any", "js"], fn: toBase64 },
  { id: "hex", label: "Hex escape (\\xNN)", contexts: ["js", "any"], fn: hexEscape },
  { id: "unicode", label: "Unicode escape (\\uNNNN)", contexts: ["js", "any"], fn: unicodeEscape },
  { id: "html_dec", label: "HTML entities (decimal)", contexts: ["html"], fn: (s) => htmlEntities(s, false) },
  { id: "html_hex", label: "HTML entities (hex)", contexts: ["html"], fn: (s) => htmlEntities(s, true) },
  { id: "mixed_case", label: "Mixed case", contexts: ["sql", "html", "any"], fn: mixedCase },
  { id: "sql_comment", label: "SQL inline-comment spaces (/**/)", contexts: ["sql"], fn: sqlCommentSpaces },
  { id: "js_fromcharcode", label: "JS String.fromCharCode()", contexts: ["js"], fn: jsFromCharCode },
  { id: "js_concat", label: "JS string concat", contexts: ["js"], fn: jsConcat },
];

/**
 * Produce obfuscation variants for a payload. When `context` is not "any",
 * context-relevant variants sort first (all variants are still returned).
 */
export function obfuscate(payload: string, context: ObfContext = "any"): Variant[] {
  const variants: Variant[] = TRANSFORMS.map((t) => ({
    id: t.id,
    label: t.label,
    value: t.fn(payload),
    contexts: t.contexts,
  }));
  if (context === "any") return variants;
  return [...variants].sort((a, b) => {
    const ra = a.contexts.includes(context) ? 0 : 1;
    const rb = b.contexts.includes(context) ? 0 : 1;
    return ra - rb;
  });
}
