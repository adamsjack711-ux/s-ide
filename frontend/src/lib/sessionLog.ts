// In-memory ring buffer of recent tool activity, used as context for the
// Claude chat. Every successful `api()` call lands here (see api.ts), and pages
// can opt-in to push additional events (e.g. WS "done" payloads) via record().
//
// Append-only + content-hashed (Stage 2 — evidence chain):
//   Each kept SessionEvent carries an immutable content (ts/category/summary)
//   plus a SHA-256 `hash` over a canonical encoding of {prev, ts, category,
//   summary} and `prev` = the previous kept entry's hash. Entries are never
//   mutated after their content is set; the only async write is patching the
//   computed `hash` onto the entry once crypto.subtle resolves (the content
//   that the hash covers is fixed at record() time, so the chain is stable).
//
//   crypto.subtle.digest is async, so hashing runs through a serialized
//   promise queue that preserves record() order; `record()` keeps its
//   synchronous signature. `verifyLog()` re-walks the kept entries and returns
//   whether the chain is intact. Ring-buffer eviction drops OLD entries; the
//   chain is verified over whatever entries remain (the oldest kept entry is
//   treated as a chain head — its `prev` is whatever it was linked to, which
//   may have been evicted, so verification re-checks links between *adjacent
//   kept* entries rather than asserting a genesis).

import { useEffect, useState } from "react";

export type SessionEvent = {
  ts: string;        // ISO timestamp
  category: string;  // path or human label (e.g. "/nmap/run", "Port Scanner: done")
  summary: string;   // short string, JSON-stringified + truncated if needed
  // ── evidence chain (set once; content above is immutable) ──
  prev: string | null;   // hash of the previous kept entry at record() time
  hash: string | null;   // SHA-256 of canonical content; null until async digest resolves
};

const MAX_EVENTS = 50;
const SUMMARY_MAX = 1200;

let buffer: SessionEvent[] = [];
const listeners = new Set<() => void>();

// The previous recorded entry, captured synchronously at record() time. Its
// `hash` is resolved by the time the next entry's queued digest runs (the
// queue is serialized in record() order), so we read prevEntry.hash there to
// fill in `prev` — this keeps links deterministic even though several
// record() calls in one tick all precede any digest resolving.
let prevEntry: SessionEvent | null = null;
// Serialize async hashing so entries are hashed in the exact order recorded.
let hashQueue: Promise<void> = Promise.resolve();

function notify() {
  for (const l of listeners) l();
}

function summarize(value: unknown): string {
  let s: string;
  try {
    s = typeof value === "string" ? value : JSON.stringify(value);
  } catch {
    s = String(value);
  }
  if (s.length > SUMMARY_MAX) s = s.slice(0, SUMMARY_MAX) + "…(truncated)";
  return s;
}

// Canonical, stable string the hash is computed over. Field order is fixed and
// each field is JSON-encoded so separators can't collide with content.
function canonical(prev: string | null, ev: Pick<SessionEvent, "ts" | "category" | "summary">): string {
  return JSON.stringify([prev, ev.ts, ev.category, ev.summary]);
}

async function sha256Hex(input: string): Promise<string> {
  const subtle = (globalThis.crypto as Crypto | undefined)?.subtle;
  if (!subtle) {
    // No WebCrypto (non-secure context / old runtime): fall back to a cheap
    // non-cryptographic digest so the chain still links deterministically.
    return fnv1aHex(input);
  }
  const bytes = new TextEncoder().encode(input);
  const digest = await subtle.digest("SHA-256", bytes);
  const view = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < view.length; i++) hex += view[i].toString(16).padStart(2, "0");
  return hex;
}

// Deterministic 32-bit FNV-1a fallback (hex), only used when WebCrypto is
// unavailable. Not collision-resistant — just keeps the chain walkable.
function fnv1aHex(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return "fnv" + (h >>> 0).toString(16).padStart(8, "0");
}

export function record(category: string, value: unknown): void {
  const entry: SessionEvent = {
    ts: new Date().toISOString(),
    category,
    summary: summarize(value),
    prev: null,            // patched in the queue from the predecessor's hash
    hash: null,            // filled in once the async digest resolves
  };
  // Capture the predecessor synchronously so ordering is fixed regardless of
  // how many record() calls fire before any digest resolves.
  const predecessor = prevEntry;
  prevEntry = entry;
  buffer = [...buffer, entry].slice(-MAX_EVENTS);
  notify();

  // Chained on hashQueue so links resolve in record() order. By the time this
  // step runs, `predecessor.hash` is already set (its digest was queued first).
  hashQueue = hashQueue
    .then(async () => {
      entry.prev = predecessor ? predecessor.hash : null;
      entry.hash = await sha256Hex(canonical(entry.prev, entry));
      notify();
    })
    .catch(() => {
      /* leave hash null; verifyLog() will report the gap */
    });
}

export function clearLog(): void {
  buffer = [];
  prevEntry = null;
  hashQueue = Promise.resolve();
  notify();
}

export function snapshot(): SessionEvent[] {
  return buffer.slice();
}

/**
 * Re-walk the kept entries and recompute each hash from its content + the
 * recorded `prev`, asserting:
 *   1. every kept entry's stored `hash` matches a fresh digest of its content;
 *   2. each entry's `prev` equals the previous kept entry's `hash` (adjacency).
 *
 * The oldest kept entry's `prev` may reference an evicted hash, so its link is
 * not asserted against a predecessor (there is none in the buffer) — only its
 * own hash integrity is checked. Returns ok=false with the offending index on
 * the first mismatch, or while any entry is still awaiting its async digest.
 */
export async function verifyLog(): Promise<{ ok: boolean; index: number | null; reason: string | null }> {
  const entries = snapshot();
  let prevHash: string | null = null;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.hash == null) {
      return { ok: false, index: i, reason: "entry hash not yet computed" };
    }
    const expected = await sha256Hex(canonical(e.prev, e));
    if (expected !== e.hash) {
      return { ok: false, index: i, reason: "content hash mismatch (tampered)" };
    }
    // Adjacency: every entry after the first must chain to its predecessor.
    if (i > 0 && e.prev !== prevHash) {
      return { ok: false, index: i, reason: "broken prev link" };
    }
    prevHash = e.hash;
  }
  return { ok: true, index: null, reason: null };
}

export function useSessionLog(): SessionEvent[] {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((n) => n + 1);
    listeners.add(fn);
    return () => { listeners.delete(fn); };
  }, []);
  return buffer;
}
