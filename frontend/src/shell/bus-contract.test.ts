/**
 * Bus wiring contract — a STATIC audit of the connective-tissue bus events.
 *
 * The bus is stringly-typed pub/sub, so the type system cannot catch an event
 * that is emitted but never subscribed (a click that silently does nothing) or
 * subscribed but never emitted (a listener that can never fire). Both shipped on
 * this branch before review: `selectAsset` had no consumer, and
 * `modelChanged{entity:"run"}` had no emitter. This test scans the source for
 * `emit("X"` / `useBus("X"` / `on("X"` and asserts the reactive selection/model
 * events are wired on BOTH sides — with a short, documented exception list so a
 * deliberately-unwired event is a recorded choice, not a silent gap.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === "node_modules" || ent.name === "__tests__") continue;
      out.push(...sourceFiles(p));
    } else if (/\.(ts|tsx)$/.test(ent.name) && !/\.test\.tsx?$/.test(ent.name)) {
      out.push(p);
    }
  }
  return out;
}

const CORPUS = sourceFiles(SRC)
  .map((f) => readFileSync(f, "utf8"))
  .join("\n");

const count = (verbs: string, ev: string) =>
  (CORPUS.match(new RegExp(`(?:${verbs})\\(\\s*["']${ev}["']`, "g")) ?? []).length;
const emitters = (ev: string) => count("emit", ev);
const subscribers = (ev: string) => count("useBus|on", ev);

// The connective-tissue events: a feature that focuses an object BROADCASTS one
// of these, and any feature that cares SUBSCRIBES. Both sides must exist, or the
// wire is dead. (Reactor coverage is what the phase-0/phase-2 tests exercise;
// this is the cheap static guard that the *wire* exists at all.)
const REACTIVE = [
  "selectFinding",
  "selectAnchor",
  "selectStep",
  "selectSubTarget",
  "modelChanged",
  "activeEngagementChanged",
  "subTargetArmed",
  "subTargetDisarmed",
  "attestationsChanged",
];

// Events that are intentionally emitter-only for now: the publisher exists but
// the intended reactor isn't built yet. Each is a KNOWN, documented seam — kept
// so the consumer can land without touching publishers. The guard below makes
// each a recorded decision: if a subscriber appears, the test fails and tells
// you to promote it into REACTIVE, so the list can never silently hide a dead
// wire that has since become live.
//   - selectAsset       : no asset-tree / graph highlight consumes it yet.
//   - pairingRunStarted : the Workbench live-output console isn't wired; run
//   - pairingRunOutput  :   status/output reach panels via modelChanged{run}
//                           and the runPairing() return value instead.
const EMITTER_ONLY = ["selectAsset", "pairingRunStarted", "pairingRunOutput"];

describe("bus wiring contract", () => {
  it("every reactive selection/model event has at least one emitter", () => {
    const dead = REACTIVE.filter((ev) => emitters(ev) === 0);
    expect(dead, `emitted by nobody (dead listeners): ${dead.join(", ")}`).toEqual([]);
  });

  it("every reactive selection/model event has at least one subscriber", () => {
    const void_ = REACTIVE.filter((ev) => subscribers(ev) === 0);
    expect(void_, `emitted into the void (no subscriber): ${void_.join(", ")}`).toEqual([]);
  });

  it("documented emitter-only events stay emitter-only (promote them if a reactor lands)", () => {
    for (const ev of EMITTER_ONLY) {
      expect(emitters(ev), `${ev} is listed emitter-only but nothing emits it`).toBeGreaterThan(0);
      expect(
        subscribers(ev),
        `${ev} now has a subscriber — move it into REACTIVE and drop it from EMITTER_ONLY`,
      ).toBe(0);
    }
  });
});
