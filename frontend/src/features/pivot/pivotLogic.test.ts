/**
 * Pure unit coverage for pivotLogic — no network, no React, no bus. Fixtures
 * only. Asserts the pivot router's publish decisions:
 *   - selectFinding + a resolved anchor → broadcasts a `selectAnchor` payload
 *     carrying that anchor, the originating findingId, and source "pivot".
 *   - selectFinding + null anchor (dangling ref) → publishes NOTHING.
 *   - selectStep with a resolved file location → broadcasts `selectAnchor`.
 *   - own-source events (source === "pivot") → ignored (no feedback loop),
 *     for both selectFinding and selectStep.
 *   - selectAsset → publishes NOTHING (asset panel highlights itself).
 *   - stepFileAnchor pulls a step's own action.params.file (+ line/labId) and
 *     returns null when the step is absent or carries no file.
 */
import { describe, it, expect } from "vitest";
import type { Anchor, FindingRef, StepRef } from "../../shell/refs";
import {
  PIVOT_SOURCE,
  decideOnSelectFinding,
  decideOnSelectStep,
  decideOnSelectAsset,
  stepFileAnchor,
} from "./pivotLogic";

// ── Fixtures ─────────────────────────────────────────────────────────────────

const findingRef: FindingRef = { findingId: "f1", subTargetId: "sub1", targetId: "t1" };
const stepRef: StepRef = { findingId: "f1", stepId: "s2" };

const fileAnchor: Anchor = { kind: "file", file: "src/app.py", line: 42, labId: "lab-a" };
const routeAnchor: Anchor = { kind: "route", route: "/login" };
const configAnchor: Anchor = { kind: "config", key: "DEBUG" };

// ── selectFinding ────────────────────────────────────────────────────────────

describe("decideOnSelectFinding", () => {
  it("broadcasts selectAnchor when an anchor resolves (file)", () => {
    const d = decideOnSelectFinding("search", findingRef, fileAnchor);
    expect(d).toEqual({
      emit: "selectAnchor",
      payload: { ref: fileAnchor, findingId: "f1", source: PIVOT_SOURCE },
    });
  });

  it("broadcasts selectAnchor for route and config anchors too", () => {
    expect(decideOnSelectFinding("problems", findingRef, routeAnchor)).toEqual({
      emit: "selectAnchor",
      payload: { ref: routeAnchor, findingId: "f1", source: PIVOT_SOURCE },
    });
    expect(decideOnSelectFinding("timeline", findingRef, configAnchor)).toEqual({
      emit: "selectAnchor",
      payload: { ref: configAnchor, findingId: "f1", source: PIVOT_SOURCE },
    });
  });

  it("publishes NOTHING on a dangling ref (anchor === null)", () => {
    expect(decideOnSelectFinding("scandiff", findingRef, null)).toBeNull();
  });

  it("ignores its own echo (source === pivot) — no feedback loop", () => {
    // Even with a perfectly good anchor, an event we emitted is dropped.
    expect(decideOnSelectFinding(PIVOT_SOURCE, findingRef, fileAnchor)).toBeNull();
  });
});

// ── selectStep ───────────────────────────────────────────────────────────────

describe("decideOnSelectStep", () => {
  it("broadcasts selectAnchor when the step resolves to a file location", () => {
    const d = decideOnSelectStep("debugger", stepRef, fileAnchor);
    expect(d).toEqual({
      emit: "selectAnchor",
      payload: { ref: fileAnchor, findingId: "f1", source: PIVOT_SOURCE },
    });
  });

  it("publishes NOTHING when no location resolves for the step", () => {
    expect(decideOnSelectStep("search", stepRef, null)).toBeNull();
  });

  it("ignores its own echo (source === pivot) — no feedback loop", () => {
    expect(decideOnSelectStep(PIVOT_SOURCE, stepRef, fileAnchor)).toBeNull();
  });
});

// ── selectAsset ──────────────────────────────────────────────────────────────

describe("decideOnSelectAsset", () => {
  it("always publishes NOTHING (asset panel highlights itself)", () => {
    expect(decideOnSelectAsset()).toBeNull();
  });
});

// ── stepFileAnchor (pure step→location resolution) ───────────────────────────

describe("stepFileAnchor", () => {
  const steps = [
    { id: "s1", action: { params: {} } },
    { id: "s2", action: { params: { file: "src/routes.py", line: 10, labId: "lab-x" } } },
    { id: "s3", action: { params: { file: "src/db.py" } } }, // no line / labId
    { id: "s4", action: { params: { file: 123 } } }, // non-string file → ignored
  ];

  it("pulls the step's own file param (+ line + labId)", () => {
    expect(stepFileAnchor(steps, "s2")).toEqual({
      kind: "file",
      file: "src/routes.py",
      line: 10,
      labId: "lab-x",
    });
  });

  it("returns a file anchor even without line/labId", () => {
    expect(stepFileAnchor(steps, "s3")).toEqual({
      kind: "file",
      file: "src/db.py",
      line: undefined,
      labId: undefined,
    });
  });

  it("returns null when the step has no (string) file param", () => {
    expect(stepFileAnchor(steps, "s1")).toBeNull();
    expect(stepFileAnchor(steps, "s4")).toBeNull();
  });

  it("returns null when the step id is absent from the chain", () => {
    expect(stepFileAnchor(steps, "nope")).toBeNull();
  });
});
