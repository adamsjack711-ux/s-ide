/**
 * PHASE-0 CONTRACT ACCEPTANCE TEST.
 *
 * Gate for the feature suite: a brand-new panel that reacts to the NEW
 * `selectFinding` selection event, added WITHOUT editing any existing panel.
 * Executed against the REAL registries + bus (no mocks). The single import of
 * the EchoPanel's own module is the ONLY wiring — its registerView/
 * registerCommand run as import side effects and it reacts to the bus.
 *
 * If this fails, the Phase-0 contract has regressed and Phase 1 must not fan out.
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";

import { getView } from "../shell/views";
import { getCommand } from "../shell/commands";
import { on, emit } from "../shell/bus";
import type { FindingRef } from "../shell/refs";

// Importing the panel's own file is the ONLY wiring.
import "../features/echo/EchoPanel";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const REF: FindingRef = { findingId: "f-123", subTargetId: "st-9", targetId: "t-1" };

describe("Phase-0 selection contract (acceptance gate)", () => {
  it("EchoPanel self-registers a view + command", () => {
    const view = getView("echo-selection");
    expect(view?.component).toBeTypeOf("function");

    const cmd = getCommand("open-echo-selection");
    expect(cmd).toBeDefined();

    const opened: unknown[] = [];
    const off = on("openView", (p) => opened.push(p));
    cmd!.run();
    off();
    expect(opened).toEqual([{ view: "echo-selection" }]);
  });

  it("reacts to selectFinding broadcast without any direct call", () => {
    const Panel = getView("echo-selection")!.component!;
    const container = document.createElement("div");
    document.body.appendChild(container);
    let root: Root;
    act(() => {
      root = createRoot(container);
      root.render(React.createElement(Panel, { params: {} }));
    });

    expect(container.textContent).toContain("reacted to 0");
    expect(container.textContent).toContain("none selected");

    // A publisher broadcasts a canonical FindingRef; the panel reacts.
    act(() => emit("selectFinding", { ref: REF, source: "test" }));
    expect(container.textContent).toContain("reacted to 1");
    expect(container.textContent).toContain("f-123");
    expect(container.textContent).toContain("st-9");

    act(() => root!.unmount());
    container.remove();
  });
});
