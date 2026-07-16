/**
 * ACCEPTANCE TEST for the architecture contract (Verify lane).
 *
 * The contract's pass/fail gate: "demonstrate adding a trivial new panel that
 * reacts to an existing bus event WITHOUT editing any existing panel file."
 *
 * This test executes that gate against the REAL registries + bus — no mocks.
 * It imports ONLY the demo panel's own module (../demo/ActiveEngagementPanel).
 * That single import is enough to make the panel fully reachable, which proves
 * the decoupling: the panel self-registers a view and a command, and reacts to
 * a bus event, without any other panel importing it or being edited.
 *
 * If this ever fails, the shell has regressed to panel-to-panel coupling.
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";

import { getView } from "../shell/views";
import { getCommand } from "../shell/commands";
import { on, emit } from "../shell/bus";

// Importing the panel's own file is the ONLY wiring. Its top-level
// registerView()/registerCommand() calls run as import side effects.
import "../demo/ActiveEngagementPanel";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

describe("panel decoupling (contract acceptance test)", () => {
  it("self-registers a view in the registry", () => {
    const view = getView("active-engagement");
    expect(view).toBeDefined();
    expect(view?.component).toBeTypeOf("function");
  });

  it("self-registers a command that opens itself via the bus", () => {
    const cmd = getCommand("open-active-engagement");
    expect(cmd).toBeDefined();

    const opened: unknown[] = [];
    const off = on("openView", (p) => opened.push(p));
    cmd!.run();
    off();

    // One command, reached through the registry, routes to the view through the
    // bus — no direct call into any panel.
    expect(opened).toEqual([{ view: "active-engagement" }]);
  });

  it("renders and reacts to the activeEngagementChanged bus event", () => {
    const Panel = getView("active-engagement")!.component!;
    const container = document.createElement("div");
    document.body.appendChild(container);
    let root: Root;
    act(() => {
      root = createRoot(container);
      root.render(React.createElement(Panel, { params: {} }));
    });

    // Starts at zero observed broadcasts.
    expect(container.textContent).toContain("reacted to 0");

    // A publisher broadcasts; the panel reacts without being called directly.
    act(() => {
      emit("activeEngagementChanged", { engagementId: "eng-xyz" });
    });
    expect(container.textContent).toContain("reacted to 1");

    act(() => {
      emit("activeEngagementChanged", { engagementId: null });
    });
    expect(container.textContent).toContain("reacted to 2");

    act(() => root!.unmount());
    container.remove();
  });
});
