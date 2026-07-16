/**
 * PHASE-2 · T4 — No coupling regressions.
 *
 * Repeats the Phase-0 decoupling gate against a DIFFERENT selection event
 * (`selectAsset`) AFTER the full F1–F9 feature suite has landed. A brand-new
 * panel that reacts to a bus event is added here WITHOUT editing any feature or
 * shell file — it self-registers and reacts purely through the registries + bus.
 * If adding it required touching a feature, coupling has regressed.
 *
 * The throwaway panel is defined INLINE in this test (it imports only the frozen
 * contract: shell/views, shell/commands, shell/bus, shell/refs) — proving a new
 * contributor needs nothing but the contract.
 */
import { describe, it, expect } from "vitest";
import React, { useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";

import { registerView, getView } from "../shell/views";
import { registerCommand, getCommand } from "../shell/commands";
import { emit, on, useBus } from "../shell/bus";
import type { AssetRef } from "../shell/refs";

// A second throwaway panel — mirrors EchoPanel but for selectAsset. Added with
// ZERO edits to any existing feature/panel/shell file.
function AssetEchoPanel(_props: { params: Record<string, any> }) {
  const [last, setLast] = useState<AssetRef | null>(null);
  const [count, setCount] = useState(0);
  useBus("selectAsset", (p) => {
    setLast(p.ref);
    setCount((n) => n + 1);
  });
  return (
    <div>
      <span data-testid="count">{count}</span>
      <span data-testid="asset">{last ? last.assetId : "none"}</span>
    </div>
  );
}

registerView({ id: "asset-echo", component: AssetEchoPanel });
registerCommand({
  id: "open-asset-echo",
  title: "Open Asset Echo (T4 coupling proof)",
  keywords: ["asset", "echo", "t4"],
  context: "View",
  run: () => emit("openView", { view: "asset-echo" }),
});

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const REF: AssetRef = { subTargetId: "st-1", assetId: "host:10.0.0.5", kind: "host" };

describe("Phase-2 T4 — no coupling regressions", () => {
  it("a second throwaway panel self-registers a view + command", () => {
    expect(getView("asset-echo")?.component).toBeTypeOf("function");
    const cmd = getCommand("open-asset-echo");
    expect(cmd).toBeDefined();
    const opened: unknown[] = [];
    const off = on("openView", (p) => opened.push(p));
    cmd!.run();
    off();
    expect(opened).toEqual([{ view: "asset-echo" }]);
  });

  it("reacts to selectAsset via the bus with no direct call", () => {
    const Panel = getView("asset-echo")!.component!;
    const container = document.createElement("div");
    document.body.appendChild(container);
    let root: Root;
    act(() => {
      root = createRoot(container);
      root.render(React.createElement(Panel, { params: {} }));
    });
    expect(container.querySelector('[data-testid="count"]')?.textContent).toBe("0");
    act(() => emit("selectAsset", { ref: REF, source: "test" }));
    expect(container.querySelector('[data-testid="count"]')?.textContent).toBe("1");
    expect(container.querySelector('[data-testid="asset"]')?.textContent).toBe("host:10.0.0.5");
    act(() => root!.unmount());
    container.remove();
  });
});
