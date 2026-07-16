/**
 * useBus must hold ONE stable subscription per (component, event) — not one per
 * render — while the handler still observes current state. Before this fix the
 * effect depended on `handler` (a fresh inline closure each render), so every
 * render tore the listener down and re-registered it; with ~10 panels mounted
 * that churned dozens of Set delete/add pairs on every state change.
 */
import { describe, it, expect } from "vitest";
import React, { useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { emit, useBus, _listenerCount } from "./bus";

function Subscriber({ onSeen }: { onSeen: (n: number) => void }) {
  const [n, setN] = useState(0);
  // A fresh inline closure every render (the common call-site shape).
  useBus("findingsChanged", () => onSeen(n));
  return React.createElement(
    "button",
    { onClick: () => setN((x) => x + 1) },
    `bump ${n}`,
  );
}

function mount(el: React.ReactElement): { container: HTMLDivElement; root: Root } {
  const container = document.createElement("div");
  document.body.appendChild(container);
  let root!: Root;
  act(() => {
    root = createRoot(container);
    root.render(el);
  });
  return { container, root };
}

describe("useBus subscription stability", () => {
  it("registers exactly one listener and keeps it across re-renders", () => {
    const before = _listenerCount("findingsChanged");
    const seen: number[] = [];
    const { container, root } = mount(
      React.createElement(Subscriber, { onSeen: (n: number) => seen.push(n) }),
    );

    expect(_listenerCount("findingsChanged")).toBe(before + 1);

    // Force several re-renders by bumping local state.
    const btn = container.querySelector("button")!;
    act(() => btn.click());
    act(() => btn.click());
    act(() => btn.click());

    // Still exactly one listener — no churn.
    expect(_listenerCount("findingsChanged")).toBe(before + 1);

    // And the handler observes the LATEST state, not a stale closure.
    act(() => emit("findingsChanged", {}));
    expect(seen.at(-1)).toBe(3);

    act(() => root.unmount());
    container.remove();
  });

  it("unsubscribes on unmount", () => {
    const before = _listenerCount("findingsChanged");
    const { container, root } = mount(
      React.createElement(Subscriber, { onSeen: () => {} }),
    );
    expect(_listenerCount("findingsChanged")).toBe(before + 1);
    act(() => root.unmount());
    container.remove();
    expect(_listenerCount("findingsChanged")).toBe(before);
  });
});
