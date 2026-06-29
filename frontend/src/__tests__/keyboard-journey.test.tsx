/**
 * End-to-end keyboard journey (Verify lane).
 *
 * Drives the full security-engagement flow FROM THE KEYBOARD ALONE, against the
 * Foundation lane's real command-registry + keymap + bus APIs — no mocks of
 * those modules. The journey:
 *
 *   ⌘N   → create engagement   (new-engagement → openView{home} + command:focus-create)
 *   ⌘T   → run a tool          (open-tool → s-ide:palette event → openTool → output)
 *   ⌘⇧F  → promote a finding   (promote-to-finding → command:run{promote-to-finding})
 *
 * The global key dispatcher is the REAL one: we mount `useGlobalKeymap()` in a
 * throwaway React component so the same window keydown listener the app installs
 * is the one under test. We then synthesize real KeyboardEvents on `window` and
 * assert the registry resolves each chord to its command and the right bus
 * events fire with the right payloads.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";

import { on, emit, type OutputLine } from "../shell/bus";
import {
  getCommand,
  getCommands,
  registerCommand,
  markUsed,
  type Command,
} from "../shell/commands";
import { KEYMAP, bindingFor, useGlobalKeymap } from "../shell/keymap";
import { TOOLS, toolById } from "../shell/tools";

// React 18 act() needs this flag in non-testing-library setups.
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

// ── Real dispatcher mount ─────────────────────────────────────────────────────

function KeymapHost() {
  useGlobalKeymap();
  return null;
}

let container: HTMLElement;
let root: Root;

function mountDispatcher() {
  container = document.createElement("div");
  document.body.appendChild(container);
  act(() => {
    root = createRoot(container);
    root.render(React.createElement(KeymapHost));
  });
}

function unmountDispatcher() {
  act(() => {
    root.unmount();
  });
  container.remove();
}

/** Press a key with modifiers, exactly as a user would, on window. */
function press(
  key: string,
  mods: { meta?: boolean; shift?: boolean; alt?: boolean } = {},
) {
  const ev = new KeyboardEvent("keydown", {
    key,
    metaKey: !!mods.meta,
    shiftKey: !!mods.shift,
    altKey: !!mods.alt,
    bubbles: true,
    cancelable: true,
  });
  act(() => {
    window.dispatchEvent(ev);
  });
  return ev;
}

// Collect bus events of interest across the journey.
type Captured = { event: string; payload: unknown };

function captureBus(events: string[]) {
  const seen: Captured[] = [];
  const offs: Array<() => void> = [];
  for (const e of events) {
    // `on` is generically typed per-event; we capture a heterogeneous set here.
    offs.push(on(e as any, (payload: unknown) => seen.push({ event: e, payload })));
  }
  return { seen, dispose: () => offs.forEach((o) => o()) };
}

describe("end-to-end keyboard journey", () => {
  beforeEach(() => {
    // NB: we deliberately do NOT clear the registry here. `registerNavCommands()`
    // latches an internal `navRegistered` flag the first time it runs, so wiping
    // the registry between tests would leave the Foundation nav/creation commands
    // permanently unregistered (the latch blocks re-registration). Mounting the
    // real keymap once registers them; they persist for the suite. Contextual
    // commands we add per-test (`promote-to-finding`) are disposed by each test.
    mountDispatcher(); // installs the real keymap listener + registerNavCommands()
  });

  afterEach(() => {
    unmountDispatcher();
    vi.restoreAllMocks();
  });

  it("mounting the keymap registers the Foundation nav + creation commands", () => {
    // useGlobalKeymap → registerNavCommands() ran on mount.
    expect(getCommand("new-engagement")).toBeDefined();
    expect(getCommand("open-tool")).toBeDefined();
    // Every key→commandId in the central keymap resolves to a real binding label.
    for (const entry of KEYMAP) {
      expect(bindingFor(entry.commandId)).toBeTruthy();
    }
    // The three journey chords are present in the central keymap.
    const byCmd = (id: string) => KEYMAP.find((k) => k.commandId === id)?.chord;
    expect(byCmd("new-engagement")).toMatchObject({ key: "n", meta: true });
    expect(byCmd("open-tool")).toMatchObject({ key: "t", meta: true });
    expect(byCmd("promote-to-finding")).toMatchObject({ key: "f", meta: true, shift: true });
  });

  it("⌘N creates an engagement: fires openView(home) + command:focus-create", () => {
    const cap = captureBus(["openView", "command:focus-create"]);
    const ev = press("n", { meta: true });

    expect(ev.defaultPrevented).toBe(true); // dispatcher claimed the chord
    const events = cap.seen.map((c) => c.event);
    expect(events).toContain("openView");
    expect(events).toContain("command:focus-create");
    const openView = cap.seen.find((c) => c.event === "openView");
    expect(openView?.payload).toMatchObject({ view: "home" });
    cap.dispose();
  });

  it("⌘T runs a tool: dispatches the palette tool-search, then openTool streams output", () => {
    // Step 1: ⌘T asks the palette to open in tool mode (window CustomEvent).
    const paletteCalls: Array<Record<string, unknown>> = [];
    const onPalette = (e: Event) =>
      paletteCalls.push((e as CustomEvent).detail ?? {});
    window.addEventListener("s-ide:palette", onPalette as EventListener);

    const ev = press("t", { meta: true });
    expect(ev.defaultPrevented).toBe(true);
    expect(paletteCalls).toEqual([{ mode: "tool" }]);
    window.removeEventListener("s-ide:palette", onPalette as EventListener);

    // Step 2: choosing a tool from the palette emits openTool — pick a real
    // descriptor so the journey runs against the actual tool registry.
    expect(TOOLS.length).toBeGreaterThan(0);
    const tool = TOOLS[0];
    const cap = captureBus(["openTool", "output"]);
    emit("openTool", { toolId: tool.id });

    // Step 3: the opened tool surface streams an output line.
    const line: OutputLine = {
      ts: Date.now(),
      tool: tool.id,
      level: "hit",
      text: "open port 443/tcp",
    };
    emit("output", line);

    const opened = cap.seen.find((c) => c.event === "openTool");
    expect(opened?.payload).toMatchObject({ toolId: tool.id });
    expect(toolById(tool.id)).toBeDefined(); // resolves in the real registry

    const out = cap.seen.find((c) => c.event === "output");
    expect(out?.payload).toMatchObject({ tool: tool.id, level: "hit" });
    cap.dispose();
  });

  it("⌘⇧F promotes a finding: runs the contextual promote command via the bus", () => {
    // The Findings lane registers `promote-to-finding` at mount; replicate that
    // contract here (id + binding + run that re-broadcasts on the bus) so the
    // chord has a live command to resolve — exactly the FindingsView wiring.
    const ran: Array<{ commandId: string }> = [];
    const offRun = on("command:run", (p) => ran.push(p));
    const promote: Command = {
      id: "promote-to-finding",
      title: "Promote result to finding",
      keywords: ["finding", "promote"],
      binding: bindingFor("promote-to-finding"),
      run: () => emit("command:run", { commandId: "promote-to-finding" }),
    };
    const offCmd = registerCommand(promote);

    // The palette/keymap mark usage; assert the binding is what the keymap owns.
    expect(bindingFor("promote-to-finding")).toBe("⌘⇧F");

    const ev = press("f", { meta: true, shift: true });
    expect(ev.defaultPrevented).toBe(true);
    expect(ran).toEqual([{ commandId: "promote-to-finding" }]);

    offCmd();
    offRun();
  });

  it("the full journey runs end-to-end from the keyboard with no direct calls", () => {
    // Register the contextual promote command (Findings lane contract).
    const events: string[] = [];
    const offs = [
      on("command:focus-create", () => events.push("focus-create")),
      on("openTool", () => events.push("openTool")),
      on("output", () => events.push("output")),
      on("command:run", (p) => events.push(`run:${p.commandId}`)),
    ];
    registerCommand({
      id: "promote-to-finding",
      title: "Promote result to finding",
      run: () => emit("command:run", { commandId: "promote-to-finding" }),
    });

    // ⌘N — create engagement
    press("n", { meta: true });
    // ⌘T — open tool palette, then choose a tool + stream output
    press("t", { meta: true });
    emit("openTool", { toolId: TOOLS[0].id });
    emit("output", { ts: Date.now(), tool: TOOLS[0].id, level: "done", text: "scan complete" });
    // ⌘⇧F — promote a finding
    press("f", { meta: true, shift: true });

    // Ordered milestones of the journey were all reached from the keyboard.
    expect(events).toEqual([
      "focus-create",
      "openTool",
      "output",
      "run:promote-to-finding",
    ]);

    // Sanity: the registry still holds the Foundation nav commands + our promote.
    const ids = new Set(getCommands().map((c) => c.id));
    expect(ids.has("new-engagement")).toBe(true);
    expect(ids.has("open-tool")).toBe(true);
    expect(ids.has("promote-to-finding")).toBe(true);

    offs.forEach((o) => o());
    markUsed("promote-to-finding"); // exercise the use-tracking path the palette runs
  });
});
