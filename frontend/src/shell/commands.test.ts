// Unit coverage for the command registry (Foundation lane). Exercises
// register/unregister, getCommands, and recent ordering. Does NOT cover the
// end-to-end keyboard journey — the Verify phase owns that.
import { describe, it, expect, beforeEach } from "vitest";
import {
  registerCommand,
  unregister,
  getCommands,
  getCommand,
  markUsed,
  getRecent,
  getRecentCommands,
  getUseCount,
  _resetCommandsForTest,
  type Command,
} from "./commands";

function cmd(id: string, title = id): Command {
  return { id, title, run: () => {} };
}

describe("command registry", () => {
  beforeEach(() => _resetCommandsForTest());

  it("registers and lists commands", () => {
    registerCommand(cmd("a", "Alpha"));
    registerCommand(cmd("b", "Beta"));
    const ids = getCommands().map((c) => c.id);
    expect(ids).toEqual(["a", "b"]);
    expect(getCommand("a")?.title).toBe("Alpha");
  });

  it("re-registering the same id replaces in place", () => {
    registerCommand(cmd("a", "Alpha"));
    registerCommand(cmd("a", "Alpha v2"));
    expect(getCommands()).toHaveLength(1);
    expect(getCommand("a")?.title).toBe("Alpha v2");
  });

  it("unregister removes a command", () => {
    const off = registerCommand(cmd("a"));
    expect(getCommand("a")).toBeDefined();
    off();
    expect(getCommand("a")).toBeUndefined();
    // calling the returned disposer is idempotent + matches unregister()
    registerCommand(cmd("b"));
    unregister("b");
    expect(getCommand("b")).toBeUndefined();
  });

  it("the disposer does not clobber a newer registration of the same id", () => {
    const off = registerCommand(cmd("a", "old"));
    registerCommand(cmd("a", "new")); // replaces
    off(); // should be a no-op now — it's not the entry we put in
    expect(getCommand("a")?.title).toBe("new");
  });

  it("markUsed records recency, most-recent first", () => {
    registerCommand(cmd("a"));
    registerCommand(cmd("b"));
    registerCommand(cmd("c"));
    markUsed("a");
    markUsed("b");
    markUsed("c");
    expect(getRecent()).toEqual(["c", "b", "a"]);
    // re-using an existing id moves it to the front without duplicating
    markUsed("a");
    expect(getRecent()).toEqual(["a", "c", "b"]);
  });

  it("getRecentCommands returns only still-registered commands, capped", () => {
    registerCommand(cmd("a"));
    registerCommand(cmd("b"));
    markUsed("a");
    markUsed("b");
    unregister("b"); // b is recent but no longer registered
    const recent = getRecentCommands(6).map((c) => c.id);
    expect(recent).toEqual(["a"]);
  });

  it("getUseCount counts invocations", () => {
    registerCommand(cmd("a"));
    expect(getUseCount("a")).toBe(0);
    markUsed("a");
    markUsed("a");
    expect(getUseCount("a")).toBe(2);
  });
});
