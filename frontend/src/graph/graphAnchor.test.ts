/**
 * Graph → bus wiring: the pure anchor mappers behind GraphView's click handlers.
 * A click on a node / asset item / SAST finding resolves to a code Anchor and is
 * broadcast as `selectAnchor` (source "graph"); these mappers are that
 * resolution. (The emit itself is the trivial one-liner publishAnchor.)
 */
import { describe, it, expect } from "vitest";
import { nodeAnchor, itemAnchor, findingAnchor } from "./GraphView";

describe("graph anchor mappers (node/item/finding → Anchor)", () => {
  it("backend node → route anchor; path-shaped frontend node → file anchor", () => {
    expect(nodeAnchor({ id: "b1", label: "/api/login", layer: "backend", kind: "route" }))
      .toEqual({ kind: "route", route: "/api/login" });
    expect(nodeAnchor({ id: "f1", label: "shell/bus.ts", layer: "frontend" }))
      .toEqual({ kind: "file", file: "shell/bus.ts" });
  });

  it("a frontend node labelled by bare module name → null (nothing to open)", () => {
    // The backend labels frontend module nodes by directory ("shell", "graph"),
    // which is not an openable file — anchoring on it produced a bogus location.
    expect(nodeAnchor({ id: "f2", label: "shell", layer: "frontend" })).toBeNull();
    expect(nodeAnchor({ id: "f3", label: "graph", layer: "frontend" })).toBeNull();
  });

  it("asset item with a file → file anchor (with line)", () => {
    expect(itemAnchor("routes", { name: "GET /users", file: "app/routes.py", line: 88 }))
      .toEqual({ kind: "file", file: "app/routes.py", line: 88 });
  });

  it("route/config items without a file → route/config anchors", () => {
    expect(itemAnchor("routes", { name: "/health" })).toEqual({ kind: "route", route: "/health" });
    expect(itemAnchor("configs", { name: "DEBUG" })).toEqual({ kind: "config", key: "DEBUG" });
  });

  it("a locationless item (e.g. a language) → null (no anchor published)", () => {
    expect(itemAnchor("languages", { name: "Python" })).toBeNull();
  });

  it("SAST finding → file anchor at its line", () => {
    expect(findingAnchor({ severity: "high", title: "SQLi", type: "sqli", file: "app/db.py", line: 12 }))
      .toEqual({ kind: "file", file: "app/db.py", line: 12 });
  });
});
