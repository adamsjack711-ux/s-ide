/**
 * Tiny in-process pub/sub that decouples the shell's panels.
 *
 * The Explorer / command palette emit `openTool`; the dockview Workspace
 * subscribes and adds a panel. Tool panels emit `output` lines; the Output
 * dock subscribes and renders them. Keeping this out of React context avoids
 * prop-drilling across the dockview boundary (panels are mounted by dockview,
 * not by our tree).
 */
import { useEffect } from "react";

export type OutputLine = {
  ts: number;
  tool: string;
  level: "info" | "hit" | "error" | "done";
  text: string;
};

type Events = {
  openTool: { toolId: string };
  output: OutputLine;
  focusFinding: { findingId: string };
  promote: { tool: string; target: string; title: string; description: string; evidence: string };
  findingsChanged: Record<string, never>;
  assetDiscovered: { scopeKey: string | null; tool: string; assets: { kind: string; key: string; props?: Record<string, unknown> }[] };
  promoteSteps: Record<string, never>;
  openEditor: { labId: string; path: string };
  openAttestation: Record<string, never>;
  attestationsChanged: Record<string, never>;
  /** Open a non-tool view as a tab in the center editor area. */
  openView: { view: "home" | "findings" | "reports" | "learn" | "settings" | "playbook" | "graph" | "build" | "labs"; params?: Record<string, unknown> };
};

type Handler<K extends keyof Events> = (payload: Events[K]) => void;

const listeners: { [K in keyof Events]?: Set<Handler<K>> } = {};

export function emit<K extends keyof Events>(event: K, payload: Events[K]): void {
  listeners[event]?.forEach((h) => h(payload));
}

export function on<K extends keyof Events>(event: K, handler: Handler<K>): () => void {
  (listeners[event] ??= new Set() as any).add(handler);
  return () => listeners[event]?.delete(handler);
}

/** React convenience: subscribe for the lifetime of a component. */
export function useBus<K extends keyof Events>(event: K, handler: Handler<K>): void {
  useEffect(() => on(event, handler), [event, handler]);
}
