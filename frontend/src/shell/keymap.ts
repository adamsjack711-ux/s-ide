/**
 * Central keymap + global key dispatcher (Foundation lane).
 *
 * The Foundation lane is the SINGLE arbiter of default key bindings — every
 * key→commandId mapping lives here, so there are no conflicts. Feature lanes
 * register their commands (shell/commands.ts) and ask Foundation to add a row
 * to KEYMAP if they want a default binding; an entry whose commandId isn't
 * registered yet is a harmless no-op until the owning lane registers it.
 *
 *   import { useGlobalKeymap, KEYMAP, bindingFor } from "../shell/keymap";
 *
 * - useGlobalKeymap() is mounted ONCE (App.tsx) and dispatches matched keys to
 *   commands.run(). ⌘K stays owned by CommandPalette itself (palette toggle).
 * - bindingFor(commandId) returns the display string ("⌘⇧F") for a command, so
 *   the palette can render it on the row.
 *
 * This module also registers the navigation + creation commands the Foundation
 * lane owns (New Engagement, Open Workbench/Labs/Findings/Settings, Open Tool,
 * Show Getting Started) via registerNavCommands(), called from useGlobalKeymap.
 */
import { useEffect } from "react";
import { emit } from "./bus";
import {
  getCommand,
  markUsed,
  registerCommand,
  type Command,
} from "./commands";

// ── Key chord model ──────────────────────────────────────────────────────────

export type Chord = {
  /** Lower-cased key (e.g. "n", "f", ","). */
  key: string;
  meta?: boolean; // ⌘ / Ctrl (we treat metaKey OR ctrlKey as "mod")
  shift?: boolean;
  alt?: boolean;
};

export type KeymapEntry = { chord: Chord; commandId: string };

const mod = (key: string, extra: Partial<Chord> = {}): Chord => ({
  key,
  meta: true,
  ...extra,
});

/**
 * Default bindings for the top actions. ⌘K is intentionally absent — the
 * palette owns it. CommandIds may be registered by other lanes later.
 */
export const KEYMAP: KeymapEntry[] = [
  { chord: mod("n"), commandId: "new-engagement" },
  { chord: mod("t"), commandId: "open-tool" },
  { chord: mod("f", { shift: true }), commandId: "promote-to-finding" },
  { chord: mod("r", { shift: true }), commandId: "retest" },
  { chord: mod("l"), commandId: "open-labs" },
  { chord: mod(","), commandId: "open-settings" },
  { chord: mod("b"), commandId: "open-workbench" },
  { chord: mod("e", { shift: true }), commandId: "open-findings" },
];

function chordMatches(c: Chord, e: KeyboardEvent): boolean {
  if (c.key !== e.key.toLowerCase()) return false;
  if (!!c.meta !== (e.metaKey || e.ctrlKey)) return false;
  if (!!c.shift !== e.shiftKey) return false;
  if (!!c.alt !== e.altKey) return false;
  return true;
}

function chordLabel(c: Chord): string {
  return (
    (c.meta ? "⌘" : "") +
    (c.alt ? "⌥" : "") +
    (c.shift ? "⇧" : "") +
    (c.key === "," ? "," : c.key.toUpperCase())
  );
}

/** Display string for a command's default binding, or undefined if unbound. */
export function bindingFor(commandId: string): string | undefined {
  const entry = KEYMAP.find((k) => k.commandId === commandId);
  return entry ? chordLabel(entry.chord) : undefined;
}

// ── Navigation + creation commands owned by Foundation ───────────────────────

let navRegistered = false;

function navCmd(
  id: string,
  title: string,
  run: Command["run"],
  keywords?: string[],
): Command {
  return { id, title, run, keywords, binding: bindingFor(id), context: "Go to" };
}

/**
 * Registers the shell-level navigation + creation commands. Idempotent — safe
 * to call from the keymap hook on every mount (re-register replaces in place).
 */
export function registerNavCommands(): void {
  if (navRegistered) return;
  navRegistered = true;

  registerCommand(
    navCmd(
      "new-engagement",
      "New Engagement",
      () => {
        // Home lane owns the create affordance; navigate home, then ask it to
        // focus/open create.
        emit("openView", { view: "home" });
        emit("command:focus-create", {});
      },
      ["create", "engagement", "project", "new"],
    ),
  );

  registerCommand(
    navCmd(
      "open-workbench",
      "Open Workbench",
      () => emit("openView", { view: "build" }),
      ["tools", "playbooks", "build"],
    ),
  );
  registerCommand(
    navCmd("open-labs", "Open Labs", () => emit("openView", { view: "labs" }), ["lab", "docker", "vuln"]),
  );
  registerCommand(
    navCmd("open-findings", "Open Findings", () => emit("openView", { view: "findings" }), ["finding", "vuln", "tracker"]),
  );
  registerCommand(
    navCmd("open-settings", "Open Settings", () => emit("openView", { view: "settings" }), ["preferences", "config", "theme"]),
  );
  registerCommand(
    navCmd("open-reports", "Open Reporting", () => emit("openView", { view: "reports" }), ["report", "export"]),
  );
  registerCommand(
    navCmd("open-graph", "Open Asset Graph", () => emit("openView", { view: "graph" }), ["assets", "nodes", "map"]),
  );
  registerCommand(
    navCmd("open-learn", "Open Learn", () => emit("openView", { view: "learn" }), ["wstg", "ptes", "guide"]),
  );

  // Open Tool — focuses the palette's tool search. The palette listens for the
  // s-ide:palette window event and opens; the prefill is carried in detail.
  registerCommand({
    id: "open-tool",
    title: "Open Tool…",
    binding: bindingFor("open-tool"),
    context: "Go to",
    keywords: ["tool", "scan", "run", "arsenal"],
    run: () =>
      window.dispatchEvent(new CustomEvent("s-ide:palette", { detail: { mode: "tool" } })),
  });

  // Getting Started — the Home lane surfaces its onboarding panel.
  registerCommand({
    id: "show-onboarding",
    title: "Show Getting Started",
    context: "Help",
    keywords: ["onboarding", "help", "tutorial", "welcome", "getting started"],
    run: () => emit("command:show-onboarding", {}),
  });
}

// ── Global dispatcher ─────────────────────────────────────────────────────────

/**
 * Mount ONCE (App.tsx). Registers the shell nav commands, then listens for
 * keydown and runs the matched command via the registry. Unresolved ids are a
 * harmless no-op.
 */
export function useGlobalKeymap(): void {
  useEffect(() => {
    registerNavCommands();

    const onKey = (e: KeyboardEvent) => {
      // Don't steal plain typing inside inputs unless the chord uses a modifier.
      const entry = KEYMAP.find((k) => chordMatches(k.chord, e));
      if (!entry) return;
      const cmd = getCommand(entry.commandId);
      if (!cmd) return; // registered later by its owning lane — no-op for now
      e.preventDefault();
      markUsed(cmd.id);
      cmd.run();
    };

    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}
