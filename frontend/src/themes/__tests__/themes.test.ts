// Exercises the .side format end-to-end: every fixture through the real
// validator, then the 5 valid ones through the apply path (CSS-var injection in
// jsdom), checking semantic-token distinctness survives. Prints a pass/fail
// table. Does NOT weaken the validator or floors — a theme that can't keep
// semantic colors distinct is supposed to fail.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect } from "vitest";
import { validateSide, deltaE } from "../validate";
import { applySide, clearSide } from "../apply";
import { PROTECTED_TOKENS } from "../sideSchema";
import { setSideTheme, getSideTheme, clearSideTheme } from "../../lib/theme";
import { BUILTIN_THEMES } from "../builtins";

const VALID = ["midnight", "paper", "high-contrast", "solarized", "terminal-green"];
const INVALID = ["no-version", "executable", "ambiguous-semantics", "bad-type"];

const FIXTURES = resolve(process.cwd(), "src/themes/fixtures");
function load(name: string): unknown {
  return JSON.parse(readFileSync(resolve(FIXTURES, `${name}.side`), "utf8"));
}

type Row = { file: string; expect: string; got: string; reason: string };
const table: Row[] = [];

describe(".side theme batch", () => {
  it("validates 5 valid + rejects 4 invalid", () => {
    for (const name of VALID) {
      const res = validateSide(load(name));
      table.push({ file: `${name}.side`, expect: "valid", got: res.ok ? "valid" : "REJECTED", reason: res.errors[0] ?? "" });
      expect(res.ok, `${name} should be valid: ${res.errors.join("; ")}`).toBe(true);
    }
    for (const name of INVALID) {
      const res = validateSide(load(name));
      table.push({ file: `${name}.side`, expect: "reject", got: res.ok ? "PASSED(!)" : "rejected", reason: res.errors[0] ?? "" });
      expect(res.ok, `${name} should be rejected`).toBe(false);
      expect(res.errors.length).toBeGreaterThan(0);
    }
  });

  it("applies valid themes hot and keeps semantic tokens distinct", () => {
    for (const name of VALID) {
      clearSide();
      const theme = load(name) as any;
      const res = applySide(theme);
      expect(res.ok, `${name} apply: ${res.errors.join("; ")}`).toBe(true);

      // Hot apply took effect on <html>.
      const style = document.documentElement.style;
      expect(style.getPropertyValue("--bg-base").trim()).toBe(theme.theme["--bg-base"]);
      expect(style.getPropertyValue("--accent").trim()).toBe(theme.theme["--accent"]);
      // Tailwind rgb-triplet family derived.
      expect(style.getPropertyValue("--bg-base-rgb").trim()).toMatch(/^\d+ \d+ \d+$/);

      // Semantically-opposed tokens stay perceptually distinct after apply.
      const applied = PROTECTED_TOKENS.map((t) => style.getPropertyValue(t).trim());
      for (let i = 0; i < applied.length; i++) {
        for (let j = i + 1; j < applied.length; j++) {
          expect(
            deltaE(applied[i], applied[j]),
            `${name}: ${PROTECTED_TOKENS[i]} vs ${PROTECTED_TOKENS[j]} not distinct`,
          ).toBeGreaterThanOrEqual(15);
        }
      }
    }
  });

  it("persists a theme and restores it (reload simulation)", () => {
    const midnight = load("midnight") as any;
    const res = setSideTheme(midnight);
    expect(res.ok).toBe(true);
    expect(getSideTheme()?.name).toBe("Midnight");

    // Simulate a reload: wipe the inline vars, then re-apply from storage.
    clearSide();
    expect(document.documentElement.style.getPropertyValue("--accent").trim()).toBe("");
    const restored = getSideTheme();
    expect(restored).not.toBeNull();
    applySide(restored!);
    expect(document.documentElement.style.getPropertyValue("--accent").trim()).toBe(midnight.theme["--accent"]);

    clearSideTheme();
    expect(getSideTheme()).toBeNull();
  });

  it("every bundled gallery theme passes the validator", () => {
    for (const t of BUILTIN_THEMES) {
      const res = validateSide(t);
      expect(res.ok, `${t.name} invalid: ${res.errors.join("; ")}`).toBe(true);
    }
    expect(BUILTIN_THEMES.length).toBe(6);
  });

  it("prints the pass/fail table", () => {
    const head = "FILE".padEnd(26) + "EXPECT".padEnd(9) + "RESULT".padEnd(11) + "REASON";
    const lines = table.map(
      (r) => r.file.padEnd(26) + r.expect.padEnd(9) + r.got.padEnd(11) + (r.reason ? r.reason.slice(0, 60) : ""),
    );
    // eslint-disable-next-line no-console
    console.log("\n.side theme batch\n" + head + "\n" + "-".repeat(78) + "\n" + lines.join("\n") + "\n");
    expect(table.length).toBe(9);
  });
});
