// Vitest config — kept separate from `vite.config.ts` so the test-time
// environment (happy-dom for localStorage / fetch shims, setup file)
// doesn't load on every `vite build`. Tests are unit-level only at this
// seed stage: no React rendering, no Electron, no real backend HTTP.

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "happy-dom",
    globals: false,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    setupFiles: ["./src/test-setup.ts"],
    // Each test file gets a fresh module graph so `lib/mode.ts` and
    // `lib/engagement.ts` (which keep module-level mutable state) don't
    // leak between specs.
    isolate: true,
  },
});
