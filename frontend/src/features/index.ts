/**
 * Feature manifest (Foundation lane) — the single import surface that stitches
 * the contributed feature panels into the shell's registries.
 *
 * Each feature is a SELF-CONTAINED module that, at import time, registers its
 * own view(s) and command(s) (shell/views.ts + shell/commands.ts), reads shared
 * state through the model API (shell/model.ts), and cross-links purely by
 * publishing/subscribing selection events on the bus (shell/bus.ts + refs.ts).
 * No feature imports or is imported by another feature or an existing panel.
 *
 * views.builtin.tsx imports THIS file once; after that, adding a feature is one
 * new self-contained module plus one import line below — no existing panel, no
 * central switch, and no shared wiring file other than this manifest is edited.
 * (This mirrors shell/tools/index.ts for tools and shell/views.builtin.tsx for
 * the stock views.)
 */

// (echo/EchoPanel is the Phase-0 decoupling ACCEPTANCE fixture — a throwaway
// panel that proved a brand-new module can react to `selectFinding` with no edit
// to any existing panel. It registered a real ⌘K command ("Open Selection Echo
// panel"), so it's imported only by its test now, not shipped in the palette.)

// ── Phase-1 features (F1–F9) ─────────────────────────────────────────────────
// Each import below is one self-registering feature module, uncommented as its
// module lands. Keeping the intended list here documents the registration
// order; an import is only active once the module exists (else tsc fails).
import "./search/SearchPanel";        // F1 — engagement-wide search
import "./problems/ProblemsPanel";    // F2 — findings-as-problems
import "./scandiff/ScanDiffPanel";    // F4 — scan-over-scan diff
import "./fixdiff/FixDiffPanel";       // F5 — before/after fix diff
import "./timeline/TimelinePanel";    // F6 — engagement timeline
import "./suggestions/Suggestions";   // F7 — inline suggestions
import "./templates/TemplatesPanel";  // F8 — templates
import "./debugger/EvidenceDebuggerPanel"; // F9 — steppable evidence chain
import "./pivot/Pivot";                // F3 — pivot navigation (LAST)
