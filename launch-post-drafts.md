# Launch post drafts — s-ide

Repo: https://github.com/adamsjack711-ux/s-ide
Demo GIF: lives at the **top of the README** (docs/demo.gif) — it is the first
thing anyone sees on the repo page, so linking the repo makes the GIF lead.

> Posting checklist
> - [ ] GIF is visible above the fold on the repo page (done — hero image under the title)
> - [ ] Lead the post/first-comment with the repo link (→ GIF first), text after
> - [ ] Post from your own account during a weekday morning ET for HN visibility
> - [ ] Old working name ("hackingpal") appears nowhere — these drafts are clean

---

## Option A — Show HN (recommended primary)

**Submit as:** URL post. URL = `https://github.com/adamsjack711-ux/s-ide`
(the README's demo GIF is the first thing on that page, so the GIF leads.)

**Title** (pick one, ≤80 chars):
- `Show HN: s-ide – an IDE for security engagements, sealed-sandbox by default`
- `Show HN: s-ide – treat a security engagement like an IDE treats a codebase`

**First comment (post immediately after submitting):**

I've been building s-ide: a desktop IDE that treats a security engagement the
way a code IDE treats a project — a persistent thing you live inside, not a pile
of terminal scrollback and screenshots.

The demo GIF at the top of the README shows the core loop: open an engagement,
run a recon tool from the panel, watch a finding stream in, then open its
investigation and jump around with ⌘K.

A few decisions that make it different from "a GUI wrapper around some tools":

- **The engagement is the workspace.** Scope, targets, findings, evidence and
  coverage all live on one local SQLite spine. Every tool run auto-attaches to
  it. Close the app, come back a week later, the whole case is still there.

- **Findings carry their reasoning.** Each finding is an ordered chain of steps
  tagged **FACT** (the tool action + its captured, hash-chained evidence) or
  **INFERENCE** (your interpretation). The copilot can reconstruct methodology
  but is built to *never* emit a step it can't anchor to evidence — no invented
  "why".

- **Sealed by default.** Targets resolve to lab / owned / external; acting on a
  non-lab target without an authorization attestation returns 403 *server-side*,
  not just a hidden button. Scope is default-deny, intrusive tool groups
  (web-exploit, AD, raw-socket) ship off-until-enabled, and there's a
  hash-chained audit log plus a fail-closed isolation check before a lab arms.

- **Tools are panels, not pages.** ~38 tools share one descriptor-driven surface
  (a tool is literally one descriptor object); results stream live over
  WebSocket, side by side. ⌘K launches any tool, jumps to any finding, or
  switches engagements.

- **Themes are decentralized and TOFU-pinned.** A `.side` theme is a declarative
  JSON token map identified by its source URL and versioned by git tags —
  Go-modules style. No upload server, no name registry to typosquat. First fetch
  of `url@version` pins a content hash; any later change to that immutable
  version is refused as tampering. The validator rejects anything executable and
  enforces a WCAG contrast floor + keeps the five severity colors provably
  distinct so a theme can't silently destroy safety meaning.

Stack: Electron + React + TS + Vite + Tailwind + dockview on a FastAPI + SQLite
backend, loopback-only with per-launch token auth. Apache-2.0.

Honest status: it's early and single-developer. Right now there's a macOS
(Apple Silicon) DMG or run-from-source; Linux/Windows builds aren't packaged yet
(the backend already targets Linux, it's the Electron packaging that's pending).
It runs active/intrusive tooling, so it's for systems you own or are authorized
to test — the sandbox and audit trail are guardrails, not a license.

I'd love feedback on the engagement-as-project model and the FACT/INFERENCE
provenance idea specifically — does that separation match how you actually work
a finding, or is it overhead?

---

## Option B — r/netsec (Show-and-tell framing)

r/netsec is strict about self-promotion; lead with the engineering, not the
"check out my tool" energy. Consider posting in the monthly hiring/tooling
threads or as a link post to the repo with a substantive comment. Flair it as a
tool/project if the sub requires.

**Title:**
`s-ide: a local security-engagement IDE with a server-side attestation gate, hash-chained finding provenance, and TOFU-pinned theme distribution`

**Body:**

Sharing a project I've been building — s-ide, a desktop IDE for running security
engagements as persistent projects rather than ad-hoc terminal sessions. Repo
(demo GIF at the top): https://github.com/adamsjack711-ux/s-ide

I'll skip the tool list and focus on the parts I think are actually interesting
to this sub:

**Provenance-first findings.** A finding isn't a text blob; it's an ordered
chain of steps, each tagged FACT (tool action + captured evidence, hash-chained)
or INFERENCE (analyst interpretation). The methodology-reconstruction view keeps
those two layers visually separate and won't synthesize a rationale it can't
anchor to a real prior step. The goal is that a report's "why" is always
traceable to evidence, and an AI assist can't quietly launder a guess into a
fact.

**Sandbox posture enforced server-side.** Default-deny scope; targets carry
provenance (lab / owned / external). Acting on a non-lab target without an
authorization attestation is a 403 from the backend, not a greyed-out button —
the gate holds against a direct API call. Intrusive capability groups
(web-exploit, AD, raw-socket) are off-until-enabled, there's a hash-chained
audit log, and a fail-closed isolation self-check runs before a lab arms.

**Decentralized, tamper-evident theme distribution.** Probably the most unusual
bit. Themes (`.side`) are declarative token maps distributed Go-modules-style:
identified by source URL, versioned by immutable git tags, no central registry
(so nothing to typosquat). Integrity is trust-on-first-use — the first fetch of
`url@version` pins a content hash and any later drift for that version is
refused as tampering; fetched themes are cached by content hash so they survive
the source repo disappearing. The validator is declarative-only (rejects
anything that looks executable or like markup), enforces a WCAG contrast floor,
and requires the five severity colors stay pairwise-distinct (ΔE ≥ 15) so a
theme can't destroy the meaning findings/reports depend on.

Architecture: FastAPI + SQLite backend (loopback-only, per-launch token auth,
WebSocket for streaming tools, SSE for the copilot) with an Electron/React
frontend. ~38 tools behind a capability gate; 95 vendored routers stay dormant
unless explicitly exposed. Apache-2.0.

Caveats up front: early, solo, macOS-Silicon binary or run-from-source for now.
It drives active/intrusive tooling — authorized targets only.

Happy to go deeper on the audit-log chaining, the attestation flow, or the theme
TOFU model in the comments.

---

## Notes / talking points for the comment threads

- **"Why not just Burp/Metasploit/a notes app?"** — those are tools; s-ide is the
  project layer *over* tools. The differentiator is state (engagement spine) +
  provenance (FACT/INFERENCE) + enforced posture, not the scanners themselves.
- **"Is the AI making stuff up?"** — the design constraint is that it can't emit
  an unanchored step; interpretation is always labeled INFERENCE and separated
  from FACT. Lean into this — it's the honest answer and the interesting one.
- **"Audit log integrity?"** — hash-chained rows; be ready to describe the chain
  (prev_hash → row_hash) if asked.
- **Expect the "authorized use only" scrutiny** on r/netsec — meet it head-on;
  the sealed-by-default posture is the answer.
- **Don't overclaim** cross-platform. Be precise: macOS Silicon DMG or source
  today; Linux/Windows packaging pending.
