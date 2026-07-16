# s-ide — threat model (the tool itself)

`docs/SAFETY-LAYER.md` covers how s-ide keeps an *engagement* in-scope (provenance,
the attestation gate, scope enforcement). This document is the complement: the
threat model of **the application as a piece of software** — a privileged local
Electron app that spawns a Python sidecar, runs network tooling, and stores
engagement data, findings, and authorization attestations.

It exists because the app runs with real local privilege against real targets, so
a defect in *s-ide* — not in a target — is itself a security event. The CSP gate
fixed in the shell-foundation-lane review (a packaged build could ship
`script-src 'unsafe-inline'` if launched with `NODE_ENV=development`) is the kind
of bug this model is meant to catch early.

## Assets

| Asset | Why it matters |
|---|---|
| Engagement data (targets, findings, evidence, run output) | Client-confidential; often contains secrets captured from targets. |
| Authorization attestations | The record that a target was in-scope and permission existed. Forgery/loss is a legal-exposure event. |
| Credentials in flight | Tool output and evidence routinely contain tokens/cookies/keys (why redaction is a T5 invariant). |
| Local privilege | The sidecar spawns tools; the HackingPal lineage drops `sudoers.d` entries for tcpdump/nmap. |
| The renderer origin | An Electron renderer with a weak CSP + node integration is an RCE surface. |

## Trust boundaries

```
 ┌─ Electron main (Node, full local privilege) ─────────────────┐
 │  · spawns the Python sidecar        · installs the CSP        │
 │  · owns auto-update                 · gates external navigation│
 └───────────────┬───────────────────────────────┬──────────────┘
                 │ IPC / loopback HTTP+WS          │ spawn
   ┌─────────────▼──────────────┐    ┌─────────────▼─────────────┐
   │ Renderer (React, untrusted │    │ Python sidecar (FastAPI)  │
   │ content may reach it via   │    │  · capability gate        │
   │ tool output / evidence)    │    │  · scope + attestation    │
   └────────────────────────────┘    └─────────────┬─────────────┘
                                                    │ runs
                                       ┌────────────▼────────────┐
                                       │ external tools / targets │
                                       └──────────────────────────┘
```

The load-bearing boundaries: (1) **main ↔ renderer** — the renderer must be
treated as potentially hostile because target-controlled strings (HTTP responses,
scan output, evidence) flow into it; (2) **sidecar ↔ target** — the scope +
attestation gate; (3) **app ↔ OS** — the sidecar's privileged tool installers.

## Adversaries & the attacks that matter

- **A malicious target.** Serves crafted responses hoping to (a) inject script
  into the renderer via un-escaped output, (b) exfiltrate a secret by getting it
  rendered somewhere unredacted, or (c) fabricate a source location the editor
  opens (the `host:port`-as-`file:line` bug — fixed). *Mitigations:* strict prod
  CSP, one shared `lib/redact` on every rendered path, anchor resolvers that
  return null rather than fabricate.
- **A confused-deputy preset.** A preset or adapter runs a tool outside the
  attested scope. *Mitigations:* the run-level mode/engagement/scope gate; the
  `SUBTARGET_UNARMED` 403; attestation required before a run. **Gap:** these are
  exercised on the happy path only — see the roadmap's adversarial-gate item.
- **Supply chain.** The renderer bundles npm deps; the sidecar bundles pip deps
  and (via PyInstaller) ships them. *Mitigation today:* none specific to s-ide.
  *Roadmap:* lockfile audit in CI (pkgxray is already in this author's toolbelt).
- **A stray dev signal in a shipped build.** `NODE_ENV`, debug flags, or an
  exposed Tier-2/3 router (`RAMPART_EXPOSE_ALL`) leaking into a packaged app.
  *Mitigation:* gate security-sensitive relaxations on `app.isPackaged`, never an
  inheritable env var (fixed for CSP; audit the rest — see roadmap).

## Invariants (must always hold)

1. **A packaged build never relaxes its own CSP / navigation / node-integration
   posture based on an env var.** Gate on `app.isPackaged`.
2. **Nothing target-controlled is rendered without passing `lib/redact`.** One
   shared redactor, enforced by its test.
3. **No run executes outside an attested, in-scope engagement.** Enforced at the
   run edge, not per-step (the per-step re-check is redundant, not primary).
4. **The renderer cannot be navigated to a remote origin or execute inline
   script in production.** `will-navigate` bounces external origins; prod CSP is
   `script-src 'self'`.
5. **Secrets never persist in engagement storage unredacted**, and attestations
   are append-only / tamper-evident.

Invariants 1–2 now have tests (the CSP gate and `lib/redact.test.ts`). Invariants
3–5 are the roadmap's next test targets.

## Out of scope (for now)

Windows packaging; a hardened auto-update signing chain; multi-user/shared-host
deployment (s-ide assumes a single local operator). These are noted so their
absence is a recorded decision, not an oversight.
