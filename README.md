# s-ide

**A security-testing IDE.** Probe any app inside a sealed sandbox, then trace every flaw from *symptom → root cause → fix*.

### ⬇️ Download

**[macOS (Apple Silicon) — s-ide-0.1.0-arm64.dmg](https://github.com/adamsjack711-ux/s-ide/releases/latest)**

Unsigned build — on first launch, right-click the app → **Open** (or `xattr -dr com.apple.quarantine /Applications/s-ide.app`). The backend sidecar is bundled; no Python setup needed.

## The idea

A security engagement, treated the way an IDE treats a codebase — a persistent project you live inside.

- **The engagement is the workspace** — scope, targets, findings, evidence, and coverage on one SQLite spine.
- **Tools are panels, not pages** — ~38 tools share one descriptor-driven surface; results stream live, side by side.
- **⌘K command palette** launches any tool, jumps to any finding, switches engagements.
- **Ambient AI copilot** reads the focused result, reconstructs methodology, and suggests next checks — never fabricating a step it can't anchor to evidence.
- **Findings carry their reasoning** — ordered steps tagged **FACT** (action + evidence) or **INFERENCE** (interpretation).
- **Fix, then re-test** — anchor a finding to its root cause, edit lab source in-place (Monaco), replay the steps to confirm.

## Sealed by default

The default posture is a sealed sandbox; reaching outside it is a deliberate, attested, logged exception.

- **Provenance** — targets resolve to `lab` / `owned` / `external`; only external is walled off.
- **Attestation hard-gate** — acting on a non-lab target without attestation returns **403** server-side.
- **Capability manifest** — intrusive groups (web-exploit, AD, raw-socket scans) ship off-until-enabled.
- **Scope** default-deny + **hash-chained audit log** + **fail-closed isolation check** before a lab arms.

## Arsenal

~38 tools across eight groups (data-driven registry — a tool is one descriptor):

| Group | Tools |
|---|---|
| Discovery | IP, DNS, WHOIS, ping, local/LAN discovery |
| Recon | port scan, TLS, HTTP probe, fingerprint, nmap |
| OSINT | CT logs, email security, takeover, reverse IP, breach, dorking, GitHub leak |
| Web Recon | subdomain enum, CMS, JWT, GraphQL |
| Web Exploit *(gated)* | XSS, SQLi, cmdi, LFI, SSRF, IDOR |
| Active Directory *(gated)* | LDAP, SMB, spray, Kerberoast, BloodHound, lateral |
| Red Team *(gated)* | reverse shell, exploit search, C2 beacon |
| Code | static codebase scan |

Plus: engagement spine (findings / CVSS / coverage / reports), asset graph, Docker/colima labs, a WSTG+PTES learning surface, and 95 vendored routers dormant behind the gate.

## Creating themes (`.side`)

s-ide themes are plain, declarative `.side` files (JSON) — a design-token → value map, no code. Distribution is **decentralized** (Go-modules / SwiftPM style): a theme is identified by its **source URL**, versioned by **git tags**, immutable per version, and verified on fetch. There is no upload server and no name registry, so there is nothing to typosquat.

### The file

```jsonc
{
  "version": "1.0",            // required — a theme that omits it is rejected
  "kind": "theme",
  "name": "Midnight",
  "author": "you",
  "theme": {
    "--bg-base": "#0d1117",
    "--bg-surface": "#161b22",
    "--bg-elevated": "#1c2330",
    "--bg-hover": "#232c3a",
    "--bg-active": "#2b3647",
    "--text-primary": "#e6edf3",
    "--text-secondary": "#aeb9c6",
    "--text-muted": "#8b949e",
    "--border": "#2a3340",
    "--border-bright": "#3a4658",
    "--accent": "#58a6ff",
    "--critical": "#f85149",   // protected semantic tokens (see below)
    "--high": "#ff9e40",
    "--medium": "#e3b341",
    "--low": "#6cb6ff",
    "--success": "#3fb950",
    "--font-sans": "Inter",    // optional
    "--font-mono": "JetBrains Mono"
  }
}
```

Token keys are the app's **real CSS variables** — use those names exactly. The `*-rgb` triplets every Tailwind class needs are **derived for you**, so only set the hex values shown.

- **Required:** all of `--bg-*` (base/surface/elevated/hover/active), `--text-primary/-secondary/-muted`, `--border`, `--border-bright`, `--accent`.
- **Protected semantic tokens** (also required): `--critical --high --medium --low --success`. These carry meaning across findings, the graph and reports, so the validator enforces they stay readable **and** mutually distinct.
- **Optional** (derived from the above if omitted): `--accent-bright/-dim/-glow`, `--text-accent`, `--border-accent`, the per-severity `*-dim` variants, `--scrollbar-track/-thumb/-thumb-hover`, `--font-sans`, `--font-mono`.
- Light vs dark is inferred from `--bg-base` luminance — no flag needed.

### Rules the validator enforces (at fetch *and* every apply)

- **Declarative only.** Values must be hex colors (`#rrggbb` / `#rrggbbaa`) or, for fonts, plain strings. Anything that looks executable or like markup (`<…>`, `url(…)`, `javascript:`, `script`, `@import`, …) is rejected — nothing in a theme can run.
- **Unknown token keys are ignored** (forward-compat); unknown *top-level* keys are rejected.
- **Contrast floor (WCAG):** primary text ≥ 4.5:1 on backgrounds; secondary text, each severity, and the accent ≥ 3:1.
- **Severity distinctness:** the five protected colors must be pairwise distinct (ΔE ≥ 15). A theme that can't keep `critical`/`high`/`medium`/`low`/`success` apart is rejected — it can't silently destroy safety meaning.

A theme that fails any check is never applied; the app stays on the current theme.

### Publishing one

1. Put your `theme.side` in a git repo (any host).
2. Tag a semver release: `git tag 1.0.0 && git push --tags`. **A published version is immutable** — to change a theme, cut a new tag.
3. Share the repo URL. That URL *is* the theme's identity.

### Installing one

**Settings → Appearance → Custom themes → Add source** (paste the repo or raw `.side` URL, optionally pin a version) → **Preview**. The preview shows the source URL, resolved version, content hash, an **official/community** badge (official = lives under the project's own org, judged by URL only — never by anything inside the file), and a per-token diff. It applies **only on explicit confirm**.

Integrity is Go-style trust-on-first-use: the first fetch of `url@version` pins its hash; any later fetch whose content changed for that immutable version is **refused as tampering**. Fetched themes are cached immutably by content hash, so a theme keeps working even if its source repo later disappears.

## Architecture

Electron + React + TS + Vite + Tailwind + dockview frontend ↔ FastAPI + SQLite backend. Loopback-only, token-auth; WebSocket for streaming tools, SSE for the copilot. Theme distribution lives in `backend/routers/themes.py` (resolve / cache / TOFU-lock) with the format + validator in `frontend/src/themes/` (mirrored in `backend/lib/theme_*`).

## Quick start

```bash
# terminal 1 — backend
cd backend && python3 -m uvicorn main:app --reload --port 8765

# terminal 2 — frontend
cd frontend && npm install && npm run dev:all
```

`RAMPART_EXPOSE_ALL=1` exposes the full gated toolset. Build the desktop app locally with `cd frontend && npm run dist:mac`.

## Releasing

The macOS DMG on the [Releases page](https://github.com/adamsjack711-ux/s-ide/releases/latest) is rebuilt by CI on every version tag. To ship a big update:

```bash
npm --prefix frontend version minor          # bump 0.1.0 → 0.2.0 (or major / patch)
git commit -am "Release v0.2.0"
git tag v0.2.0 && git push --follow-tags     # tag push → GitHub Actions builds + attaches the DMG
```

## ⚠️ Authorized use only

s-ide runs active, intrusive tooling. Use it **only** against systems you own or have written permission to test. The sandbox, attestation gate, and audit trail are guardrails, not a license.

## License

Apache-2.0 — see [LICENSE](LICENSE).
