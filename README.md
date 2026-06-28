# s-ide

**A security-testing IDE.** Probe any app inside a sealed sandbox, then trace every flaw from *symptom → root cause → fix*.

> Working name. Built on [HackingPal](https://github.com/hackingpal)'s backend (vendored, decoupled).

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

## Architecture

Electron + React + TS + Vite + Tailwind + dockview frontend ↔ FastAPI + SQLite backend (vendored from HackingPal `60a38c4`). Loopback-only, token-auth; WebSocket for streaming tools, SSE for the copilot.

## Quick start

```bash
# terminal 1 — backend
cd backend && python3 -m uvicorn main:app --reload --port 8765

# terminal 2 — frontend
cd frontend && npm install && npm run dev:all
```

`RAMPART_EXPOSE_ALL=1` exposes the full gated toolset. Build the desktop app with `cd frontend && npm run dist:dir`.

## ⚠️ Authorized use only

s-ide runs active, intrusive tooling. Use it **only** against systems you own or have written permission to test. The sandbox, attestation gate, and audit trail are guardrails, not a license.
