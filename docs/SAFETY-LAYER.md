# s-ide — Safety layer + code review (spec, 2026-06-28)

> Extends existing seams (bus.ts · tools registry · engagement/lab spine · sessionLog · server-side `target_policy`). **Core principle:** the sealed sandbox is the default; anything reaching OUTSIDE the box (external targets/repos) is a deliberate, gated, attested, logged exception. The safe path is the default path.

## Provenance + modes
- Tag every target/repo: **lab** (inside the sealed box) · **owned** (a repo the authenticated GitHub user owns) · **external** (anything else).
- Static review by provenance: lab/owned → **exploit-grounded** (full analysis, exploitable paths, correlate with the dynamic evidence chain at `root_cause.anchor`); external → **defensive only** (weakness + risk + fix, CodeQL/Snyk-style). **Never emit turnkey exploit paths for external code.**
- Live/active tools fire only against **lab** targets OR targets with a **completed authorization attestation**. External static review allowed; external live probing is NOT auto-wired.

## Authorization attestation (gate for any non-lab active run)
- Stored scope record per engagement: `{ targets[], window, authority_note, attested_by, timestamp }`.
- **No attestation → active tools refuse (hard, server-side).** Surface status in the StatusBar.

## Static highlight confidence
- **confirmed** = static finding the dynamic chain actually reached (proven). **suspected** = static pattern match, no dynamic confirmation (candidate, flagged — not a verdict). Render distinctly; never assert `suspected` as fact. Headline the overlap where static + dynamic agree on the same anchor.

## Default-deny scope (keep)
- Preserve `backend/config.json` target_policy default-deny external + engagement scope. Reaching a new target is explicit + logged. Don't weaken it.

## Audit trail
- Append-only, content-hashed log of every active action: `{ action, target, provenance, params, attestation_id, timestamp, hash }`. Reuse the evidence ledger (`lib/audit_log.py`). Nothing active is anonymous.

## Responsible disclosure
- When external defensive review finds something real, route toward reporting to the maintainer: link the repo's SECURITY policy if present, offer a "report responsibly" path. Default toward disclosure, not use.

## Rate / aggression limits
- Cap active-scan intensity (esp. external) as a blast-radius backstop, independent of intent.

## GitHub auth
- OAuth is for FETCHING source only. Read access ≠ test authorization. Owning a repo enables **owned** mode for code review; it does NOT enable live probing of any deployment.

## Don't
- Don't weaken target_policy. Don't rename `X-MHP-*` headers. Don't emit exploit-grounded output for external code. Don't let active tools fire outside the box without a stored attestation.

## Acceptance
- Active tool vs non-lab target with NO attestation → refused.
- External repo review → defensive output only; no turnkey exploit path.
- A `suspected` finding is never rendered as `confirmed`/fact.
- Every active action appears in the append-only audit log with its attestation id.
- `npx tsc --noEmit` and `python3 -c "import main"` clean.

## Build order (staged)
1. **Provenance tagging + default-deny** — ✅ foundation agent: `lib/safety.py` provenance(lab/owned/external), keep target_policy.
2. **Attestation gate** — ✅ foundation agent: `attestations` table + `require_active_allowed` hard gate wired into active routers; `routers/safety.py`; StatusBar surface + AttestationModal.
3. **Audit log** — ✅ foundation agent: `audit_active` → reuse hash-chained `audit_log`.
4. **Two-mode static review + confidence** — 〔next〕 extend `codescan`: provenance-aware mode (lab/owned exploit-grounded vs external defensive-only); confidence confirmed (dynamic chain reached the anchor — correlate via `lib/method` steps) vs suspected (pattern only); render distinctly.
5. **Disclosure workflow** — 〔next〕 detect repo SECURITY policy, "report responsibly" path.
6. **Rate limits** — 〔next〕 cap active-scan intensity, esp. external.
