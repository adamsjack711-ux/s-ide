# s-ide — Tool Checklist

> **Re-scope (2026-06-28):** the product thesis moves from *"slim, zero-setup only"*
> to an **open security-testing sandbox** — "as open and secure as we can." This
> intentionally reverses the earlier locks (Tier-1-only gate, fuzzers deferred):
> we now expose the full tool arsenal, but each capability is made safe by
> the security model in §1 rather than by hiding it.
>
> Backend is already vendored (all 88 routers present); porting = (a) widening the
> capability gate, (b) writing a tool descriptor per tool, (c) the bigger pieces
> (playbooks, labs, self-assess, terminal). **Currently wired: 7** (ip, dns, whois,
> ping, ports, tls, http) + the engagement spine (findings/cvss/coverage/reports).

**Tier legend** — `T1` zero-setup · `T2` privilege/root/raw-socket · `T3` external setup (API key / Docker / AD creds / hardware).
**Exposure legend** — `default` on for everyone · `auth+scope` intrusive: authorization checkbox + engagement scope + audit · `enable+sudoers` per-tool one-click sudoers install + explicit enable + audit · `setup-detected` shows requirements, lights up when deps present (the Connect-AI pattern) · `lab-confined` runnable safely inside lab containers.

---

## ✅ BUILD STATUS (2026-06-28) — tool breadth DONE

**37 tool descriptors wired** (6 parallel agents + AD written inline; tsc clean, vite build green, smoke-tested live: JWT decode 200, Exploits search 200, /ws/xss registered). Registry refactored to `src/shell/tools/` (types · core · per-group files · index aggregator · capability). Capability model live: Tier-1 info-gathering on by default; **privileged / Tier-3 / intrusive groups OFF until enabled in Settings → Capabilities**.

- **Done:** Discovery (+local_discovery, lan_scan) · Recon (+fingerprint, nmap) · OSINT (ct, email_sec, takeover, reverse_ip, breach, dorking, github_leak) · Web Recon (subdom, cms, jwt, graphql) · Web Exploit (xss/sqli/cmdi/lfi/ssrf/idor) · Active Directory (ldap, smb, kerberoast, bloodhound, lateral, ad_spray) · Red Team (exploits, reverse_shell, c2_beacon) · capability manifest (`exposure.py` + frontend `capability.ts` + `CapabilitiesPanel`).
- **Still pending:** Support descriptors (audit_log + processes, mode-aware) · Labs/colima + lab↔engagement · Playbooks + editor · Self-Assess · Terminal (lab-PTY) · server-side capability enforcement (currently UI-gated; scope/auth/audit are the hard backend gates) · Payload Obfuscator (no backend — client-side port later). Packaged `.app` on Desktop is the OLD 7-tool build — rebuild to refresh.

---

## 0. Locked scope & decisions (2026-06-28)

- **Refined ~40 tools**, not all ~74 — *all basic red-team + select information-gathering*. The curated set is marked **【IN】** below; everything else is **〔later〕**.
- **Privileged/intrusive = off until enabled.** Present in the codebase, disabled by default, flipped on per-group in Settings → Capabilities (with requirement check + auth + audit). Maximally open *capability*, safe *default*.
- **Build order: capability model + labs FIRST** (Stage A), so privileged/intrusive tools have a safe home before they land.
- **Terminal = lab-container shell first** (sandboxed); raw host shell only later behind explicit enable + audit.

### The refined 40 (build target)

**Information gathering (22)** — Discovery: IP✅·DNS✅·WHOIS✅·Ping✅·Local Discovery·LAN Scan · Recon: Port Scanner✅·TLS✅·HTTP Probe✅·Fingerprint·Nmap · OSINT: CT Logs·Email Security·Takeover·Reverse IP·Breach·Google Dorking·GitHub Leak · Web Recon: Subdomain Enum·CMS/Stack·JWT·GraphQL
**Red team (16)** — Web Exploit: XSS·SQLi·CMDi·LFI·SSRF·IDOR · Active Directory: LDAP·SMB·Password Spray·Kerberoast·BloodHound·Lateral · Red Team core: Reverse Shell·Payload Obfuscator·Exploits/SearchSploit·C2 Beacon Sim
**Support (2, mode-aware)** — Audit Log · Processes
**+ Terminal** (lab-confined PTY, its own milestone) · **+ Playbooks/editor · Labs+colima · Self-Assess** (the named sub-projects)

*7 already wired → ~33 tool descriptors to build, plus the sandbox spine + sub-projects.*

### Build sequence
- **Stage A — Sandbox spine:** capability manifest (`exposure.py` rework) + Settings → Capabilities panel + Labs/colima + lab↔engagement attach + RuntimeBanner. *Privileged tools' safe home.*
- **Stage B — Information gathering (22):** fast T1 descriptors; Nmap = enable+sudoers.
- **Stage C — Red team (16):** web-exploit (shared `RequestForm`/`useAttackWS`), AD (setup-detected), red-team core — all off-until-enabled + auth+scope+audit.
- **Stage D — Support + sub-projects:** mode-aware Audit Log + Processes, Playbooks + editor, Self-Assess (web/app/system).
- **Stage E — Terminal:** lab-container PTY.

〔later〕 = deferred from the 40: most of OSINT's long tail (Wayback/URLScan/Shodan·Censys/People/Profiles/Email Harvest/Dork Gen), Cloud (AWS/Azure/GCP/IMDS/S3), Red Team's Pivot + Cred Harvest, Crypto Hash Cracker, all Monitoring(IDS/Systemd/Firewall)/Forensics(Persistence/Stego/Posture/Users)/Wireless, Network Audit, TCPDump, Brew, WiFi.

---

## 1. Security model — the "secure" half of the sandbox

The breadth is only acceptable if these stay load-bearing. Build/confirm these first:

- [ ] **Capability manifest** — rework `backend/lib/exposure.py` from binary Tier-1/all into a per-tool `{tier, intrusive, requirements, enabled}` registry. `main.py` registers Tier-1 by default; Tier-2/3 require explicit, persisted enablement (audited). One source of truth, surfaced in a Settings → Capabilities panel.
- [ ] **Scope enforcement stays the hard gate** — `target_policy` (default-deny external; loopback/private/Tailscale/lab allowed) + engagement scope. No tool bypasses it; intrusive tools additionally require the authorization checkbox. Keep `config.json` strict.
- [ ] **Lab vs Engagement mode** is the sandbox boundary — **lab mode** = practice against owned/lab targets, scope relaxed *within the lab network only*; **engagement mode** = scoped real targets, full audit. Mode is per-window (already built).
- [ ] **Audit everything privileged/intrusive** — the hash-chained `audit_log` already records argv/target/approver; ensure every newly-wired Tier-2/3/intrusive tool writes to it.
- [ ] **Setup transparency** — surface the `tool_requirements` registry (binaries / API keys / sudoers / docker) as a per-tool "what this needs" panel with install hints.

---

## 2. Priority port (your 8 categories)

### 1 — Discovery  (`lan`, `localdisco` to add; ip/dns/whois/ping ✅)
- [x] IP Checker (`ip_checker`) · T1 · default — **wired**
- [x] DNS Recon (`dns_recon`) · T1 · default — **wired**
- [x] WHOIS · ASN (`whois`) · T1 · default — **wired**
- [x] Ping (`ping`) · T1 · default — **wired**
- [ ] **Local Discovery** (`local_discovery`) · T1 · default — WS; local interfaces/routes/netstat
- [ ] **LAN Scan** (`lan_scan`) · T2 (ARP/raw socket) · enable+sudoers · WS streaming

### 2 — Recon  (`nmap`, `audit`, `fingerprint`, `tcpdump` to add; ports/tls/http ✅)
- [x] Port Scanner (`port_scanner`) · T1 connect / T2 SYN · default (SYN toggle = enable+sudoers) — **wired (connect)**
- [x] TLS Auditor (`tls_audit`) · T1 · default — **wired**
- [x] HTTP Probe (`http_probe`) · T1 · default — **wired**
- [ ] **Fingerprint** (`fingerprint`) · T1 · default — HTTP one-shot
- [ ] **Nmap** (`nmap`) · T2 (nmap binary + sudoers for SYN/OS/UDP) · enable+sudoers · WS, 612 NSE, server-side dry-run preview
- [ ] **Network Audit** (`audit`) · T2 · enable+sudoers · composite port/risk/fix table
- [ ] **TCPDump** (`tcpdump`) · T2 (libpcap + sudoers) · enable+sudoers · WS packet capture

### 3 — OSINT  (14 tools — mostly T1; a few key-gated)
- [ ] **CT Logs** (`ct_log`) · T1 · default
- [ ] **Email Security** (`email_security`) · T1 · default — SPF/DMARC/DKIM
- [ ] **Takeover** (`takeover`) · T1 · default — WS
- [ ] **Reverse IP** (`reverse_ip`) · T1 · default
- [ ] **Breach Lookup** (`breach`) · T1 (pwned k-anon) / T3 (HIBP email key) · default + setup-detected sub-feature
- [ ] **Google Dorking** (`dorking`) · T1 · default
- [ ] **Dork Generator** (`dorking` osint) · T1 · default
- [ ] **GitHub Leak** (`github_leak`) · T1 (unauth) / T3 (PAT) · default + setup-detected
- [ ] **Shodan · Censys** (`shodan_censys`) · T3 (keys) · setup-detected
- [ ] **People · Email Enum** (`people_enum`) · T3 (Hunter.io) / partial T1 · setup-detected
- [ ] **Profile Finder** (`profile_finder`) · T1 · default
- [ ] **Email Harvest** (`email_harvest`) · T1 / T3 (Hunter) · default
- [ ] **Wayback URLs** (`wayback`) · T1 · default
- [ ] **URLScan** (`urlscan`) · T1 (free) / T3 (key) · default

### 4 — Web Recon  (4 tools — all T1)
- [ ] **Subdomain Enum** (`subdomain_enum`) · T1 · auth+scope (active enum; has `confirm_auth`) · WS
- [ ] **CMS / Stack** (`cms`) · T1 · default
- [ ] **JWT** (`jwt_analyzer`) · T1 · default
- [ ] **GraphQL** (`graphql`) · T1 · default — introspection

### 5 — Web Exploit  (6 tools — T1 pure-python but INTRUSIVE; un-defer)
- [ ] **XSS** (`xss`) · T1 · auth+scope · WS (`useAttackWS` pattern)
- [ ] **SQL Injection** (`sqli`) · T1 · auth+scope · WS
- [ ] **Command Injection** (`cmdi`) · T1 · auth+scope · WS
- [ ] **LFI / Path Traversal** (`lfi`) · T1 · auth+scope · WS
- [ ] **SSRF** (`ssrf`) · T1 · auth+scope · WS
- [ ] **IDOR** (`idor`) · T1 · auth+scope · WS
> Port the shared `RequestForm` (FUZZ marker, auth checkbox, allow-private toggle, rate slider) + `AttackResults` + the `useAttackWS` hook — one descriptor variant covers all six.

### 6 — Active Directory  (6 tools — T3: impacket/ldap3 + AD connectivity + creds)
- [ ] **LDAP Enumerator** (`ldap_enum`) · T3 · setup-detected + auth+scope
- [ ] **SMB Enumerator** (`smb_enum`) · T3 · setup-detected + auth+scope
- [ ] **Password Sprayer** (`ad_spray`) · T3 · setup-detected + auth+scope (audited)
- [ ] **Kerberos Roasting** (`kerberos_roast`) · T3 · setup-detected + auth+scope · server-side dry-run preview
- [ ] **BloodHound Ingestor** (`bloodhound_ingest`) · T3 · setup-detected
- [ ] **Lateral Movement** (`lateral`) · T3 · setup-detected + auth+scope (already audits `/load` + `/path`)

### 7 — Monitoring / Forensics (mode-aware)  ← your "audit log + processes based on lab/engagement"
- [ ] **Audit Log** (`audit_log`) · T1 · default — read-only view of the hash-chained trail; **engagement mode** = full engagement timeline, **lab mode** = lab-run rows only
- [ ] **Processes** (`processes`) · T1 list / T2 kill · default (kill = enable) — **mode-aware**: engagement = local host audit; lab = scope to lab-container PIDs; killing gated + audited

### 8 — Terminal  (larger milestone — see §7)
- [ ] **Terminal** (`term`) · T2 · its own milestone — one-shot exec ships today; we want a real PTY. `@xterm/xterm` already a dep.

---

## 3. Remaining catalog (not in your 8 — flag include now vs later)

- [ ] **Cloud**: AWS / Azure / GCP Recon (`aws_recon`/`azure_recon`/`gcp_recon`, T3 creds) · IMDS Tester (`imds`, T1) · S3 Scanner (`s3_scanner`, T3)
- [ ] **Red Team**: Reverse Shell (`reverse_shell`, T2) · Payload Obfuscator (`obfuscator`, T1) · Pivoting (T2) · Credential Harvest (`cred_harvest`, T3) · C2 Beacon Sim (`c2_beacon`, T2/T3) · Exploits/SearchSploit (`exploits`, T1 offline)
- [ ] **Crypto**: Hash Cracker (`hash_cracker`, T1) · CVSS ✅ (in spine)
- [ ] **Monitoring (Linux)**: IDS (`ids`, T2) · Systemd Units (T2) · Firewall Rules (T2)
- [ ] **Forensics**: Persistence (`persistence`, T2) · Steganography (`stego`, T1) · macOS/Linux/Windows Posture (T1, used by Self-Assess) · Users Audit (T2)
- [ ] **Wireless**: WiFi Scan (`wifi_scan`, T2) · Evil Twin (`evil_twin`, T2) · Bluetooth (`bt_recon`, T2) · WPA/PMKID (`wpa_capture`, T3 hardware)
- [ ] **Utilities**: WiFi Integrity (`wifi`, T2) · Packages/Brew (`brew`, T2)

---

## 4. Playbooks + customization
- [ ] Port `presets` router + `lib/preset_engine.py` + built-in `.mhp` playbooks (`backend/presets/`)
- [ ] **Playbooks view** — list/run a playbook (chains tool steps against a target)
- [ ] **Playbook editor** — create/edit/save custom playbooks (the "customize" ask); persist per-engagement and/or global
- [ ] Wire playbook steps to the tool registry so "approve step" opens the right `ToolPanel` pre-filled (reuse the suggest-checks approve flow)

## 5. Labs (colima) + lab ↔ engagement
- [ ] Port `labs` router + `lib/labs.py` (DVWA / Juice Shop / Metasploitable / vulhub-net)
- [ ] **Runtime detection** — colima/Docker presence → `RuntimeBanner` (start/status); `setup-detected` with `brew install colima docker` hint
- [ ] **Lab ↔ engagement attach** (upstream `fbe64cc`) — attach a lab to an engagement, auto-register lab targets, scope-tag them `lab`
- [ ] Lab lifecycle UI (build/start/stop + live build log over WS) — the natural **sandbox**: intrusive tools run safely against lab containers

## 6. Self-Assess (web / application / system)  ← "better baked-in"
- [ ] Port `basic_check` + posture routers (`macos_posture`/`linux_posture`/`windows_posture`) + `users_audit`
- [ ] **System self-assess** — local host posture (firewall, hardening, sudoers, users, listening ports) → scored report
- [ ] **Web/app self-assess** — point at a URL → run the passive web-recon + (in lab/authorized) web-exploit suite as a guided sweep → scored report with promote-to-finding
- [ ] One-click "assess my machine" / "assess this app" entry that composes existing tools (a built-in playbook)

## 7. Terminal (PTY) — its own milestone
- [ ] Backend: real PTY over WebSocket (python `pty`/`ptyprocess` or `node-pty` in the Electron main) — replaces one-shot exec
- [ ] Frontend: `@xterm/xterm` + `@xterm/addon-fit` panel in the dockview work area
- [ ] **Security (the hard part — "open but secure")**: decide confinement — confined to a lab container shell by default? scoped + audited keystrokes in engagement mode? no raw host shell without explicit enable. This is where "open" most needs "secure" — design before building.

## 8. Engine work this requires
- [ ] `exposure.py` → capability manifest (§1) + Settings → Capabilities panel (enable/disable groups, see requirements)
- [ ] Tool-registry descriptors for every ported tool (most are 1 descriptor each; web-exploit + AD reuse shared variants)
- [ ] `RequestForm` / `useAttackWS` / `AttackResults` port for the intrusive WS tools
- [ ] `tool_requirements` panel + per-tool `setup-detected` states
- [ ] Mode-aware behavior for audit-log + processes (and scope relaxation inside labs)

---

## Open decisions (need your call before the big sweep)
1. **Privileged/intrusive default** — expose Tier-2/3 tools but **off until enabled** (recommended: maximally open *capability*, safe *default*), or on-by-default?
2. **Un-listed groups (Cloud / Red Team / Crypto / Wireless / Linux-only)** — sweep them in now too, or land your 8 + playbooks/labs/self-assess first?
3. **Terminal confinement** — lab-container shell only to start, or host shell behind explicit enable+audit?
4. **Order** — breadth-first (wire all the easy T1 descriptors fast), or capability-model + labs first so the privileged tools have their safe home before they land?
