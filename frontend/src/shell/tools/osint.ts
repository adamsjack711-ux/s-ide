/**
 * OSINT tools — passive reconnaissance group. Certificate Transparency, email
 * auth posture, subdomain takeover, reverse-IP, breach data, dork generation,
 * and GitHub leak search. All Tier-1 (zero-setup), modelled on the HTTP
 * templates in `core.ts` (WHOIS / TLS_AUDIT).
 *
 * Where `api.ts` already has a typed client fn we use it; otherwise we hit the
 * REST path directly via `authFetch`. Several client fns can return a
 * `{ needConfirm }` shape (scope gating) — we pass confirm=true and surface the
 * reason as a row if the backend still asks.
 */
import { authFetch, fetchCtSearch, fetchEmailAudit, fetchTakeoverCheck, fetchReverseIp } from "../../api";
import { fmt, type HttpDescriptor, type ResultRow, type ToolDescriptor } from "./types";

/** True when a client fn returned the scope-gate `{ needConfirm }` sentinel. */
function isNeedConfirm(r: any): r is { needConfirm: true; reason: string } {
  return r != null && r.needConfirm === true;
}

const CT_LOG: HttpDescriptor = {
  id: "ct_log",
  label: "CT Log Search",
  group: "OSINT",
  blurb: "Certificate Transparency (crt.sh) — subdomains + recent issuance.",
  tier: 1,
  transport: "http",
  fields: [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true }],
  columns: ["Field", "Value"],
  run: (v) => fetchCtSearch(v.domain.trim().toLowerCase(), true),
  toRows: (r) => {
    if (isNeedConfirm(r)) return [{ cols: ["Needs confirmation", r.reason], level: "error" }];
    const rows: ResultRow[] = [];
    rows.push({ cols: ["Total records", String(r.total_records ?? 0)] });
    rows.push({ cols: ["Recent (7d)", String(r.recent_7d_count ?? 0)] });
    for (const s of r.subdomains || []) rows.push({ cols: ["Subdomain", s], level: "hit" });
    for (const w of r.wildcard_subdomains || []) rows.push({ cols: ["Wildcard", w], level: "hit" });
    for (const c of r.recent_certs || []) rows.push({ cols: ["Recent cert", `${c.name} · ${c.issuer} · ${c.not_after}`] });
    for (const f of r.findings || []) rows.push({ cols: [f.label, f.detail], level: f.severity === "high" ? "error" : "info" });
    return rows;
  },
  doneText: (r) => (isNeedConfirm(r) ? "needs confirmation" : `${(r.subdomains || []).length} subdomains · ${fmt(r.elapsed_seconds)}s`),
};

const EMAIL_SECURITY: HttpDescriptor = {
  id: "email_security",
  label: "Email Security",
  group: "OSINT",
  blurb: "SPF / DMARC / DKIM / MTA-STS / BIMI posture audit.",
  tier: 1,
  transport: "http",
  fields: [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true }],
  columns: ["Field", "Value"],
  run: (v) => fetchEmailAudit(v.domain.trim().toLowerCase(), true),
  toRows: (r) => {
    if (isNeedConfirm(r)) return [{ cols: ["Needs confirmation", r.reason], level: "error" }];
    const rows: ResultRow[] = [];
    rows.push({ cols: ["SPF", r.spf?.present ? r.spf.all_qualifier || "present" : "missing"], level: r.spf?.present ? "info" : "error" });
    rows.push({ cols: ["DMARC", r.dmarc?.present ? r.dmarc.tags?.p || "present" : "missing"], level: r.dmarc?.present ? "info" : "error" });
    rows.push({ cols: ["DKIM selectors", (r.dkim?.selectors_found || []).join(", ") || "none"] });
    rows.push({ cols: ["MTA-STS", r.mta_sts?.present ? "present" : "missing"] });
    rows.push({ cols: ["BIMI", r.bimi?.present ? "present" : "missing"] });
    for (const f of r.findings || []) rows.push({ cols: [f.label, f.detail], level: f.severity === "high" ? "error" : "info" });
    return rows;
  },
  toOutputs: (r) => (isNeedConfirm(r) ? [] : (r.findings || []).map((f: any) => ({ level: f.severity === "high" ? "error" : "info", text: `${f.label}: ${f.detail}` }))),
  doneText: (r) => (isNeedConfirm(r) ? "needs confirmation" : r.policy?.verdict || "done"),
};

const TAKEOVER: HttpDescriptor = {
  id: "takeover",
  label: "Subdomain Takeover",
  group: "OSINT",
  blurb: "CNAME dangling / takeover signature check for an FQDN.",
  tier: 1,
  transport: "http",
  fields: [{ name: "fqdn", label: "FQDN", type: "text", placeholder: "blog.example.com", required: true }],
  columns: ["Field", "Value"],
  run: (v) => fetchTakeoverCheck(v.fqdn.trim().toLowerCase(), true),
  toRows: (r) => {
    if (isNeedConfirm(r)) return [{ cols: ["Needs confirmation", r.reason], level: "error" }];
    const vulnerable = r.verdict === "vulnerable" || r.verdict === "dangling";
    const rows: ResultRow[] = [];
    rows.push({ cols: ["Verdict", r.verdict], level: vulnerable ? "error" : "info" });
    rows.push({ cols: ["CNAME chain", (r.cname_chain || []).join(" → ") || "(none)"] });
    if (r.service) rows.push({ cols: ["Service", r.service] });
    rows.push({ cols: ["Signature matched", String(r.signature_matched)] });
    if (r.evidence) rows.push({ cols: ["Evidence", r.evidence], level: vulnerable ? "error" : "info" });
    return rows;
  },
  doneText: (r) => (isNeedConfirm(r) ? "needs confirmation" : `verdict: ${r.verdict}`),
};

const REVERSE_IP: HttpDescriptor = {
  id: "reverse_ip",
  label: "Reverse IP",
  group: "OSINT",
  blurb: "Domains co-hosted on a shared IP address.",
  tier: 1,
  transport: "http",
  fields: [{ name: "target", label: "IP", type: "text", placeholder: "1.2.3.4", required: true }],
  columns: ["Domain"],
  run: (v) => fetchReverseIp(v.target.trim(), true),
  toRows: (r) => {
    if (isNeedConfirm(r)) return [{ cols: [`Needs confirmation: ${r.reason}`], level: "error" }];
    const rows: ResultRow[] = (r.domains || []).map((d: string) => ({ cols: [d], level: "hit" as const }));
    if (r.rate_limited) rows.push({ cols: ["(rate-limited — partial results)"], level: "error" });
    return rows;
  },
  doneText: (r) => (isNeedConfirm(r) ? "needs confirmation" : `${r.count ?? (r.domains || []).length} domains · ${fmt(r.elapsed_seconds)}s`),
};

const BREACH: HttpDescriptor = {
  id: "breach",
  label: "Breach Lookup",
  group: "OSINT",
  blurb: "HIBP domain-wide breach roll-up (counts, data classes, timeline).",
  tier: 1,
  // Paid HIBP key needed for the domain endpoint (and the email variant); the
  // free k-anonymity password check is a separate endpoint not wired here.
  requires: "HIBP API key (paid) in Keychain via POST /settings/keys/hibp_api_key",
  transport: "http",
  fields: [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true }],
  columns: ["Breach", "Detail"],
  // No typed client fn — hit /breach/domain/{domain} directly.
  run: (v) => authFetch(`/breach/domain/${encodeURIComponent(v.domain.trim().toLowerCase())}`).then((r) => r.json()),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    rows.push({ cols: ["Total breaches", String(r.count ?? (r.breaches || []).length)] });
    for (const b of r.breaches || []) {
      // HIBP breach objects: Name/Title, BreachDate, PwnCount, DataClasses[].
      const name = b.Title || b.Name || "(breach)";
      const date = b.BreachDate || "";
      const pwn = b.PwnCount != null ? `${b.PwnCount} accounts` : "";
      const classes = Array.isArray(b.DataClasses) ? b.DataClasses.join(", ") : "";
      const detail = [date, pwn, classes].filter(Boolean).join(" · ");
      rows.push({ cols: [name, detail], level: "hit" });
    }
    return rows;
  },
  doneText: (r) => `${r.count ?? (r.breaches || []).length} breaches`,
};

const DORKING: HttpDescriptor = {
  id: "dorking",
  label: "Dork Generator",
  group: "OSINT",
  blurb: "Google dork queries for a target, by category (manual; no key needed).",
  tier: 1,
  transport: "http",
  fields: [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true },
    {
      name: "category", label: "Category", type: "select", default: "all",
      options: [
        { value: "all", label: "All" },
        { value: "files", label: "Files" },
        { value: "admin", label: "Admin panels" },
        { value: "leaks", label: "Leaks / secrets" },
        { value: "errors", label: "Errors" },
        { value: "configs", label: "Configs" },
        { value: "discovery", label: "Discovery" },
        { value: "archives", label: "Archives" },
      ],
    },
  ],
  columns: ["Category", "Dork", "URL"],
  // POST /dorking/generate — categories defaults to all when omitted; execute=false
  // returns dork strings only (passive, no upstream calls).
  run: (v) => {
    const cat = (v.category || "all").trim();
    const body: Record<string, unknown> = { target: v.domain.trim().toLowerCase(), execute: false };
    if (cat && cat !== "all") body.categories = [cat];
    return authFetch("/dorking/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => r.json());
  },
  toRows: (r) => (r.dorks || []).map((d: any) => ({ cols: [d.category || "", d.query || "", d.url || ""] })),
  doneText: (r) => `${(r.dorks || []).length} dorks`,
};

const GITHUB_LEAK: HttpDescriptor = {
  id: "github_leak",
  label: "GitHub Leak Search",
  group: "OSINT",
  blurb: "Search public GitHub code for credentials referencing a target.",
  tier: 1,
  // Works unauthenticated (10 req/min); a github_token in Keychain raises limits to 30/min.
  requires: "Optional: github_token in Keychain raises the rate limit (unauth works)",
  transport: "http",
  fields: [{ name: "query", label: "Target / org", type: "text", placeholder: "example.com", required: true }],
  columns: ["Repo", "Path", "Snippet"],
  // POST /github-leak/search — target + auto-generated leak patterns; results are
  // grouped per query, each with items[].
  run: (v) =>
    authFetch("/github-leak/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: v.query.trim() }),
    }).then((r) => r.json()),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    for (const res of r.results || []) {
      if (res.error) { rows.push({ cols: [res.label || "", res.error, ""], level: "error" }); continue; }
      for (const it of res.items || []) {
        const repo = it.repository?.full_name || "";
        const snippet = (it.snippets || [])[0] || "";
        rows.push({ cols: [repo, it.path || it.name || "", snippet], level: "hit" });
      }
    }
    return rows;
  },
  doneText: (r) => {
    const hits = (r.results || []).reduce((n: number, res: any) => n + (res.items || []).length, 0);
    return `${hits} hits${r.authenticated ? "" : " (unauth)"}`;
  },
};

export const OSINT_TOOLS: ToolDescriptor[] = [
  CT_LOG, EMAIL_SECURITY, TAKEOVER, REVERSE_IP, BREACH, DORKING, GITHUB_LEAK,
];
