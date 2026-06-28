/**
 * Active Directory tools — thin UI wrappers over the vendored, engagement-scoped,
 * audit-logged backend AD routers. Tier 3 (impacket/ldap3 + AD connectivity +
 * credentials); the offensive ones are intrusive (authorization + scope + audit
 * enforced server-side). Credentials are passed straight through, never stored.
 */
import { authFetch } from "../../api";
import { fmt, type HttpDescriptor, type ResultRow, type WsDescriptor } from "./types";

/** Shared credential fields → a CredsModel object (dc_host required). */
const CRED_FIELDS = [
  { name: "dc_host", label: "DC host", type: "text" as const, placeholder: "dc01.corp.local", required: true },
  { name: "domain", label: "Domain", type: "text" as const, placeholder: "corp.local" },
  { name: "username", label: "Username", type: "text" as const, placeholder: "sAMAccountName" },
  { name: "password", label: "Password", type: "text" as const, placeholder: "(or leave blank)" },
];
const creds = (v: Record<string, string>) => ({
  dc_host: v.dc_host?.trim(),
  domain: v.domain?.trim() || "",
  username: v.username?.trim() || "",
  password: v.password ?? "",
});
const post = (path: string, body: unknown) =>
  authFetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json());

const sev = (s?: string): ResultRow["level"] => (s === "high" || s === "critical" ? "error" : "info");

const LDAP_ENUM: HttpDescriptor = {
  id: "ldap_enum",
  label: "LDAP Enumerator",
  group: "Active Directory",
  tier: 3,
  requires: "ldap3 + AD connectivity + credentials",
  blurb: "Enumerate users, groups, DCs, policy and GPOs over LDAP.",
  transport: "http",
  fields: CRED_FIELDS,
  columns: ["Item", "Detail"],
  run: (v) => post("/ldap/enum", { creds: creds(v), confirm: true }),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    for (const f of r?.findings || []) rows.push({ cols: [f.title, f.detail], level: sev(f.severity) });
    const cat = r?.categories || {};
    for (const u of cat.users || []) rows.push({ cols: ["user " + (u.sam || u.display || ""), u.display || ""] });
    for (const g of cat.groups || []) rows.push({ cols: ["group " + (g.sam || ""), g.description || ""] });
    for (const d of cat.dcs || []) rows.push({ cols: ["DC " + (d.sam || d.dns || ""), ((d.os || "") + " " + (d.os_version || "")).trim()] });
    return rows;
  },
  doneText: (r) => `${(r?.findings || []).length} findings`,
};

const SMB_ENUM: HttpDescriptor = {
  id: "smb_enum",
  label: "SMB Enumerator",
  group: "Active Directory",
  tier: 3,
  requires: "impacket + SMB host (+ optional credentials)",
  blurb: "Enumerate SMB shares, signing, and access over a target host.",
  transport: "http",
  fields: [...CRED_FIELDS, { name: "target", label: "Target (host)", type: "text" as const, placeholder: "(defaults to DC host)" }],
  columns: ["Item", "Detail"],
  run: (v) => post("/smb/enum", { creds: creds(v), target: v.target?.trim() || "", confirm: true }),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    for (const f of r?.findings || []) rows.push({ cols: [f.title, f.detail], level: sev(f.severity) });
    for (const s of r?.shares || []) rows.push({ cols: [`share ${s.name || s}`, typeof s === "object" ? (s.remark || s.access || "") : ""], level: "hit" });
    return rows;
  },
  doneText: (r) => `${(r?.shares || []).length} shares · ${(r?.findings || []).length} findings`,
};

const KERBEROAST: HttpDescriptor = {
  id: "kerberos_roast",
  label: "Kerberos Roasting",
  group: "Active Directory",
  tier: 3,
  intrusive: true,
  requires: "impacket + AD connectivity + credentials",
  blurb: "Request TGS tickets for SPN-bearing accounts (authorized engagements only).",
  transport: "http",
  fields: [...CRED_FIELDS, { name: "spn_filter", label: "SPN filter", type: "text" as const, placeholder: "* (all)" }],
  columns: ["Account", "Hash"],
  run: (v) => post("/kerberoast/run", { creds: creds(v), spn_filter: v.spn_filter?.trim() || "", confirm_auth: true, confirm: true }),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    for (const h of r?.hashes || []) {
      const account = typeof h === "object" ? (h.user || h.sam || h.account || "") : "";
      const hash = typeof h === "object" ? (h.hash || h.krb5tgs || "") : String(h);
      rows.push({ cols: [account, String(hash).slice(0, 80) + (String(hash).length > 80 ? "…" : "")], level: "hit" });
    }
    return rows;
  },
  doneText: (r) => `${(r?.hashes || []).length} roastable`,
};

const BLOODHOUND: HttpDescriptor = {
  id: "bloodhound_ingest",
  label: "BloodHound Ingestor",
  group: "Active Directory",
  tier: 3,
  requires: "bloodhound-python + AD connectivity + credentials",
  blurb: "Run BloodHound collection against the domain (produces JSON for analysis).",
  transport: "http",
  fields: [...CRED_FIELDS, { name: "methods", label: "Methods", type: "text" as const, default: "Default", placeholder: "Default,Group,Session" }],
  columns: ["Field", "Value"],
  run: (v) =>
    post("/bloodhound/run", {
      creds: creds(v),
      methods: (v.methods || "Default").split(",").map((m) => m.trim()).filter(Boolean),
    }),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    const push = (k: string, val?: unknown) => { if (val != null && val !== "") rows.push({ cols: [k, String(val)] }); };
    push("Job", r?.job_id || r?.jid); push("Files", r?.file_count); push("Message", r?.message);
    return rows;
  },
  doneText: (r) => r?.message || `${r?.file_count ?? 0} JSON files`,
};

const LATERAL: HttpDescriptor = {
  id: "lateral",
  label: "Lateral Movement",
  group: "Active Directory",
  tier: 3,
  intrusive: true,
  requires: "a loaded BloodHound graph (upload first)",
  blurb: "Find attack paths between principals in a loaded BloodHound graph.",
  transport: "http",
  fields: [
    { name: "source", label: "Source principal", type: "text" as const, placeholder: "USER@CORP.LOCAL", required: true },
    { name: "target", label: "Target", type: "text" as const, placeholder: "(blank = any Domain Admin)" },
    { name: "max_hops", label: "Max hops", type: "text" as const, default: "6" },
  ],
  columns: ["Hop", "Edge"],
  run: (v) =>
    post("/lateral/path", { source: v.source?.trim(), target: v.target?.trim() || "", max_hops: Number(v.max_hops || 6), confirm_auth: true }),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    const paths = r?.paths || [];
    paths.forEach((p: any, i: number) => {
      rows.push({ cols: [`path ${i + 1}`, ""], level: "hit" });
      for (const step of p?.steps || p || []) {
        const from = step.from || step[0] || "";
        const edge = step.edge || step.kind || step[1] || "→";
        rows.push({ cols: [String(from), String(edge)] });
      }
    });
    return rows;
  },
  doneText: (r) => `${(r?.paths || []).length} paths`,
};

const AD_SPRAY: WsDescriptor = {
  id: "ad_spray",
  label: "Password Sprayer",
  group: "Active Directory",
  tier: 3,
  intrusive: true,
  requires: "AD connectivity + a userlist (authorized engagements only)",
  blurb: "Low-and-slow password spray with lockout safety (authorization required).",
  transport: "ws",
  wsPath: "/ws/ad-spray",
  fields: [
    { name: "dc_host", label: "DC host", type: "text", placeholder: "dc01.corp.local", required: true },
    { name: "domain", label: "Domain", type: "text", placeholder: "corp.local" },
    { name: "users", label: "Users (comma/newline)", type: "text", placeholder: "alice, bob, carol", required: true },
    { name: "passwords", label: "Passwords (comma/newline)", type: "text", placeholder: "Spring2026!, Welcome1", required: true },
    { name: "delay_sec", label: "Delay (s)", type: "text", default: "0.5" },
    { name: "authorized", label: "I have authorization to spray this domain", type: "checkbox" },
  ],
  columns: ["User", "Result"],
  buildInit: (v) => ({
    creds: { dc_host: v.dc_host?.trim(), domain: v.domain?.trim() || "" },
    users: (v.users || "").split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
    passwords: (v.passwords || "").split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
    delay_sec: Number(v.delay_sec || 0.5),
    confirm_auth: v.authorized === "true",
  }),
  toRow: (ev) => {
    if (ev?.type !== "attempt") return null;
    const valid = ev.valid || ev.result === "valid" || ev.status === "valid" || ev.success;
    return valid ? { cols: [ev.user || "", `VALID${ev.password ? " · " + ev.password : ""}`], level: "hit" } : null;
  },
  toOutput: (ev) => {
    switch (ev?.type) {
      case "started": return { level: "info", text: `started — ${ev.total} attempts` };
      case "attempt": return { level: ev.valid || ev.success ? "hit" : "info", text: `${ev.user}: ${ev.valid || ev.success ? "VALID" : ev.result || ev.status || "no"}` };
      case "done": return { level: "done", text: `done${ev.stopped ? " (stopped)" : ""}` };
      case "error": return { level: "error", text: ev.detail || ev.error || "error" };
      default: return null;
    }
  },
  doneText: (ev) => (ev?.type === "done" ? `${fmt(ev.valid_count ?? 0)} valid` : ""),
};

export const AD_TOOLS = [LDAP_ENUM, SMB_ENUM, KERBEROAST, BLOODHOUND, LATERAL, AD_SPRAY];
