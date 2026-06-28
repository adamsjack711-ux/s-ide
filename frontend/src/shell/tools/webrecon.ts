/**
 * Web Recon tools — application-layer fingerprinting + introspection.
 *
 * Contracts harvested from the vendored backend:
 *   - subdomain_enum  WS  /ws/subdom-enum   (routers/subdomain_enum.py)
 *   - cms             GET /cms/fingerprint  (routers/cms.py)
 *   - jwt             POST /jwt/decode      (routers/jwt_analyzer.py)
 *   - graphql         GET /graphql/introspect (routers/graphql.py)
 *
 * HTTP tools call authFetch directly with confirm=true so the server-side
 * scope `warn` verdict doesn't block a one-shot recon call.
 */
import { authFetch } from "../../api";
import { fmt, type HttpDescriptor, type ResultRow, type ToolDescriptor, type WsDescriptor } from "./types";

const SUBDOMAIN_ENUM: WsDescriptor = {
  id: "subdomain_enum",
  label: "Subdomain Enum",
  group: "Web Recon",
  blurb: "Active subdomain enumeration across passive sources + DNS permutations.",
  tier: 1,
  intrusive: true,
  transport: "ws",
  wsPath: "/ws/subdom-enum",
  fields: [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true },
    {
      name: "sources", label: "Sources", type: "select", default: "all",
      options: [
        { value: "all", label: "All free sources" },
        { value: "crt.sh", label: "crt.sh only" },
        { value: "hackertarget", label: "HackerTarget only" },
        { value: "otx", label: "AlienVault OTX only" },
        { value: "rapiddns", label: "RapidDNS only" },
      ],
    },
    { name: "resolve", label: "Resolve to IP", type: "checkbox", default: "true" },
    { name: "permutations", label: "DNS permutations", type: "checkbox", default: "true" },
  ],
  columns: ["Subdomain", "IP", "Sources"],
  buildInit: (v) => ({
    confirm_auth: true,
    domain: v.domain?.trim().toLowerCase().replace(/^\.+/, ""),
    sources: v.sources && v.sources !== "all" ? [v.sources] : undefined,
    resolve: v.resolve !== "false",
    permutations: v.permutations !== "false",
  }),
  toRow: (ev) => {
    if (ev?.type === "found") return { cols: [ev.name, ev.ip || "", (ev.sources || []).join(", ")], level: "hit" };
    if (ev?.type === "permutation_found") return { cols: [ev.subdomain, ev.ip || "", "permutation"], level: "hit" };
    return null;
  },
  toOutput: (ev) => {
    switch (ev?.type) {
      case "started": return { level: "info", text: `started — ${ev.domain} · sources ${(ev.sources || []).join(", ")}` };
      case "scope": return { level: ev.verdict === "deny" ? "error" : "info", text: `scope ${ev.verdict} — ${ev.reason}` };
      case "source_start": return { level: "info", text: `${ev.source}: querying…` };
      case "source_done": return { level: ev.error ? "error" : "info", text: `${ev.source}: ${ev.error ? ev.error : `${ev.count} new`}` };
      case "found": return { level: "hit", text: `${ev.name}${ev.ip ? " → " + ev.ip : ""}` };
      case "phase": return { level: "info", text: ev.message || `phase ${ev.phase}` };
      case "permutation_found": return { level: "hit", text: `${ev.subdomain} → ${ev.ip} (permutation)` };
      case "done": return { level: "done", text: `done — ${ev.total} unique, ${ev.resolved} resolved in ${fmt(ev.elapsed)}s${ev.stopped ? " (stopped)" : ""}` };
      case "error": return { level: "error", text: ev.detail || "error" };
      default: return null;
    }
  },
  doneText: (ev) => (ev?.type === "done" ? `${ev.total} unique · ${ev.resolved} resolved · ${fmt(ev.elapsed)}s` : ""),
};

const CMS: HttpDescriptor = {
  id: "cms",
  label: "CMS / Stack Detect",
  group: "Web Recon",
  blurb: "Fingerprint CMS, frameworks, servers, and CDNs from response signals.",
  tier: 1,
  transport: "http",
  fields: [{ name: "url", label: "URL / host", type: "text", placeholder: "https://example.com", required: true }],
  columns: ["Technology", "Category", "Version", "Confidence"],
  run: (v) => {
    const qs = new URLSearchParams({ url: v.url.trim(), confirm: "true" });
    return authFetch(`/cms/fingerprint?${qs}`).then((r) => r.json());
  },
  toRows: (r) => {
    const rows: ResultRow[] = [];
    for (const t of r?.technologies || []) {
      rows.push({ cols: [t.name, t.category || "", t.version || "", t.confidence || ""], level: "hit" });
    }
    for (const f of r?.findings || []) {
      rows.push({ cols: [f.label, f.detail, "", ""], level: f.severity === "high" ? "error" : "info" });
    }
    return rows;
  },
  toOutputs: (r) => (r?.findings || []).map((f: any) => ({ level: f.severity === "high" ? "error" : "info", text: `${f.label}: ${f.detail}` })),
  doneText: (r) => `${(r?.technologies || []).length} technologies · ${r?.host || ""}`,
};

const JWT: HttpDescriptor = {
  id: "jwt",
  label: "JWT Decode / Verify",
  group: "Web Recon",
  blurb: "Decode header + claims and flag alg=none, weak HMAC secrets, expiry.",
  tier: 1,
  transport: "http",
  fields: [{ name: "token", label: "Token", type: "text", placeholder: "eyJhbGci…", required: true }],
  columns: ["Field", "Value"],
  run: (v) =>
    authFetch("/jwt/decode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: v.token.trim(), weak_secrets: true }),
    }).then((r) => r.json()),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    const push = (k: string, val?: unknown, level?: ResultRow["level"]) => {
      if (val != null && val !== "") rows.push({ cols: [k, String(val)], level });
    };
    push("alg", r?.alg, String(r?.alg).toUpperCase() === "NONE" ? "error" : undefined);
    push("typ", r?.typ);
    push("kid", r?.kid);
    push("Signature", r?.signature_present ? "present" : "missing");
    for (const [k, val] of Object.entries(r?.header || {})) push(`header.${k}`, val);
    for (const [k, val] of Object.entries(r?.payload || {})) push(`payload.${k}`, typeof val === "object" ? JSON.stringify(val) : val);
    if (r?.claims_meta?.exp_iso) push("exp", r.claims_meta.exp_iso, r.claims_meta.expired ? "error" : undefined);
    if (r?.claims_meta?.iat_iso) push("iat", r.claims_meta.iat_iso);
    if (r?.weak_secret_match) push("Weak secret", r.weak_secret_match.secret, "error");
    for (const f of r?.findings || []) rows.push({ cols: [f.label, f.detail], level: f.severity === "high" ? "error" : f.severity === "warn" ? "info" : "info" });
    return rows;
  },
  toOutputs: (r) => (r?.findings || []).map((f: any) => ({ level: f.severity === "high" ? "error" : "info", text: `${f.label}: ${f.detail}` })),
  doneText: (r) => `alg=${r?.alg || "?"} · ${(r?.findings || []).length} findings`,
};

const GRAPHQL: HttpDescriptor = {
  id: "graphql",
  label: "GraphQL Introspection",
  group: "Web Recon",
  blurb: "Probe a GraphQL endpoint for introspection and dump the schema surface.",
  tier: 1,
  transport: "http",
  fields: [{ name: "url", label: "Endpoint URL", type: "text", placeholder: "https://example.com/graphql", required: true }],
  columns: ["Kind", "Name", "Detail"],
  run: (v) => {
    const qs = new URLSearchParams({ url: v.url.trim(), confirm: "true" });
    return authFetch(`/graphql/introspect?${qs}`).then((r) => r.json());
  },
  toRows: (r) => {
    const rows: ResultRow[] = [];
    if (!r?.introspection_enabled) {
      for (const f of r?.findings || []) rows.push({ cols: ["info", f.label, f.detail] });
      return rows;
    }
    if (r.query_type) rows.push({ cols: ["root", "Query", r.query_type] });
    if (r.mutation_type) rows.push({ cols: ["root", "Mutation", r.mutation_type] });
    if (r.subscription_type) rows.push({ cols: ["root", "Subscription", r.subscription_type] });
    for (const q of r.queries || []) {
      const args = (q.args || []).map((a: any) => `${a.name}: ${a.type}`).join(", ");
      rows.push({ cols: ["query", q.field, `(${args}) → ${q.type}`], level: "hit" });
    }
    for (const m of r.mutations || []) {
      const args = (m.args || []).map((a: any) => `${a.name}: ${a.type}`).join(", ");
      rows.push({ cols: ["mutation", m.field, `(${args}) → ${m.type}`], level: "hit" });
    }
    for (const t of r.types || []) rows.push({ cols: [t.kind || "type", t.name, t.description || ""] });
    for (const d of r.deprecated || []) rows.push({ cols: ["deprecated", `${d.parent}.${d.field}`, d.reason || ""], level: "info" });
    return rows;
  },
  toOutputs: (r) => (r?.findings || []).map((f: any) => ({ level: f.severity === "high" ? "error" : f.severity === "warn" ? "info" : "info", text: `${f.label}: ${f.detail}` })),
  doneText: (r) =>
    r?.introspection_enabled
      ? `introspection ON — ${(r.queries || []).length} queries · ${(r.mutations || []).length} mutations · ${r.type_count || 0} types`
      : "introspection disabled",
};

export const WEBRECON_TOOLS: ToolDescriptor[] = [SUBDOMAIN_ENUM, CMS, JWT, GRAPHQL];
