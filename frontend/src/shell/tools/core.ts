/**
 * Core tools — the originally-wired Tier-1 set, grouped by domain
 * (Discovery / Recon). New tools live in sibling group files.
 */
import { fetchWhois, fetchIpReport, fetchTlsAudit } from "../../api";
import { fmt, type HttpDescriptor, type ResultRow, type WsDescriptor } from "./types";

const DNS_RECON: WsDescriptor = {
  id: "dns_recon",
  label: "DNS Recon",
  group: "Discovery",
  blurb: "Subdomain enumeration + records over the system resolver.",
  tier: 1,
  transport: "ws",
  wsPath: "/ws/dns-recon",
  fields: [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true },
    { name: "wordlist", label: "Wordlist", type: "select", default: "small", options: [{ value: "small", label: "Small (fast)" }, { value: "medium", label: "Medium" }] },
  ],
  columns: ["Subdomain", "IP"],
  mode: "passive",
  parseAssets: (events) => events.filter((e) => e?.type === "hit").map((e) => ({ kind: "host" as const, key: e.subdomain, props: { ip: e.ip } })),
  buildInit: (v) => ({ domain: v.domain?.trim().toLowerCase(), wordlist: v.wordlist || "small" }),
  toRow: (ev) => (ev?.type === "hit" ? { cols: [ev.subdomain, ev.ip], level: "hit" } : null),
  toOutput: (ev) => {
    switch (ev?.type) {
      case "started": return { level: "info", text: `started — ${ev.domain} · ${ev.wordlist_size} candidates · NS ${(ev.ns || []).join(", ")}` };
      case "hit": return { level: "hit", text: `${ev.subdomain} → ${ev.ip}` };
      case "done": return { level: "done", text: `done — ${ev.found} found in ${fmt(ev.elapsed)}s${ev.stopped ? " (stopped)" : ""}` };
      case "error": return { level: "error", text: ev.detail || "error" };
      default: return null;
    }
  },
  doneText: (ev) => (ev?.type === "done" ? `${ev.found} found · ${fmt(ev.elapsed)}s` : ""),
};

const IP_CHECK: HttpDescriptor = {
  id: "ip_checker",
  label: "IP Checker",
  group: "Discovery",
  blurb: "Blue-team IP triage — class, reverse DNS, ASN/org, DNSBL, verdict.",
  tier: 1,
  transport: "http",
  fields: [{ name: "target", label: "IP / host", type: "text", placeholder: "1.1.1.1", required: true }],
  columns: ["Field", "Value"],
  mode: "passive",
  parseAssets: (events, target) => {
    const r = events[0];
    return r?.ip ? [{ kind: "host" as const, key: r.ip, props: { input: target, org: r.org, country: r.country, reverse_dns: r.reverse_dns } }] : [];
  },
  run: (v) => fetchIpReport(v.target.trim()),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    const push = (k: string, val?: unknown) => { if (val != null && val !== "") rows.push({ cols: [k, String(val)] }); };
    push("IP", r.ip); push("Class", r.ip_class); push("Reverse DNS", r.reverse_dns);
    push("Org", r.org); push("Hosting", r.hosting); push("Country", r.country);
    for (const d of r.dnsbl || []) if (d.listed) rows.push({ cols: [`DNSBL ${d.name}`, d.status], level: "error" });
    rows.push({ cols: ["Verdict", r.verdict_text], level: r.verdict_severity === "high" ? "error" : "info" });
    return rows;
  },
  doneText: (r) => r.verdict_text,
};

const WHOIS: HttpDescriptor = {
  id: "whois",
  label: "WHOIS / ASN",
  group: "Discovery",
  blurb: "WHOIS + ASN/network lookup for an IP, CIDR, or domain.",
  tier: 1,
  transport: "http",
  fields: [{ name: "target", label: "Target", type: "text", placeholder: "example.com or 1.2.3.4", required: true }],
  columns: ["Field", "Value"],
  run: (v) => fetchWhois(v.target.trim()),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    const push = (k: string, val?: unknown) => { if (val != null && val !== "") rows.push({ cols: [k, String(val)] }); };
    if (r?.asn) { push("ASN", r.asn.number); push("ASN name", r.asn.name); push("Prefix", r.asn.prefix); push("Country", r.asn.country); push("Registry", r.asn.registry); }
    if (r?.domain) { push("Registrar", r.domain.registrar); push("Created", r.domain.created); push("Expires", r.domain.expires); push("Nameservers", (r.domain.nameservers || []).join(", ")); }
    if (r?.network) { push("Netrange", r.network.netrange); push("CIDR", r.network.cidr); push("Org", r.network.org); }
    for (const f of r?.findings || []) rows.push({ cols: [f.label, f.detail], level: f.severity === "high" ? "error" : "info" });
    return rows;
  },
  toOutputs: (r) => (r?.findings || []).map((f: any) => ({ level: f.severity === "high" ? "error" : "info", text: `${f.label}: ${f.detail}` })),
  doneText: (r) => `${(r?.findings || []).length} findings`,
};

const PING: WsDescriptor = {
  id: "ping",
  label: "Ping",
  group: "Discovery",
  blurb: "ICMP/TCP reachability check via the system ping.",
  tier: 1,
  transport: "ws",
  wsPath: "/ws/ping",
  fields: [
    { name: "target", label: "Target", type: "text", placeholder: "1.1.1.1", required: true },
    { name: "count", label: "Count", type: "text", default: "4" },
  ],
  columns: ["Output"],
  buildInit: (v) => ({ target: v.target.trim(), count: Number(v.count || 4) }),
  toRow: (ev) => (ev?.type === "line" ? { cols: [ev.text] } : null),
  toOutput: (ev) => {
    switch (ev?.type) {
      case "started": return { level: "info", text: ev.cmd };
      case "line": return { level: "info", text: ev.text };
      case "done": return { level: "done", text: `done${ev.stopped ? " (stopped)" : ""}` };
      case "error": return { level: "error", text: ev.detail || "error" };
      default: return null;
    }
  },
};

const PORT_SCAN: WsDescriptor = {
  id: "port_scanner",
  label: "Port Scanner",
  group: "Recon",
  blurb: "Threaded TCP connect scan (zero-setup; SYN mode is privileged and gated).",
  tier: 1,
  transport: "ws",
  wsPath: "/ws/port-scan",
  fields: [
    { name: "target", label: "Target", type: "text", placeholder: "127.0.0.1", required: true },
    { name: "ports", label: "Ports", type: "text", default: "1-1024", placeholder: "1-1024,8080" },
  ],
  columns: ["Port", "Service", "Banner"],
  mode: "passive",
  parseAssets: (events, target) =>
    events.filter((e) => e?.type === "open").map((e) => ({ kind: "service" as const, key: `${target}:${e.port}`, props: { port: e.port, service: e.service, banner: e.banner } })),
  buildInit: (v) => ({ target: v.target.trim(), ports: v.ports || "1-1024" }),
  toRow: (ev) => (ev?.type === "open" ? { cols: [String(ev.port), ev.service || "", ev.banner || ""], level: "hit" } : null),
  toOutput: (ev) => {
    switch (ev?.type) {
      case "started": return { level: "info", text: `started — ${ev.target} (${ev.ip}) · ${ev.total} ports · ${ev.threads} threads` };
      case "open": return { level: "hit", text: `${ev.port}/tcp open ${ev.service || ""} ${ev.banner || ""}`.trim() };
      case "done": return { level: "done", text: `done — ${ev.open_count} open in ${fmt(ev.elapsed)}s${ev.stopped ? " (stopped)" : ""}` };
      case "error": return { level: "error", text: ev.detail || "error" };
      default: return null;
    }
  },
  doneText: (ev) => (ev?.type === "done" ? `${ev.open_count} open · ${fmt(ev.elapsed)}s` : ""),
};

const TLS_AUDIT: HttpDescriptor = {
  id: "tls_audit",
  label: "TLS Audit",
  group: "Recon",
  blurb: "Certificate, protocol support, cipher, and HSTS audit.",
  tier: 1,
  transport: "http",
  fields: [
    { name: "host", label: "Host", type: "text", placeholder: "example.com", required: true },
    { name: "port", label: "Port", type: "text", default: "443" },
  ],
  columns: ["Field", "Value"],
  mode: "passive",
  parseAssets: (events, target) => {
    const r = events[0];
    return r?.cert ? [{ kind: "cert" as const, key: r.cert.subject || target, props: { issuer: r.cert.issuer, not_after: r.cert.not_after, host: target } }] : [];
  },
  run: (v) => fetchTlsAudit(v.host.trim(), Number(v.port || 443)),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    const push = (k: string, val?: unknown, level?: ResultRow["level"]) => { if (val != null && val !== "") rows.push({ cols: [k, String(val)], level }); };
    push("Subject", r.cert?.subject); push("Issuer", r.cert?.issuer);
    push("Expires", r.cert?.not_after, (r.cert?.days_until_expiry ?? 99) < 14 ? "error" : undefined);
    if (r.cert?.days_until_expiry != null) push("Days to expiry", r.cert.days_until_expiry, r.cert.days_until_expiry < 14 ? "error" : undefined);
    if (r.negotiated_cipher) push("Cipher", `${r.negotiated_cipher.name} (${r.negotiated_cipher.protocol}, ${r.negotiated_cipher.bits}b)`);
    for (const [proto, state] of Object.entries(r.protocols || {})) push(proto, state, proto.includes("1.0") && state === "supported" ? "error" : undefined);
    push("HSTS", r.hsts?.present ? `yes (max-age ${r.hsts.max_age})` : "no");
    return rows;
  },
  doneText: (r) => `${r.cert?.issuer ? "cert ok" : "no cert"} · ${r.host}`,
};

const HTTP_PROBE: WsDescriptor = {
  id: "http_probe",
  label: "HTTP Probe",
  group: "Recon",
  blurb: "Content discovery + header/tech fingerprint over HTTP(S).",
  tier: 1,
  transport: "ws",
  wsPath: "/ws/http-probe",
  fields: [
    { name: "url", label: "URL", type: "text", placeholder: "https://example.com", required: true },
    { name: "wordlist", label: "Wordlist", type: "select", default: "small", options: [{ value: "small", label: "Small (fast)" }, { value: "medium", label: "Medium" }] },
  ],
  columns: ["Path", "Status", "Length", "Location"],
  mode: "passive",
  parseAssets: (events, target) =>
    events.filter((e) => e?.type === "hit").map((e) => ({ kind: "endpoint" as const, key: `${target}${e.path}`, props: { status: e.status, length: e.length } })),
  buildInit: (v) => ({ url: v.url.trim(), wordlist: v.wordlist || "small" }),
  toRow: (ev) => (ev?.type === "hit" ? { cols: [ev.path, String(ev.status), String(ev.length), ev.location || ""], level: "hit" } : null),
  toOutput: (ev) => {
    switch (ev?.type) {
      case "started": return { level: "info", text: `started — ${ev.base} · ${ev.wordlist_size} paths · methods ${(ev.methods_allowed || []).join(",")}` };
      case "finding": return { level: ev.severity === "high" ? "error" : "info", text: `${ev.label}: ${ev.detail}` };
      case "hit": return { level: "hit", text: `${ev.status} ${ev.path}${ev.location ? " → " + ev.location : ""}` };
      case "done": return { level: "done", text: `done — ${ev.hits} hits in ${fmt(ev.elapsed)}s${ev.stopped ? " (stopped)" : ""}` };
      case "error": return { level: "error", text: ev.detail || "error" };
      default: return null;
    }
  },
  doneText: (ev) => (ev?.type === "done" ? `${ev.hits} hits · ${fmt(ev.elapsed)}s` : ""),
};

export const CORE_TOOLS = [DNS_RECON, IP_CHECK, WHOIS, PING, PORT_SCAN, TLS_AUDIT, HTTP_PROBE];
