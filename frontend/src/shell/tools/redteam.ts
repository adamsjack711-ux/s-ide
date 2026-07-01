/**
 * Red Team tools — offensive/intrusive group.
 *
 * Contracts harvested from the vendored backend routers (do not invent):
 *   - exploits      → GET  /exploits/search?q=...   (HTTP one-shot)
 *   - reverse_shell → POST /reverse-shell/payload   (HTTP one-shot, payload generator)
 *   - c2_beacon     → POST /c2/listener             (HTTP one-shot, egress-test listener)
 *
 * Tier/intrusive gating per the capability layer:
 *   - exploits      : Tier 1, offline searchsploit (exploitdb optional → falls back to remote)
 *   - reverse_shell : Tier 2, intrusive (payload generator / listener)
 *   - c2_beacon     : Tier 2, intrusive (egress / beacon test)
 */
import { authFetch } from "../../api";
import { obfuscate, type Variant, type ObfContext } from "../../lib/obfuscate";
import type { ToolDescriptor, HttpDescriptor, ResultRow, OutLine } from "./types";

// ── exploits (SearchSploit) ──────────────────────────────────────────────────
const EXPLOITS: HttpDescriptor = {
  id: "exploits",
  label: "Exploits / SearchSploit",
  group: "Red Team",
  blurb: "Search an offline ExploitDB (searchsploit); falls back to the remote API when not installed.",
  tier: 1,
  requires: "exploitdb optional (local searchsploit; remote fallback otherwise)",
  transport: "http",
  fields: [
    { name: "query", label: "Query", type: "text", placeholder: "apache 2.4.49", required: true },
  ],
  columns: ["EDB-ID", "Title", "Type", "Platform", "Path"],
  run: (v) =>
    authFetch(`/exploits/search?q=${encodeURIComponent((v.query || "").trim())}`).then((r) => r.json()),
  // Response: { exploits: [{id,title,path,type,platform,date,cve,source}], source, query }
  toRows: (j) =>
    (j?.exploits || []).map(
      (e: any): ResultRow => ({
        cols: [
          String(e.id ?? ""),
          String(e.title ?? ""),
          String(e.type ?? ""),
          String(e.platform ?? ""),
          String(e.path ?? ""),
        ],
        level: "hit",
      }),
    ),
  toOutputs: (j) => {
    const out: OutLine[] = [];
    const n = (j?.exploits || []).length;
    out.push({ level: "info", text: `source: ${j?.source ?? "?"} · query: ${j?.query ?? ""}` });
    for (const e of j?.exploits || []) {
      out.push({ level: "hit", text: `[${e.id}] ${e.title}${e.path ? ` (${e.path})` : ""}` });
    }
    if (!n) out.push({ level: "info", text: "no exploits found" });
    return out;
  },
  doneText: (j) => `${(j?.exploits || []).length} exploits · ${j?.source ?? "?"}`,
};

// ── reverse_shell (Payload generator) ────────────────────────────────────────
const REVERSE_SHELL: HttpDescriptor = {
  id: "reverse_shell",
  label: "Reverse Shell",
  group: "Red Team",
  blurb: "Generate a reverse-shell payload one-liner for a chosen LHOST/LPORT and shell type.",
  tier: 2,
  intrusive: true,
  requires: "authorized engagement scope (intrusive)",
  transport: "http",
  fields: [
    { name: "lhost", label: "LHOST", type: "text", placeholder: "10.0.0.1", required: true },
    { name: "lport", label: "LPORT", type: "text", default: "4444", required: true },
    {
      name: "kind",
      label: "Shell type",
      type: "select",
      default: "bash-tcp",
      // IDs match reverse_shell.py _VALID_PAYLOAD_KINDS / PAYLOAD_KINDS.
      options: [
        { value: "bash-tcp", label: "Bash (/dev/tcp)" },
        { value: "bash-i", label: "Bash -i" },
        { value: "nc-e", label: "netcat -e" },
        { value: "nc-mkfifo", label: "netcat + mkfifo" },
        { value: "python", label: "Python" },
        { value: "python3", label: "Python3" },
        { value: "perl", label: "Perl" },
        { value: "ruby", label: "Ruby" },
        { value: "php", label: "PHP" },
        { value: "powershell", label: "PowerShell" },
        { value: "socat", label: "socat (TTY)" },
        { value: "awk", label: "awk" },
        { value: "telnet-fifo", label: "telnet + mkfifo" },
      ],
    },
  ],
  columns: ["Kind", "Payload"],
  run: (v) =>
    authFetch("/reverse-shell/payload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: (v.kind || "bash-tcp").trim(),
        lhost: (v.lhost || "").trim(),
        lport: Number(v.lport || 4444),
      }),
    }).then((r) => r.json()),
  // Router returns a single {cmd} per request (one kind at a time) — one payload row.
  toRows: (j): ResultRow[] =>
    j?.cmd ? [{ cols: [String(j.kind ?? ""), String(j.cmd)], level: "hit" }] : [],
  toOutputs: (j): OutLine[] => (j?.cmd ? [{ level: "hit", text: String(j.cmd) }] : []),
  doneText: (j) => (j?.cmd ? "payload generated" : "no payload"),
};

// ── c2_beacon (C2 Beacon Sim) ────────────────────────────────────────────────
const C2_BEACON: HttpDescriptor = {
  id: "c2_beacon",
  label: "C2 Beacon Sim",
  group: "Red Team",
  blurb: "Egress/beacon test — start a listener and get copy-paste beacon commands to fire from a target.",
  tier: 2,
  intrusive: true,
  requires: "authorized engagement scope (intrusive)",
  transport: "http",
  fields: [
    { name: "port", label: "Port", type: "text", default: "8080", required: true },
    { name: "host", label: "Bind host", type: "text", default: "0.0.0.0" },
    {
      name: "mode",
      label: "Mode",
      type: "select",
      default: "http",
      options: [
        { value: "http", label: "HTTP" },
        { value: "tcp", label: "TCP" },
      ],
    },
  ],
  columns: ["Field", "Value"],
  run: (v) =>
    authFetch("/c2/listener", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        port: Number(v.port || 8080),
        host: (v.host || "0.0.0.0").trim(),
        mode: (v.mode || "http").trim(),
      }),
    }).then((r) => r.json()),
  // Response: { listener: {id,port,host,mode,token,...}, beacons: {name: cmd} }
  toRows: (j) => {
    const rows: ResultRow[] = [];
    const l = j?.listener || {};
    const push = (k: string, val?: unknown) => {
      if (val != null && val !== "") rows.push({ cols: [k, String(val)] });
    };
    push("Listener ID", l.id);
    push("Bind", l.host != null && l.port != null ? `${l.host}:${l.port}` : "");
    push("Mode", l.mode);
    push("Token", l.token);
    for (const [name, cmd] of Object.entries(j?.beacons || {})) {
      rows.push({ cols: [`beacon (${name})`, String(cmd)], level: "hit" });
    }
    return rows;
  },
  toOutputs: (j) => {
    const out: OutLine[] = [];
    const l = j?.listener || {};
    out.push({
      level: "info",
      text: `listener ${l.id ?? "?"} up on ${l.host ?? "?"}:${l.port ?? "?"} (${l.mode ?? "?"})`,
    });
    for (const [name, cmd] of Object.entries(j?.beacons || {})) {
      out.push({ level: "hit", text: `${name}: ${cmd}` });
    }
    return out;
  },
  doneText: (j) => {
    const l = j?.listener || {};
    return l.id ? `listener ${l.id} · ${l.host}:${l.port}` : "no listener";
  },
};

// ── payload_obfuscator (client-side, no backend) ─────────────────────────────
// A pure-renderer utility: transform a payload into encoding/evasion variants.
// Tier 1, non-intrusive (touches no target), so it's always available; the
// scope/authorization/audit gates apply to whatever tool consumes the output.
const PAYLOAD_OBFUSCATOR: HttpDescriptor = {
  id: "payload_obfuscator",
  label: "Payload Obfuscator",
  group: "Red Team",
  blurb: "Encode a payload into filter/WAF-evasion variants (URL, base64, hex, unicode, HTML entities, mixed-case, SQL comments, JS). Runs entirely in the app — no backend.",
  tier: 1,
  requires: "none (client-side)",
  transport: "http",
  fields: [
    { name: "payload", label: "Payload", type: "text", placeholder: "<script>alert(1)</script>", required: true },
    {
      name: "context",
      label: "Context",
      type: "select",
      default: "any",
      options: [
        { value: "any", label: "Any" },
        { value: "url", label: "URL / query" },
        { value: "html", label: "HTML" },
        { value: "js", label: "JavaScript" },
        { value: "sql", label: "SQL" },
      ],
    },
  ],
  columns: ["Technique", "Output"],
  // No network: compute the variants locally and hand them to the panel.
  run: async (v) => ({
    payload: v.payload ?? "",
    context: v.context || "any",
    variants: obfuscate(v.payload ?? "", (v.context || "any") as ObfContext),
  }),
  toRows: (j) =>
    (j?.variants || []).map(
      (x: Variant): ResultRow => ({ cols: [x.label, x.value], level: "hit" }),
    ),
  toOutputs: (j) => {
    const out: OutLine[] = [{ level: "info", text: `${(j?.variants || []).length} variants · context: ${j?.context}` }];
    for (const x of j?.variants || []) out.push({ level: "hit", text: `${x.label}: ${x.value}` });
    return out;
  },
  doneText: (j) => `${(j?.variants || []).length} variants`,
};

export const REDTEAM_TOOLS: ToolDescriptor[] = [EXPLOITS, REVERSE_SHELL, C2_BEACON, PAYLOAD_OBFUSCATOR];
