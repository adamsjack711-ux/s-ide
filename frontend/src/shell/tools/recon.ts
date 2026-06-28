/**
 * Recon group tools — service fingerprint (HTTP one-shot) + nmap (WS stream).
 * Contracts harvested from src/api.ts (fetchFingerprint/FingerprintResult,
 * NmapOptions/NmapEvent/NmapReport) and backend routers/nmap.py (init: { opts,
 * confirm, ... }; opts carries targets[] + scan_type).
 */
import { fetchFingerprint } from "../../api";
import { type HttpDescriptor, type WsDescriptor, type ResultRow, type ToolDescriptor } from "./types";

const FINGERPRINT: HttpDescriptor = {
  id: "fingerprint",
  label: "Service Fingerprint",
  group: "Recon",
  blurb: "Banner-grab + service/version guess for a single host:port.",
  tier: 1,
  transport: "http",
  fields: [
    { name: "host", label: "Host", type: "text", placeholder: "example.com", required: true },
    { name: "port", label: "Port", type: "text", default: "80" },
  ],
  columns: ["Field", "Value"],
  run: (v) => fetchFingerprint(v.host.trim(), Number(v.port || 80)),
  toRows: (r) => {
    const rows: ResultRow[] = [];
    const push = (k: string, val?: unknown, level?: ResultRow["level"]) => {
      if (val != null && val !== "") rows.push({ cols: [k, String(val)], level });
    };
    push("Host", r.host);
    push("IP", r.ip);
    push("Port", r.port);
    push("Open", r.open ? "yes" : "no", r.open ? "hit" : undefined);
    push("Service", r.service_guess);
    push("Version", r.version);
    for (const line of r.banner_lines || []) push("Banner", line);
    for (const [k, val] of Object.entries(r.extras || {})) push(k, val);
    if (r.elapsed_ms != null) push("Elapsed (ms)", r.elapsed_ms);
    if (r.error) push("Error", r.error, "error");
    if (r.policy?.verdict) push("Policy", `${r.policy.verdict} — ${r.policy.reason}`, r.policy.verdict === "deny" ? "error" : undefined);
    return rows;
  },
  doneText: (r) => `${r.open ? "open" : "closed"} · ${r.service_guess || "unknown"} · ${r.host}:${r.port}`,
};

const NMAP: WsDescriptor = {
  id: "nmap",
  label: "Nmap",
  group: "Recon",
  blurb: "Streaming nmap scan — connect by default; SYN/UDP/OS need sudo.",
  tier: 2,
  intrusive: true,
  requires: "nmap binary + sudo for SYN/OS/UDP",
  transport: "ws",
  wsPath: "/ws/nmap",
  fields: [
    { name: "target", label: "Target", type: "text", placeholder: "192.168.1.0/24 or host", required: true },
    {
      name: "scan_type",
      label: "Scan type",
      type: "select",
      default: "connect",
      options: [
        { value: "connect", label: "TCP connect (-sT)" },
        { value: "syn", label: "SYN stealth (-sS, sudo)" },
        { value: "udp", label: "UDP (-sU, sudo)" },
      ],
    },
    { name: "ports", label: "Ports", type: "text", placeholder: "1-1024,8080" },
  ],
  columns: ["Output"],
  buildInit: (v) => {
    const scanType = v.scan_type || "connect";
    const opts: Record<string, unknown> = {
      targets: [v.target.trim()],
      scan_type: scanType,
      use_sudo: scanType === "syn" || scanType === "udp",
    };
    if (v.ports?.trim()) opts.port_spec = v.ports.trim();
    return { opts };
  },
  toRow: (ev) => {
    switch (ev?.type) {
      case "line":
      case "stderr":
        return ev.text ? { cols: [ev.text], level: ev.type === "stderr" ? "error" : "info" } : null;
      default:
        return null;
    }
  },
  toOutput: (ev) => {
    switch (ev?.type) {
      case "policy": {
        const denied = (ev.verdicts || []).filter((p: any) => p.verdict === "deny");
        if (denied.length)
          return { level: "error", text: `policy denied: ${denied.map((p: any) => `${p.target} (${p.reason})`).join("; ")}` };
        return { level: "info", text: `policy ok — ${(ev.verdicts || []).length} target(s)` };
      }
      case "started":
        return { level: "info", text: `started — ${ev.cmd}` };
      case "line":
        return { level: "info", text: ev.text };
      case "stderr":
        return { level: "error", text: ev.text };
      case "progress": {
        const bits = [
          ev.pct != null ? `${ev.pct}%` : null,
          ev.hosts_done != null ? `${ev.hosts_done} done` : null,
          ev.hosts_up != null ? `${ev.hosts_up} up` : null,
        ].filter(Boolean);
        return bits.length ? { level: "info", text: `progress — ${bits.join(" · ")}` } : null;
      }
      case "done": {
        const openCount = (ev.report?.hosts || []).reduce(
          (acc: number, h: any) => acc + (h.ports || []).filter((p: any) => p.state === "open").length,
          0,
        );
        return { level: "done", text: `done — rc ${ev.rc} · ${openCount} open port(s)${ev.stopped ? " (stopped)" : ""}` };
      }
      case "error":
        return { level: "error", text: ev.detail || "error" };
      default:
        return null;
    }
  },
  doneText: (ev) => {
    if (ev?.type !== "done") return "";
    const openCount = (ev.report?.hosts || []).reduce(
      (acc: number, h: any) => acc + (h.ports || []).filter((p: any) => p.state === "open").length,
      0,
    );
    return `rc ${ev.rc} · ${openCount} open${ev.stopped ? " (stopped)" : ""}`;
  },
};

export const RECON_TOOLS: ToolDescriptor[] = [FINGERPRINT, NMAP];
