/**
 * Discovery group tools — local-host / LAN enumeration over WS.
 * Contracts harvested from src/api.ts (LocalDiscoveryInit/Event, LanInit/Event)
 * and backend routers/local_discovery.py + routers/lan_scan.py.
 */
import { fmt, type WsDescriptor, type ToolDescriptor } from "./types";

const LOCAL_DISCOVERY: WsDescriptor = {
  id: "local_discovery",
  label: "Local Discovery",
  group: "Discovery",
  blurb: "Passive local-network discovery — mDNS / SSDP / LLMNR neighbours on the wire.",
  tier: 1,
  transport: "ws",
  wsPath: "/ws/local-discovery",
  fields: [
    {
      name: "protocols",
      label: "Protocols",
      type: "select",
      default: "all",
      options: [
        { value: "all", label: "All (mDNS · SSDP · LLMNR)" },
        { value: "mdns", label: "mDNS only" },
        { value: "ssdp", label: "SSDP only" },
        { value: "llmnr", label: "LLMNR only" },
      ],
    },
    { name: "duration", label: "Listen (s)", type: "text", default: "8" },
  ],
  columns: ["Proto", "Host / IP", "Service", "Detail"],
  buildInit: (v) => ({
    protocols:
      v.protocols === "all" || !v.protocols ? ["mdns", "ssdp", "llmnr"] : [v.protocols],
    duration: Number(v.duration || 8),
  }),
  toRow: (ev) => {
    if (ev?.type !== "found") return null;
    const hostIp = ev.ip ? `${ev.ip}${ev.port ? ":" + ev.port : ""}` : ev.server || "";
    const service = ev.service_type || ev.instance || ev.st || "";
    const detail = ev.location || ev.usn || ev.server || "";
    return { cols: [ev.proto || "", hostIp, service, detail], level: "hit" };
  },
  toOutput: (ev) => {
    switch (ev?.type) {
      case "start":
        return { level: "info", text: `started — ${(ev.protocols || []).join(", ")} · ${ev.duration}s` };
      case "found":
        return { level: "hit", text: `${ev.proto} ${ev.ip || ev.server || ev.instance || ""} ${ev.service_type || ev.st || ""}`.trim() };
      case "done": {
        const counts = ev.counts || {};
        const summary = Object.entries(counts).map(([k, n]) => `${k}:${n}`).join(" ");
        return { level: "done", text: `done — ${summary || "0 found"} in ${fmt(ev.elapsed)}s` };
      }
      case "error":
        return { level: "error", text: ev.detail || "error" };
      default:
        return null;
    }
  },
  doneText: (ev) => {
    if (ev?.type !== "done") return "";
    const total = Object.values(ev.counts || {}).reduce((a: number, b: any) => a + Number(b), 0);
    return `${total} found · ${fmt(ev.elapsed)}s`;
  },
};

const LAN_SCAN: WsDescriptor = {
  id: "lan_scan",
  label: "LAN Scan",
  group: "Discovery",
  blurb: "Sweep the local subnet for live hosts (ARP/ping) with hostname + MAC.",
  tier: 2,
  requires: "raw socket / sudo for ARP",
  transport: "ws",
  wsPath: "/ws/lan-scan",
  fields: [
    { name: "network", label: "Network (CIDR)", type: "text", placeholder: "auto / 192.168.1.0/24" },
  ],
  columns: ["IP", "Hostname", "MAC"],
  buildInit: (v) => (v.network?.trim() ? { network: v.network.trim() } : {}),
  toRow: (ev) =>
    ev?.type === "host"
      ? { cols: [ev.ip, ev.hostname || "", ev.mac || ""], level: ev.is_self ? "info" : "hit" }
      : null,
  toOutput: (ev) => {
    switch (ev?.type) {
      case "started":
        return { level: "info", text: `started — ${ev.network} (local ${ev.local_ip}) · ${ev.total_hosts} hosts` };
      case "host":
        return {
          level: ev.is_self ? "info" : "hit",
          text: `${ev.ip}${ev.hostname ? " " + ev.hostname : ""}${ev.mac ? " [" + ev.mac + "]" : ""}${ev.is_self ? " (self)" : ""}`,
        };
      case "mac_update":
        return { level: "info", text: `${ev.ip} → ${ev.mac}` };
      case "done":
        return { level: "done", text: `done — ${ev.found} hosts in ${fmt(ev.elapsed)}s${ev.stopped ? " (stopped)" : ""}` };
      case "error":
        return { level: "error", text: ev.detail || "error" };
      default:
        return null;
    }
  },
  doneText: (ev) => (ev?.type === "done" ? `${ev.found} hosts · ${fmt(ev.elapsed)}s` : ""),
};

export const DISCOVERY_TOOLS: ToolDescriptor[] = [LOCAL_DISCOVERY, LAN_SCAN];
