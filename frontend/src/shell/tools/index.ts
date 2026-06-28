/**
 * Tool registry aggregator. Each group file owns its descriptors; this file
 * stitches them into the registry the shell consumes. Capability gating
 * (off-until-enabled for privileged/intrusive tools) lives in ./capability.
 */
import { CORE_TOOLS } from "./core";
import { DISCOVERY_TOOLS } from "./discovery";
import { RECON_TOOLS } from "./recon";
import { OSINT_TOOLS } from "./osint";
import { WEBRECON_TOOLS } from "./webrecon";
import { WEBEXPLOIT_TOOLS } from "./webexploit";
import { AD_TOOLS } from "./ad";
import { REDTEAM_TOOLS } from "./redteam";
import { CODESCAN_TOOLS } from "./codescan";
import { isToolEnabled } from "./capability";
import type { ToolDescriptor } from "./types";

export * from "./types";
export * from "./capability";

/** Canonical group order for the Explorer / palette. */
const GROUP_ORDER = ["Discovery", "Recon", "OSINT", "Web Recon", "Web Exploit", "Code", "Active Directory", "Red Team", "Support"];

export const TOOLS: ToolDescriptor[] = [
  ...CORE_TOOLS,
  ...DISCOVERY_TOOLS,
  ...RECON_TOOLS,
  ...OSINT_TOOLS,
  ...WEBRECON_TOOLS,
  ...WEBEXPLOIT_TOOLS,
  ...AD_TOOLS,
  ...REDTEAM_TOOLS,
  ...CODESCAN_TOOLS,
];

export function toolById(id: string): ToolDescriptor | undefined {
  return TOOLS.find((t) => t.id === id);
}

/** All groups (for a capabilities/settings view) — every tool, ignoring enablement. */
export function allToolGroups(): { group: string; tools: ToolDescriptor[] }[] {
  return groupBy(TOOLS);
}

/** Groups containing only currently-enabled tools (what the Explorer shows). */
export function toolGroups(): { group: string; tools: ToolDescriptor[] }[] {
  return groupBy(TOOLS.filter(isToolEnabled)).filter((g) => g.tools.length > 0);
}

function groupBy(tools: ToolDescriptor[]): { group: string; tools: ToolDescriptor[] }[] {
  const groups = Array.from(new Set(tools.map((t) => t.group)));
  groups.sort((a, b) => {
    const ia = GROUP_ORDER.indexOf(a), ib = GROUP_ORDER.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });
  return groups.map((group) => ({ group, tools: tools.filter((t) => t.group === group) }));
}
