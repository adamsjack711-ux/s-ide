// Thin lab API helpers used by the lab MDI surface (LabTabView / LabConsole).
// Mirrors the subset of the backend lab contract those views need; LabsView
// keeps its own fuller copy of these shapes.
import { authFetch } from "../api";

export type LabMeta = {
  id: string;
  name: string;
  summary: string;
  category: string;
  port_map: Record<string, number>;
  primary_url: string;
  default_creds: string | null;
  has_sidecar: boolean;
  sidecar_cmds: string[];
};

export type LabContainerState =
  | "running" | "exited" | "missing" | "created" | "paused" | "dead" | "partial" | "starting" | "unknown";

export type LabStatus = {
  container: { state: LabContainerState; status?: string };
  build_status?: "idle" | "building" | "built" | "error";
  compose?: { state: string; services: { name: string; state: string }[]; running_count: number; total: number };
};

export type SidecarResult = { rc: number; stdout: string; stderr: string };

export async function fetchCatalog(): Promise<LabMeta[]> {
  const r = await authFetch("/labs/catalog");
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = (await r.json()) as { labs: LabMeta[] };
  return body.labs ?? [];
}

export async function fetchLabStatus(id: string): Promise<LabStatus> {
  const r = await authFetch(`/labs/${encodeURIComponent(id)}/status`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()) as LabStatus;
}

/** Run a whitelisted, positional-only command in the lab's sidecar container. */
export async function sidecarExec(
  id: string,
  cmd: string,
  args: string[],
  timeout = 120,
): Promise<SidecarResult> {
  const r = await authFetch(`/labs/${encodeURIComponent(id)}/sidecar/exec`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cmd, args, timeout }),
  });
  if (!r.ok) {
    // The backend returns rc:-1 in-body for validation errors, but a transport
    // failure (auth/500) still throws here.
    throw new Error(`HTTP ${r.status}`);
  }
  return (await r.json()) as SidecarResult;
}

export function isLive(state: LabContainerState | undefined): boolean {
  return state === "running" || state === "partial" || state === "starting";
}
