// playbookApi — the single client seam over routers/playbook_run.py.
//
// Both BuildPanel (left rail) and PlaybookEditor (tab) talk to the backend
// through these helpers so the request shapes stay in one place. Every call
// goes through authFetch (X-MHP-Token attached).
//
// Lab binding: the backend carries a nullable `lab_id` COLUMN on the playbooks
// table (ALTER TABLE ADD COLUMN). A playbook targets at most one training lab;
// null = unbound. We chose a real column over folding it into the steps JSON so
// a future query can list "playbooks for lab X" without parsing every blob.

import { authFetch } from "../api";

/** HTML5 DnD payload type for a tool dragged from the palette → a playbook. */
export const TOOL_DND_MIME = "application/x-s-ide-tool-id";

export type PlaybookStep = {
  tool_id: string;
  in_map?: string | null;
  expected?: string;
  methodology_ids?: string[];
};

export type Playbook = {
  id: string;
  name: string;
  steps: PlaybookStep[];
  lab_id?: string | null;
};

export type Coverage = {
  required: string[];
  covered: string[];
  missing: string[];
  pct: number;
};

async function json<T>(r: Response): Promise<T> {
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()) as T;
}

export async function listPlaybooks(): Promise<Playbook[]> {
  const r = await authFetch("/playbooks");
  const b = await json<{ playbooks: Playbook[] }>(r);
  return b.playbooks ?? [];
}

export async function getPlaybook(id: string): Promise<Playbook> {
  return json<Playbook>(await authFetch(`/playbooks/${id}`));
}

export async function createPlaybook(
  name: string,
  steps: PlaybookStep[] = [],
  labId: string | null = null,
): Promise<Playbook> {
  const r = await authFetch("/playbooks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, steps, lab_id: labId }),
  });
  return json<Playbook>(r);
}

/** Replace name + steps + lab binding (the editor always sends the whole doc). */
export async function savePlaybook(
  id: string,
  name: string,
  steps: PlaybookStep[],
  labId: string | null,
): Promise<Playbook> {
  const r = await authFetch(`/playbooks/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, steps, lab_id: labId }),
  });
  return json<Playbook>(r);
}

/** Append a single tool step to an existing playbook and persist it. */
export async function appendStep(pb: Playbook, toolId: string): Promise<Playbook> {
  const steps: PlaybookStep[] = [
    ...pb.steps,
    { tool_id: toolId, in_map: null, expected: "", methodology_ids: [] },
  ];
  return savePlaybook(pb.id, pb.name, steps, pb.lab_id ?? null);
}

export async function coverage(id: string): Promise<Coverage> {
  return json<Coverage>(await authFetch(`/playbooks/${id}/coverage`, { method: "POST" }));
}

/** Delete a playbook entirely. */
export async function deletePlaybook(id: string): Promise<void> {
  const r = await authFetch(`/playbooks/${id}`, { method: "DELETE" });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
}

export type Lab = { id: string; name: string };

export async function listLabs(): Promise<Lab[]> {
  try {
    const r = await authFetch("/labs");
    if (!r.ok) return [];
    const b = (await r.json()) as { labs?: Lab[] };
    return (b.labs ?? []).map((l) => ({ id: l.id, name: l.name }));
  } catch {
    return [];
  }
}
