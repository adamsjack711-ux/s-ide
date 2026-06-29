/**
 * Engagement-spine client — Target / Sub-target / Engagement / pairing model.
 *
 * Mirrors `backend/lib/spine.py`. One rule drives the UI: authorization flows
 * from the engagement, never from a target existing.
 *
 *  - A **Target** is inert (provenance + name + metadata).
 *  - A **Sub-target** is an addressable component, *un-armed* by default.
 *  - Attaching an **engagement** arms a sub-target (the deliberate act).
 *  - Only an armed **pairing** (engagement × sub-target) runs or mints findings.
 *
 * Every call rides the shared `authFetch` (X-MHP-Token / -Mode / -Engagement-Id
 * headers); the backend treats the *arming* engagement as the source of truth
 * for a run, so these helpers don't have to thread it manually.
 */
import { authFetch, parseError } from "../api";
import type { Finding } from "./engagement";
import { emit } from "../shell/bus";

export type Provenance = "lab" | "owned" | "external";
export type SubTargetType = "host" | "service" | "url" | "endpoint" | "directory";

export const PROVENANCES: Provenance[] = ["lab", "owned", "external"];
export const SUBTARGET_TYPES: SubTargetType[] = [
  "host", "service", "url", "endpoint", "directory",
];

export type Arming = {
  id: string;
  sub_target_id: string;
  engagement_id: string;
  engagement_name: string | null;
  armed_at: string;
  detached_at: string | null;
};

export type SubTarget = {
  id: string;
  target_id: string;
  type: SubTargetType;
  address: string;
  label: string;
  metadata: Record<string, unknown>;
  created_at: string;
  /** Live arming state — true iff an engagement is currently attached. */
  armed: boolean;
  arming: Arming | null;
};

export type Target = {
  id: string;
  name: string;
  provenance: Provenance;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  /** Present on detail / expanded list responses. */
  sub_targets?: SubTarget[];
};

export type PairingRun = {
  id: string;
  sub_target_id: string;
  engagement_id: string;
  target_id: string;
  tool: string;
  status: "started" | "completed" | "error" | "refused";
  started_at: string;
  ended_at: string | null;
  output: string;
  summary: string;
};

/** A finding enriched with its pairing provenance triple. */
export type PairingFinding = Finding & {
  sub_target_id: string;
  target_id: string;
};

async function jsonOrThrow<T>(r: Response): Promise<T> {
  if (!r.ok) throw new Error(await parseError(r));
  return r.json() as Promise<T>;
}

function postJson(path: string, body: unknown): Promise<Response> {
  return authFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ── Targets ────────────────────────────────────────────────────────────────

export async function listTargets(expand = true): Promise<Target[]> {
  const r = await authFetch(`/spine/targets?expand=${expand ? 1 : 0}`);
  const body = await jsonOrThrow<{ targets: Target[] }>(r);
  return body.targets;
}

export async function getTarget(tid: string): Promise<Target> {
  return jsonOrThrow<Target>(await authFetch(`/spine/targets/${tid}`));
}

export async function createTarget(input: {
  name: string;
  provenance: Provenance;
  metadata?: Record<string, unknown>;
}): Promise<Target> {
  return jsonOrThrow<Target>(await postJson(`/spine/targets`, input));
}

export async function deleteTarget(tid: string): Promise<void> {
  const r = await authFetch(`/spine/targets/${tid}`, { method: "DELETE" });
  if (!r.ok) throw new Error(await parseError(r));
}

// ── Sub-targets ──────────────────────────────────────────────────────────────

export async function createSubTarget(
  targetId: string,
  input: { type: SubTargetType; address: string; label?: string },
): Promise<SubTarget> {
  return jsonOrThrow<SubTarget>(
    await postJson(`/spine/targets/${targetId}/subtargets`, input),
  );
}

export async function deleteSubTarget(sid: string): Promise<void> {
  const r = await authFetch(`/spine/subtargets/${sid}`, { method: "DELETE" });
  if (!r.ok) throw new Error(await parseError(r));
}

// ── Arming (attach / detach an engagement — the safety core) ─────────────────

export async function armSubTarget(
  sub: SubTarget,
  engagementId: string,
): Promise<SubTarget> {
  const body = await jsonOrThrow<{ sub_target: SubTarget }>(
    await postJson(`/spine/subtargets/${sub.id}/arm`, { engagement_id: engagementId }),
  );
  emit("subTargetArmed", {
    subTargetId: sub.id,
    engagementId,
    targetId: sub.target_id,
  });
  return body.sub_target;
}

export async function disarmSubTarget(sub: SubTarget): Promise<SubTarget> {
  const body = await jsonOrThrow<{ sub_target: SubTarget }>(
    await postJson(`/spine/subtargets/${sub.id}/disarm`, {}),
  );
  emit("subTargetDisarmed", { subTargetId: sub.id, targetId: sub.target_id });
  return body.sub_target;
}

// ── Workbench: run a pairing ─────────────────────────────────────────────────

export async function runPairing(sub: SubTarget, tool = "connect"): Promise<PairingRun> {
  const arming = sub.arming;
  emit("pairingRunStarted", {
    subTargetId: sub.id,
    engagementId: arming?.engagement_id ?? "",
    tool,
  });
  // authFetch surfaces the refusal body (403 SUBTARGET_UNARMED, scope/attestation
  // denials) through parseError — the caller shows it to the operator.
  const r = await authFetch(`/spine/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sub_target_id: sub.id, tool }),
  });
  const run = await jsonOrThrow<PairingRun>(r);
  emit("pairingRunOutput", {
    subTargetId: sub.id,
    engagementId: run.engagement_id,
    runId: run.id,
    status: run.status,
    output: run.output,
  });
  return run;
}

export async function listRuns(sid: string): Promise<PairingRun[]> {
  const body = await jsonOrThrow<{ runs: PairingRun[] }>(
    await authFetch(`/spine/subtargets/${sid}/runs`),
  );
  return body.runs;
}

// ── Findings (born from a pairing) ───────────────────────────────────────────

export async function createPairingFinding(input: {
  sub_target_id: string;
  title: string;
  severity: Finding["severity"];
  description?: string;
  evidence?: string;
  tool?: string;
}): Promise<PairingFinding> {
  const f = await jsonOrThrow<PairingFinding>(await postJson(`/spine/findings`, input));
  emit("findingCreated", {
    findingId: f.id,
    engagementId: f.engagement_id,
    subTargetId: f.sub_target_id,
    targetId: f.target_id,
  });
  emit("findingsChanged", {});
  return f;
}

export async function listAllPairingFindings(): Promise<PairingFinding[]> {
  const body = await jsonOrThrow<{ findings: PairingFinding[] }>(
    await authFetch(`/spine/findings`),
  );
  return body.findings;
}

export async function listTargetFindings(tid: string): Promise<PairingFinding[]> {
  const body = await jsonOrThrow<{ findings: PairingFinding[] }>(
    await authFetch(`/spine/targets/${tid}/findings`),
  );
  return body.findings;
}

// ── Engagement view ──────────────────────────────────────────────────────────

export async function engagementArmed(eid: string): Promise<SubTarget[]> {
  const body = await jsonOrThrow<{ sub_targets: (SubTarget & { target?: Target })[] }>(
    await authFetch(`/spine/engagements/${eid}/armed`),
  );
  return body.sub_targets;
}

// ── Default-safe local surface ───────────────────────────────────────────────

export async function bootstrapLocal(): Promise<{ target: Target; engagement: unknown }> {
  return jsonOrThrow(await postJson(`/spine/bootstrap-local`, {}));
}
