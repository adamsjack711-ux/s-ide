// Safety-layer client — authorization attestations + provenance.
// Active tools refuse to fire against non-lab targets without a stored
// attestation (server-side hard gate); this surfaces + creates them.
import { authFetch } from "../api";

export type Provenance = "lab" | "owned" | "external";

export type Attestation = {
  id: string;
  engagement_id: string | null;
  targets: string[];
  window_start: string;
  window_end: string;
  authority_note: string;
  attested_by: string;
  created_at: string;
};

export async function listAttestations(engagementId: string | null): Promise<Attestation[]> {
  if (!engagementId) return [];
  try {
    const r = await authFetch(`/safety/attestations?engagement_id=${encodeURIComponent(engagementId)}`);
    if (!r.ok) return [];
    const j = await r.json();
    return j.attestations ?? [];
  } catch {
    return [];
  }
}

export async function createAttestation(body: {
  engagement_id: string;
  targets: string[];
  window_start: string;
  window_end: string;
  authority_note: string;
  attested_by: string;
}): Promise<Attestation> {
  const r = await authFetch("/safety/attestations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).attestation;
}

export async function getProvenance(target: string): Promise<Provenance> {
  try {
    const r = await authFetch(`/safety/provenance?target=${encodeURIComponent(target)}`);
    if (!r.ok) return "external";
    return (await r.json()).provenance ?? "external";
  } catch {
    return "external";
  }
}
