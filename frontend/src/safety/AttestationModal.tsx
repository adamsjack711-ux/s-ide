import { useEffect, useState } from "react";
import { emit, on } from "../shell/bus";
import { getActiveEngagementId } from "../lib/engagement";
import { createAttestation } from "../lib/safety";

/**
 * Authorization attestation form. Active tools refuse to fire against non-lab
 * targets until a covering attestation is stored for the engagement (the
 * server-side hard gate). This is the deliberate, attested exception to the
 * sealed-sandbox default. Opens on the `openAttestation` bus event.
 */
export default function AttestationModal() {
  const [open, setOpen] = useState(false);
  const [targets, setTargets] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [note, setNote] = useState("");
  const [by, setBy] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => on("openAttestation", () => { setErr(""); setOpen(true); }), []);

  if (!open) return null;

  async function save() {
    const eid = getActiveEngagementId();
    if (!eid) { setErr("Select or create an engagement first."); return; }
    const t = targets.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (!t.length) { setErr("List at least one authorized target."); return; }
    setBusy(true);
    try {
      await createAttestation({
        engagement_id: eid,
        targets: t,
        window_start: start || new Date().toISOString(),
        window_end: end || new Date(Date.now() + 7 * 86400000).toISOString(),
        authority_note: note,
        attested_by: by,
      });
      emit("attestationsChanged", {});
      setOpen(false);
      setTargets(""); setNote(""); setBy("");
    } catch (e: any) {
      setErr(e?.message || "failed to save attestation");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setOpen(false)}>
      <div className="w-[34rem] rounded-lg bg-bg-card p-4 shadow-2xl ring-1 ring-divider" onClick={(e) => e.stopPropagation()}>
        <div className="mb-1 text-sm font-semibold text-ink-primary">Authorization attestation</div>
        <p className="mb-3 text-xs text-ink-dim">
          Active tools refuse to run against non-lab (external) targets without this. Read access ≠ test authorization — only attest targets you are authorized to test.
        </p>

        <label className="mb-2 block text-xs text-ink-muted">
          Authorized targets <span className="text-ink-dim">(one per line; host / CIDR / URL)</span>
          <textarea value={targets} onChange={(e) => setTargets(e.target.value)} rows={3}
            placeholder="example.com&#10;10.0.0.0/24"
            className="mt-1 w-full rounded bg-bg-base px-2 py-1 font-mono text-xs text-ink-primary outline-none ring-1 ring-divider focus:ring-accent" />
        </label>

        <div className="mb-2 flex gap-3">
          <label className="flex-1 text-xs text-ink-muted">Window start
            <input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)}
              className="mt-1 w-full rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent" />
          </label>
          <label className="flex-1 text-xs text-ink-muted">Window end
            <input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)}
              className="mt-1 w-full rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent" />
          </label>
        </div>

        <label className="mb-2 block text-xs text-ink-muted">Authority / scope note
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="SOW #, written authorization reference…"
            className="mt-1 w-full rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent" />
        </label>
        <label className="mb-3 block text-xs text-ink-muted">Attested by
          <input value={by} onChange={(e) => setBy(e.target.value)} placeholder="your name"
            className="mt-1 w-full rounded bg-bg-base px-2 py-1 text-sm text-ink-primary outline-none ring-1 ring-divider focus:ring-accent" />
        </label>

        {err && <div className="mb-2 text-xs text-danger">{err}</div>}
        <div className="flex justify-end gap-2">
          <button onClick={() => setOpen(false)} className="rounded px-3 py-1.5 text-sm text-ink-muted hover:text-ink-primary">Cancel</button>
          <button onClick={save} disabled={busy} className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:bg-accentBright disabled:opacity-50">
            {busy ? "Saving…" : "Attest"}
          </button>
        </div>
      </div>
    </div>
  );
}
