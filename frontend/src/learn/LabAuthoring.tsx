import { useCallback, useState } from "react";
import SectionLabel from "../shell/SectionLabel";

import { authFetch } from "../api";

/**
 * Lab authoring form. Writes a lab's learner_view (description / objective /
 * hints), the PRIVATE solution, a source_anchor (file:line), and a stub
 * armed_snapshot — via PUT /method/labs/{id}.
 *
 * The solution is sent only on save; it is NEVER read back into any learner
 * view (the learner reads go through /method/labs/{id}/learner, which whitelists
 * learner_view). This form deliberately does not re-fetch the solution.
 */

export default function LabAuthoring() {
  const [labId, setLabId] = useState("");
  const [description, setDescription] = useState("");
  const [objective, setObjective] = useState("");
  const [hints, setHints] = useState<string[]>([""]);
  const [solution, setSolution] = useState("");
  const [anchorFile, setAnchorFile] = useState("");
  const [anchorLine, setAnchorLine] = useState("");
  const [snapshot, setSnapshot] = useState("");

  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);

  function patchHint(i: number, value: string) {
    setHints((prev) => prev.map((h, idx) => (idx === i ? value : h)));
  }
  function addHint() {
    setHints((prev) => [...prev, ""]);
  }
  function removeHint(i: number) {
    setHints((prev) => (prev.length === 1 ? [""] : prev.filter((_, idx) => idx !== i)));
  }

  const save = useCallback(async () => {
    const id = labId.trim();
    if (!id) {
      setStatus({ ok: false, msg: "Lab id is required." });
      return;
    }
    setSaving(true);
    setStatus(null);

    const learner_view = {
      description: description.trim(),
      objective: objective.trim(),
      hints: hints.map((h) => h.trim()).filter(Boolean),
    };

    // Only send fields the author actually filled in; method.upsert_lab keeps
    // existing values for nulls, so partial saves don't clobber.
    const body: Record<string, unknown> = { learner_view };
    if (solution.trim()) {
      // Store as structured json; fall back to a plain note if not JSON.
      try {
        body.solution = JSON.parse(solution);
      } catch {
        body.solution = { note: solution };
      }
    }
    if (anchorFile.trim()) {
      body.source_anchor = {
        file: anchorFile.trim(),
        ...(anchorLine.trim() ? { line: Number(anchorLine) } : {}),
      };
    }
    if (snapshot.trim()) {
      try {
        body.armed_snapshot = JSON.parse(snapshot);
      } catch {
        body.armed_snapshot = { note: snapshot };
      }
    }

    try {
      const r = await authFetch(`/method/labs/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setStatus({ ok: true, msg: `Saved lab "${id}".` });
    } catch (e) {
      setStatus({ ok: false, msg: e instanceof Error ? e.message : "Save failed" });
    } finally {
      setSaving(false);
    }
  }, [labId, description, objective, hints, solution, anchorFile, anchorLine, snapshot]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-bg-sidebar text-sm">
      <div className="border-b border-divider px-3 py-3">
        <SectionLabel>Author a lab</SectionLabel>
        <p className="mt-2 text-xs text-ink-muted">
          Author the learner-facing view and the private solution. The solution stays server-side —
          it is never shown to learners or included in reports.
        </p>
      </div>

      <div className="space-y-4 px-3 py-3">
        <Field label="Lab id">
          <input
            value={labId}
            onChange={(e) => setLabId(e.target.value)}
            placeholder="e.g. sqli-login-01"
            className={inputCls}
          />
        </Field>

        <Section title="Learner view">
          <Field label="Objective">
            <input
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="What the learner should achieve"
              className={inputCls}
            />
          </Field>
          <Field label="Description">
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Scenario framing the learner sees"
              rows={3}
              className={textareaCls}
            />
          </Field>
          <Field label="Hints (revealed progressively, never the solution)">
            <div className="space-y-1.5">
              {hints.map((h, i) => (
                <div key={i} className="flex gap-1.5">
                  <span className="mt-1.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim">{i + 1}.</span>
                  <input
                    value={h}
                    onChange={(e) => patchHint(i, e.target.value)}
                    placeholder={`Hint ${i + 1}`}
                    className={inputCls}
                  />
                  <button onClick={() => removeHint(i)} className="rounded px-1.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim hover:text-danger">
                    ✕
                  </button>
                </div>
              ))}
              <button onClick={addHint} className="rounded bg-bg-card px-2 py-1 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary">
                + hint
              </button>
            </div>
          </Field>
        </Section>

        <Section title="Private solution">
          <div className="mb-1.5 rounded bg-amber/10 px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-amber ring-1 ring-amber/30">
            Stays server-side — never shown to learners or in reports.
          </div>
          <textarea
            value={solution}
            onChange={(e) => setSolution(e.target.value)}
            placeholder="The intended solution. JSON is stored structured; plain text is wrapped as { note }."
            rows={4}
            className={textareaCls}
          />
        </Section>

        <Section title="Source anchor">
          <div className="grid grid-cols-3 gap-1.5">
            <input
              value={anchorFile}
              onChange={(e) => setAnchorFile(e.target.value)}
              placeholder="file (e.g. app/login.py)"
              className={`col-span-2 ${inputCls}`}
            />
            <input
              value={anchorLine}
              onChange={(e) => setAnchorLine(e.target.value)}
              placeholder="line"
              inputMode="numeric"
              className={inputCls}
            />
          </div>
        </Section>

        <Section title="Armed snapshot (stub)">
          <textarea
            value={snapshot}
            onChange={(e) => setSnapshot(e.target.value)}
            placeholder="Optional JSON snapshot of the armed lab state (stub for now)."
            rows={2}
            className={textareaCls}
          />
        </Section>

        {status && (
          <div className={`text-xs ${status.ok ? "text-success" : "text-danger"}`}>{status.msg}</div>
        )}

        <button
          onClick={() => void save()}
          disabled={saving || !labId.trim()}
          className="w-full rounded bg-accent/15 px-3 py-2 text-sm text-accent ring-1 ring-accent/40 hover:bg-accent/25 disabled:opacity-50"
        >
          {saving ? "Saving…" : "Save lab"}
        </button>
      </div>
    </div>
  );
}

const inputCls =
  "w-full rounded bg-bg-card px-2 py-1 text-xs text-ink-primary outline-none ring-1 ring-divider placeholder:text-ink-dim";
const textareaCls = `${inputCls} resize-y font-mono`;

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="pb-1 text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">{label}</div>
      {children}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded ring-1 ring-divider">
      <div className="border-b border-divider px-2 py-1.5 text-xs font-medium text-ink-primary">{title}</div>
      <div className="space-y-2 px-2 py-2">{children}</div>
    </div>
  );
}
