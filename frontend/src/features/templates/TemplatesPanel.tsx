/**
 * F8 — Templates panel (feature entry file).
 *
 * Reusable, declarative FINDING + PLAYBOOK templates: create once, instantiate
 * many. Built-in templates ship as JSON constants (builtins.ts); the user's own
 * templates persist as plain JSON in localStorage under `s-ide:templates:v1`
 * (see templateStore.ts). Nothing here is executable — templates are data, and
 * every text field is validated against markup/executable content on save/load.
 *
 * Instantiate:
 *   - FINDING template → the NORMAL audited write path, promoteToFinding(...),
 *     which emits `modelChanged` so Problems / search / timeline all refresh and
 *     the finding appears in the model. This module never bypasses that path.
 *   - PLAYBOOK template → there is no confirmed backend playbook-create API we
 *     can safely call, so instantiating a playbook OPENS the playbook view
 *     (emit openView) carrying the declarative draft. It fabricates NO backend
 *     state; the UI is explicit that this drafts/opens, it does not persist a
 *     server-side playbook.
 *
 * Contract: reads the active engagement id from lib/engagement, cross-links only
 * via the bus (openView / modelChanged), registers its own view + command, and
 * imports no other feature.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { registerView, type ViewParams } from "../../shell/views";
import { registerCommand } from "../../shell/commands";
import { emit, useBus } from "../../shell/bus";
import {
  getActiveEngagementId,
  useActiveEngagementId,
  promoteToFinding,
  FINDING_SEVERITIES,
  type FindingSeverity,
} from "../../lib/engagement";
import {
  loadUserTemplates,
  saveUserTemplates,
  mergeTemplates,
  upsertUserTemplate,
  removeUserTemplate,
  validateTemplate,
  toPromoteInput,
  newUserId,
  type Template,
  type FindingTemplate,
  type PlaybookTemplate,
} from "./templateStore";
import { BUILTIN_TEMPLATES } from "./builtins";

const SOURCE = "templates";

// ── small presentational helpers ─────────────────────────────────────────────

const SEV_CLASS: Record<FindingSeverity, string> = {
  critical: "text-critical border-critical",
  high: "text-high border-high",
  medium: "text-medium border-medium",
  low: "text-low border-low",
  info: "text-ink-muted border-divider",
};

function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide ${SEV_CLASS[severity]}`}
    >
      {severity}
    </span>
  );
}

// ── panel ────────────────────────────────────────────────────────────────────

type LoadState = "loading" | "ready" | "error";

function TemplatesPanel(_props: { params: ViewParams }) {
  const activeId = useActiveEngagementId();
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [user, setUser] = useState<Template[]>([]);
  const [editing, setEditing] = useState<Template | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoadState("loading");
    try {
      setUser(loadUserTemplates());
      setError(null);
      setLoadState("ready");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setLoadState("error");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Refresh on model changes so a finding created elsewhere keeps our "appears
  // in the model" claim honest (the flash confirmation clears too).
  useBus("modelChanged", () => setFlash((f) => f));

  const all = useMemo(() => mergeTemplates(BUILTIN_TEMPLATES, user), [user]);

  const persist = useCallback((next: Template[]) => {
    setUser(next);
    saveUserTemplates(next);
  }, []);

  const onDelete = useCallback(
    (id: string) => {
      persist(removeUserTemplate(user, id));
    },
    [persist, user],
  );

  const onInstantiateFinding = useCallback(async (t: FindingTemplate) => {
    const eid = getActiveEngagementId();
    if (!eid) return;
    setFlash(null);
    setError(null);
    try {
      // NORMAL WRITE PATH — promoteToFinding emits modelChanged; every view
      // (Problems, search, timeline) refreshes and the finding is now in the model.
      const f = await promoteToFinding(toPromoteInput(t, eid));
      setFlash(`Created finding “${f.title}” — now in the engagement.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const onInstantiatePlaybook = useCallback((t: PlaybookTemplate) => {
    // HONEST: no confirmed backend playbook-create API, so we OPEN the playbook
    // view with the declarative draft rather than fabricating server state.
    emit("openView", {
      view: "playbook",
      params: { draft: { name: t.name, description: t.description, steps: t.steps }, source: SOURCE },
    });
    setFlash(`Opened playbook draft “${t.name}” (declarative — no server playbook created).`);
  }, []);

  // ── states ─────────────────────────────────────────────────────────────────
  if (loadState === "loading") {
    return <Centered>Loading templates…</Centered>;
  }
  if (loadState === "error") {
    return (
      <Centered>
        <div className="text-critical">Couldn’t load templates.</div>
        <div className="mt-1 text-ink-dim">{error}</div>
        <button
          className="mt-3 rounded border border-divider px-3 py-1 text-ink-primary hover:bg-bg-card"
          onClick={load}
        >
          Retry
        </button>
      </Centered>
    );
  }

  if (editing) {
    return (
      <TemplateEditor
        initial={editing}
        onCancel={() => setEditing(null)}
        onSave={(t) => {
          persist(upsertUserTemplate(user, t));
          setEditing(null);
        }}
      />
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base text-[calc(13px_*_var(--text-scale))] text-ink-primary">
      <header className="flex items-center justify-between border-b border-divider px-4 py-3">
        <div>
          <div className="text-[calc(14px_*_var(--text-scale))]">Templates</div>
          <div className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">
            Reusable finding &amp; playbook templates — create once, instantiate many.
          </div>
        </div>
        <div className="flex gap-2">
          <button
            className="rounded border border-divider px-2.5 py-1 text-[calc(12px_*_var(--text-scale))] hover:bg-bg-card"
            onClick={() => setEditing(blankTemplate("finding"))}
          >
            + Finding template
          </button>
          <button
            className="rounded border border-divider px-2.5 py-1 text-[calc(12px_*_var(--text-scale))] hover:bg-bg-card"
            onClick={() => setEditing(blankTemplate("playbook"))}
          >
            + Playbook template
          </button>
        </div>
      </header>

      {!activeId && (
        <div className="border-b border-divider bg-bg-card px-4 py-2 text-[calc(12px_*_var(--text-scale))] text-medium">
          No active engagement pinned. Instantiating a finding is disabled — pin
          an engagement to write findings into the model.
        </div>
      )}
      {flash && (
        <div className="border-b border-divider bg-bg-card px-4 py-2 text-[calc(12px_*_var(--text-scale))] text-success">
          {flash}
        </div>
      )}
      {error && (
        <div className="border-b border-divider bg-bg-card px-4 py-2 text-[calc(12px_*_var(--text-scale))] text-critical">
          {error}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto p-4">
        {all.length === 0 ? (
          <Centered>
            No templates yet — create one with the buttons above.
          </Centered>
        ) : (
          <ul className="flex flex-col gap-2">
            {all.map((t) => (
              <TemplateRow
                key={t.id}
                template={t}
                hasEngagement={!!activeId}
                onEdit={() => setEditing(t)}
                onDelete={() => onDelete(t.id)}
                onInstantiate={() =>
                  t.kind === "finding"
                    ? onInstantiateFinding(t)
                    : onInstantiatePlaybook(t)
                }
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center gap-1 bg-bg-base p-8 text-center text-[calc(13px_*_var(--text-scale))] text-ink-muted">
      {children}
    </div>
  );
}

// ── one template row ─────────────────────────────────────────────────────────

function TemplateRow({
  template, hasEngagement, onEdit, onDelete, onInstantiate,
}: {
  template: Template;
  hasEngagement: boolean;
  onEdit: () => void;
  onDelete: () => void;
  onInstantiate: () => void;
}) {
  const isBuiltin = template.builtin === true;
  const isFinding = template.kind === "finding";
  const title = isFinding ? (template as FindingTemplate).title : (template as PlaybookTemplate).name;
  const desc = template.description;

  return (
    <li className="rounded-lg border border-divider bg-bg-card p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate text-ink-primary">{title}</span>
            <span className="rounded border border-divider px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
              {template.kind}
            </span>
            {isFinding && <SeverityBadge severity={(template as FindingTemplate).severity} />}
            {isBuiltin && (
              <span className="rounded border border-divider px-1.5 py-0.5 text-[calc(10px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">
                built-in
              </span>
            )}
          </div>
          {desc && (
            <p className="mt-1 line-clamp-2 text-[calc(12px_*_var(--text-scale))] text-ink-muted">
              {desc}
            </p>
          )}
          {template.kind === "playbook" && (
            <div className="mt-1 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
              {(template as PlaybookTemplate).steps.length} step
              {(template as PlaybookTemplate).steps.length === 1 ? "" : "s"}
            </div>
          )}
          {isFinding && (template as FindingTemplate).cvssVector && (
            <div className="mt-1 font-mono text-[calc(10px_*_var(--text-scale))] text-ink-dim break-all">
              {(template as FindingTemplate).cvssVector}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {isFinding ? (
            <button
              className="rounded bg-accent px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-bg-base disabled:cursor-not-allowed disabled:opacity-40"
              disabled={!hasEngagement}
              title={hasEngagement ? "Create a finding in the active engagement" : "Pin an engagement first"}
              onClick={onInstantiate}
            >
              Instantiate
            </button>
          ) : (
            <button
              className="rounded border border-divider px-2 py-1 text-[calc(11px_*_var(--text-scale))] hover:bg-bg-base"
              title="Open a declarative playbook draft (no server playbook is created)"
              onClick={onInstantiate}
            >
              Open draft
            </button>
          )}
          {!isBuiltin && (
            <>
              <button
                className="rounded border border-divider px-2 py-1 text-[calc(11px_*_var(--text-scale))] hover:bg-bg-base"
                onClick={onEdit}
              >
                Edit
              </button>
              <button
                className="rounded border border-divider px-2 py-1 text-[calc(11px_*_var(--text-scale))] text-critical hover:bg-bg-base"
                onClick={onDelete}
              >
                Delete
              </button>
            </>
          )}
        </div>
      </div>
    </li>
  );
}

// ── editor ───────────────────────────────────────────────────────────────────

function blankTemplate(kind: "finding" | "playbook"): Template {
  if (kind === "finding") {
    return {
      id: newUserId("finding"), kind: "finding", title: "", severity: "medium",
      cvssVector: "", description: "", remediation: "", references: [],
    };
  }
  return { id: newUserId("playbook"), kind: "playbook", name: "", description: "", steps: [] };
}

function TemplateEditor({
  initial, onSave, onCancel,
}: {
  initial: Template;
  onSave: (t: Template) => void;
  onCancel: () => void;
}) {
  const [draft, setDraft] = useState<Template>(initial);
  const [errors, setErrors] = useState<string[]>([]);

  const set = (patch: Partial<Template>) => setDraft((d) => ({ ...d, ...patch } as Template));

  const save = () => {
    // Validate through the SAME store gate the load path uses — rejects markup /
    // executable content, invalid CVSS, bad severity before it can be persisted.
    const res = validateTemplate(draft);
    if (!res.ok) {
      setErrors(res.errors);
      return;
    }
    onSave(res.template);
  };

  const field = "w-full rounded border border-divider bg-bg-base px-2 py-1 text-ink-primary outline-none focus:border-accent";
  const labelCls = "text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim";

  return (
    <div className="flex h-full min-h-0 flex-col bg-bg-base text-[calc(13px_*_var(--text-scale))] text-ink-primary">
      <header className="flex items-center justify-between border-b border-divider px-4 py-3">
        <div className="text-[calc(14px_*_var(--text-scale))]">
          {initial.builtin ? "Duplicate" : (draft as any).title || (draft as any).name ? "Edit" : "New"}{" "}
          {draft.kind} template
        </div>
        <div className="flex gap-2">
          <button className="rounded border border-divider px-2.5 py-1 text-[calc(12px_*_var(--text-scale))] hover:bg-bg-card" onClick={onCancel}>
            Cancel
          </button>
          <button className="rounded bg-accent px-3 py-1 text-[calc(12px_*_var(--text-scale))] text-bg-base" onClick={save}>
            Save
          </button>
        </div>
      </header>

      {errors.length > 0 && (
        <div className="border-b border-divider bg-bg-card px-4 py-2 text-[calc(12px_*_var(--text-scale))] text-critical">
          <ul className="list-disc pl-4">
            {errors.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      <div className="min-h-0 flex-1 space-y-3 overflow-auto p-4">
        {draft.kind === "finding" ? (
          <>
            <label className="block space-y-1">
              <span className={labelCls}>Title</span>
              <input className={field} value={(draft as FindingTemplate).title}
                onChange={(e) => set({ title: e.target.value } as any)} />
            </label>
            <label className="block space-y-1">
              <span className={labelCls}>Severity</span>
              <select className={field} value={(draft as FindingTemplate).severity}
                onChange={(e) => set({ severity: e.target.value as FindingSeverity } as any)}>
                {FINDING_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <label className="block space-y-1">
              <span className={labelCls}>CVSS v3.1 vector (optional)</span>
              <input className={`${field} font-mono`} placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                value={(draft as FindingTemplate).cvssVector}
                onChange={(e) => set({ cvssVector: e.target.value } as any)} />
            </label>
            <label className="block space-y-1">
              <span className={labelCls}>Description</span>
              <textarea className={`${field} min-h-[80px]`} value={(draft as FindingTemplate).description}
                onChange={(e) => set({ description: e.target.value } as any)} />
            </label>
            <label className="block space-y-1">
              <span className={labelCls}>Remediation</span>
              <textarea className={`${field} min-h-[60px]`} value={(draft as FindingTemplate).remediation}
                onChange={(e) => set({ remediation: e.target.value } as any)} />
            </label>
            <label className="block space-y-1">
              <span className={labelCls}>References (one per line)</span>
              <textarea className={`${field} min-h-[60px]`}
                value={(draft as FindingTemplate).references.join("\n")}
                onChange={(e) => set({ references: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) } as any)} />
            </label>
          </>
        ) : (
          <>
            <label className="block space-y-1">
              <span className={labelCls}>Name</span>
              <input className={field} value={(draft as PlaybookTemplate).name}
                onChange={(e) => set({ name: e.target.value } as any)} />
            </label>
            <label className="block space-y-1">
              <span className={labelCls}>Description</span>
              <textarea className={`${field} min-h-[60px]`} value={(draft as PlaybookTemplate).description}
                onChange={(e) => set({ description: e.target.value } as any)} />
            </label>
            <label className="block space-y-1">
              <span className={labelCls}>Steps (one per line — labels only, no commands)</span>
              <textarea className={`${field} min-h-[140px]`}
                value={(draft as PlaybookTemplate).steps.join("\n")}
                onChange={(e) => set({ steps: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) } as any)} />
            </label>
          </>
        )}
      </div>
    </div>
  );
}

// ── registration (runs at import) ────────────────────────────────────────────
registerView({ id: "templates", component: TemplatesPanel });
registerCommand({
  id: "templates.open",
  title: "Open Templates",
  keywords: ["template", "finding", "playbook", "reuse"],
  context: "View",
  run: () => emit("openView", { view: "templates" }),
});
