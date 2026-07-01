// Typed engagement-create flow.
//
// The engagement *type* decides what it hooks onto and which fields it
// collects (see backend EngagementCreate):
//
//   local-app — a codebase/folder. Collects a directory to hook onto
//               (validated server-side: must exist + be readable). Becomes
//               the engagement's source root.
//   web-app   — a running site. Collects target URL(s) + optional auth
//               (session cookie / bearer token / login credentials). The
//               first URL becomes the primary target. Auth is sent once,
//               encrypted server-side, and never shown again — the form
//               only ever displays a redacted reference afterwards.
//
// Common to both: name, provenance (lab | owned | external — drives the
// safety mode), and optional scope notes.
//
// On success the caller (HomeView) pins the new engagement active, sets its
// primary target / source root as the default target for tools, and opens a
// window pinned to it (?engagement=<id>).

import { useState } from "react";
import {
  createEngagement,
  type CreatedEngagement,
  type EngagementProvenance,
  type AuthKind,
} from "../lib/engagement";

type EngType = "local-app" | "web-app";

const PROVENANCE_HINT: Record<EngagementProvenance, string> = {
  lab: "Sandbox / training target. Active tools run freely.",
  owned: "You own or operate this. Full mode.",
  external: "Third-party target. Defensive / gated — active runs need an attestation.",
};

const AUTH_KINDS: { value: AuthKind; label: string; hint: string }[] = [
  { value: "none", label: "None", hint: "Unauthenticated." },
  { value: "cookie", label: "Session cookie", hint: "A Cookie header to replay." },
  { value: "bearer", label: "Bearer token", hint: "A token replayed as Authorization: Bearer." },
  { value: "credentials", label: "Login credentials", hint: "Username + password for a login flow." },
];

const inputCls =
  "mt-1 w-full rounded bg-bg-base px-2 py-1.5 text-sm text-ink-primary " +
  "outline-none ring-1 ring-divider focus:ring-accent placeholder:text-ink-dim";

export default function NewEngagementModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (e: CreatedEngagement) => void;
}) {
  const [type, setType] = useState<EngType>("web-app");
  const [name, setName] = useState("");
  const [provenance, setProvenance] = useState<EngagementProvenance>("owned");
  const [notes, setNotes] = useState("");

  // local-app
  const [sourceRoot, setSourceRoot] = useState("");

  // web-app
  const [urls, setUrls] = useState<string[]>([""]);
  const [authKind, setAuthKind] = useState<AuthKind>("none");
  const [cookie, setCookie] = useState("");
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loginUrl, setLoginUrl] = useState("");

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  if (!open) return null;

  const canBrowse = typeof (window as any).nt?.pickDirectory === "function";

  function reset() {
    setType("web-app"); setName(""); setProvenance("owned"); setNotes("");
    setSourceRoot(""); setUrls([""]); setAuthKind("none");
    setCookie(""); setToken(""); setUsername(""); setPassword(""); setLoginUrl("");
    setErr("");
  }

  function close() { reset(); onClose(); }

  async function browse() {
    try {
      const picked = await (window as any).nt.pickDirectory();
      if (picked) setSourceRoot(picked);
    } catch { /* user cancelled / no picker */ }
  }

  async function submit() {
    const trimmedName = name.trim();
    if (!trimmedName) { setErr("Give the engagement a name."); return; }

    const payload: Parameters<typeof createEngagement>[0] = {
      name: trimmedName,
      type,
      provenance,
      notes: notes.trim(),
    };

    if (type === "local-app") {
      if (!sourceRoot.trim()) {
        setErr("Choose a directory to hook onto.");
        return;
      }
      payload.source_root = sourceRoot.trim();
    } else {
      const cleaned = urls.map((u) => u.trim()).filter(Boolean);
      if (!cleaned.length) {
        setErr("Add at least one target URL.");
        return;
      }
      payload.targets = cleaned;
      if (authKind !== "none") {
        payload.auth = {
          kind: authKind,
          ...(authKind === "cookie" ? { cookie } : {}),
          ...(authKind === "bearer" ? { token } : {}),
          ...(authKind === "credentials"
            ? { username, password, login_url: loginUrl.trim() }
            : {}),
        };
      }
    }

    setBusy(true);
    setErr("");
    try {
      const created = await createEngagement(payload);
      onCreated(created);
      reset();
    } catch (e: any) {
      // Server-side validation (bad path / invalid URL) surfaces here.
      setErr(e?.message || "Failed to create engagement.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={close}
    >
      <div
        className="max-h-[88vh] w-[40rem] overflow-y-auto rounded-lg bg-bg-card p-5 shadow-2xl ring-1 ring-divider"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 text-sm font-semibold text-ink-primary">New engagement</div>
        <p className="mb-4 text-xs text-ink-dim">
          The type decides what this engagement hooks onto and what it collects.
        </p>

        {/* ── Type selector ─────────────────────────────────────────── */}
        <div className="mb-4 grid grid-cols-2 gap-2">
          <TypeCard
            active={type === "local-app"}
            onClick={() => setType("local-app")}
            title="Local codebase"
            sub="A folder to review / fix in place"
          />
          <TypeCard
            active={type === "web-app"}
            onClick={() => setType("web-app")}
            title="Web application"
            sub="A running site, optionally authenticated"
          />
        </div>
        <div className="mb-4 text-[calc(10px_*_var(--text-scale))] text-ink-dim">
          <span className="rounded border border-divider px-1.5 py-0.5 opacity-60">
            Host target — coming soon
          </span>
        </div>

        {/* ── Common: name ──────────────────────────────────────────── */}
        <label className="mb-3 block text-xs text-ink-muted">
          Name
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="ACME Q3 web assessment"
            spellCheck={false}
            className={inputCls}
            autoFocus
          />
        </label>

        {/* ── Common: provenance ───────────────────────────────────── */}
        <div className="mb-1 text-xs text-ink-muted">Provenance</div>
        <div className="mb-1 flex gap-1.5">
          {(["lab", "owned", "external"] as EngagementProvenance[]).map((p) => (
            <button
              key={p}
              onClick={() => setProvenance(p)}
              className={
                "flex-1 rounded px-2 py-1.5 text-xs font-medium capitalize ring-1 transition-colors " +
                (provenance === p
                  ? "bg-accent text-bg-base ring-accent"
                  : "bg-bg-base text-ink-muted ring-divider hover:text-ink-primary")
              }
            >
              {p}
            </button>
          ))}
        </div>
        <p className="mb-4 text-[calc(11px_*_var(--text-scale))] text-ink-dim">{PROVENANCE_HINT[provenance]}</p>

        {/* ── Branch: local-app ─────────────────────────────────────── */}
        {type === "local-app" && (
          <label className="mb-3 block text-xs text-ink-muted">
            Source directory <span className="text-ink-dim">(must exist &amp; be readable)</span>
            <div className="mt-1 flex gap-2">
              <input
                value={sourceRoot}
                onChange={(e) => setSourceRoot(e.target.value)}
                placeholder="/Users/you/code/project"
                spellCheck={false}
                className={inputCls + " mt-0 font-mono"}
              />
              {canBrowse && (
                <button
                  onClick={browse}
                  className="shrink-0 rounded bg-bg-base px-3 text-xs text-ink-muted ring-1 ring-divider hover:text-ink-primary"
                >
                  Browse…
                </button>
              )}
            </div>
          </label>
        )}

        {/* ── Branch: web-app ───────────────────────────────────────── */}
        {type === "web-app" && (
          <>
            <div className="mb-1 text-xs text-ink-muted">
              Target URL(s) <span className="text-ink-dim">(first is the primary target)</span>
            </div>
            <div className="mb-3 space-y-1.5">
              {urls.map((u, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    value={u}
                    onChange={(e) =>
                      setUrls((arr) => arr.map((x, j) => (j === i ? e.target.value : x)))
                    }
                    placeholder="https://app.example.com"
                    spellCheck={false}
                    className={inputCls + " mt-0 font-mono"}
                  />
                  {urls.length > 1 && (
                    <button
                      onClick={() => setUrls((arr) => arr.filter((_, j) => j !== i))}
                      className="shrink-0 rounded px-2 text-ink-dim hover:text-danger"
                      aria-label="remove URL"
                    >
                      ✕
                    </button>
                  )}
                </div>
              ))}
              <button
                onClick={() => setUrls((arr) => [...arr, ""])}
                className="text-[calc(11px_*_var(--text-scale))] text-accent hover:underline"
              >
                + Add URL
              </button>
            </div>

            {/* Auth */}
            <div className="mb-1 text-xs text-ink-muted">Authentication (optional)</div>
            <select
              value={authKind}
              onChange={(e) => setAuthKind(e.target.value as AuthKind)}
              className={inputCls}
            >
              {AUTH_KINDS.map((k) => (
                <option key={k.value} value={k.value}>{k.label}</option>
              ))}
            </select>
            <p className="mt-1 text-[calc(11px_*_var(--text-scale))] text-ink-dim">
              {AUTH_KINDS.find((k) => k.value === authKind)?.hint}
            </p>

            {authKind !== "none" && (
              <p className="mt-1 text-[calc(11px_*_var(--text-scale))] text-amber">
                Stored encrypted and scoped to this engagement's target only. It is
                never shown again — only a redacted reference.
              </p>
            )}

            {authKind === "cookie" && (
              <label className="mt-2 block text-xs text-ink-muted">
                Cookie header
                <input
                  value={cookie}
                  onChange={(e) => setCookie(e.target.value)}
                  placeholder="session=abc123; csrf=…"
                  spellCheck={false}
                  className={inputCls + " font-mono"}
                />
              </label>
            )}
            {authKind === "bearer" && (
              <label className="mt-2 block text-xs text-ink-muted">
                Bearer token
                <input
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="eyJhbGciOi…"
                  spellCheck={false}
                  className={inputCls + " font-mono"}
                />
              </label>
            )}
            {authKind === "credentials" && (
              <div className="mt-2 space-y-2">
                <label className="block text-xs text-ink-muted">
                  Username
                  <input value={username} onChange={(e) => setUsername(e.target.value)}
                    spellCheck={false} className={inputCls} />
                </label>
                <label className="block text-xs text-ink-muted">
                  Password
                  <input type="password" value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className={inputCls} />
                </label>
                <label className="block text-xs text-ink-muted">
                  Login URL <span className="text-ink-dim">(optional)</span>
                  <input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)}
                    placeholder="https://app.example.com/login"
                    spellCheck={false} className={inputCls + " font-mono"} />
                </label>
              </div>
            )}
            <div className="mb-3" />
          </>
        )}

        {/* ── Common: scope notes ───────────────────────────────────── */}
        <label className="mb-3 block text-xs text-ink-muted">
          Scope notes <span className="text-ink-dim">(optional)</span>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={2}
            placeholder="Rules of engagement, out-of-scope reminders…"
            className={inputCls}
          />
        </label>

        {err && <div className="mb-2 text-xs text-danger">⚠ {err}</div>}

        <div className="flex justify-end gap-2">
          <button
            onClick={close}
            className="rounded px-3 py-1.5 text-sm text-ink-muted hover:text-ink-primary"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy}
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-bg-base hover:bg-accentBright disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create engagement"}
          </button>
        </div>
      </div>
    </div>
  );
}

function TypeCard({
  active, onClick, title, sub,
}: {
  active: boolean; onClick: () => void; title: string; sub: string;
}) {
  return (
    <button
      onClick={onClick}
      className={
        "rounded-lg border p-3 text-left transition-colors " +
        (active
          ? "border-accent bg-accent/10"
          : "border-divider bg-bg-base hover:border-accent/50")
      }
    >
      <div className="text-[calc(13px_*_var(--text-scale))] font-semibold text-ink-primary">{title}</div>
      <div className="mt-0.5 text-[calc(11px_*_var(--text-scale))] text-ink-dim">{sub}</div>
    </button>
  );
}
