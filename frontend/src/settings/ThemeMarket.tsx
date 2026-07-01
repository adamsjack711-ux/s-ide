import { useEffect, useRef, useState } from "react";
import {
  addSource,
  fetchThemeFile,
  getManifest,
  removeSource,
  resolveTheme,
  TamperError,
  type ManifestEntry,
  type ResolveResult,
} from "../themes/api";
import type { SideTheme } from "../themes/sideSchema";
import { BUILTIN_THEMES } from "../themes/builtins";
import { clearSideTheme, getSideTheme } from "../lib/theme";
import { validateSide } from "../themes/validate";
import { notify } from "../shell/toast";
import ThemePreviewModal from "./ThemePreviewModal";
import ThemeMiniPreview from "./ThemeMiniPreview";

// Bundled themes resolve locally — no fetch — so they get a synthetic,
// already-verified meta for the shared preview modal.
function builtinMeta(t: SideTheme): ResolveResult {
  return { url: `builtin://${t.name}`, version: t.version, hash: "bundled", official: true, source: "locked", verified: true, name: t.name };
}

// A theme loaded from a local .side file has no remote source/hash — give it a
// synthetic meta so the shared preview modal can present + apply it. The modal
// re-validates on confirm regardless (apply.ts is the authoritative gate).
function localFileMeta(t: SideTheme, filename: string): ResolveResult {
  return { url: `file://${filename}`, version: t.version, hash: "local file", official: false, source: "tofu", verified: false, name: t.name };
}

// One-time breadcrumb (set by lib/theme.ts boot path when a persisted custom
// theme fails re-validation and is dropped). We surface it once here so the
// removal isn't silent. Read-and-clear so it shows exactly once.
const DROPPED_KEY = "s-ide:side-theme-dropped";

/**
 * Decentralized theme manager. Themes are identified by source URL (git repo or
 * raw .side). There is no upload server and no name registry — identity is the
 * URL. Add a source, then Preview (resolves the latest/pinned version, verifies
 * the TOFU hash server-side) → the mandatory preview modal applies on confirm.
 */
export default function ThemeMarket() {
  const [sources, setSources] = useState<ManifestEntry[]>([]);
  const [defaultUrl, setDefaultUrl] = useState("");
  const [url, setUrl] = useState("");
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState<SideTheme | null>(() => getSideTheme());
  const [preview, setPreview] = useState<{ theme: SideTheme; meta: ResolveResult } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Surface a one-time notice if a persisted custom theme was dropped on boot
  // because it no longer validates (the boot path removes it silently).
  useEffect(() => {
    let dropped: string | null = null;
    try {
      dropped = sessionStorage.getItem(DROPPED_KEY);
      if (dropped) sessionStorage.removeItem(DROPPED_KEY);
    } catch { /* ignore */ }
    if (dropped) {
      notify({
        kind: "info",
        message: `Custom theme "${dropped}" was removed — it no longer passes validation. Reverted to the bundled theme.`,
        duration: 8000,
      });
    }
  }, []);

  async function refresh() {
    try {
      const m = await getManifest();
      setSources(m.themes);
      setDefaultUrl(m.default_manifest_url);
    } catch (e: any) {
      setError(e?.message ?? "failed to load manifest");
    }
  }
  useEffect(() => { void refresh(); }, []);

  async function add() {
    const u = url.trim();
    const v = version.trim() || undefined;
    if (!u) return;
    setBusy("add");
    setError(null);
    try {
      const m = await addSource(u, v);
      setSources(m.themes);
      setUrl("");
      setVersion("");
      // Don't make the user hunt for "Preview" — resolve + open it now.
      const added = m.themes.find((s) => s.url === u) ?? { url: u, version: v, official: false };
      void doPreview(added as ManifestEntry);
    } catch (e: any) {
      setError(e?.message ?? "failed to add source");
    } finally {
      setBusy(null);
    }
  }

  // Local .side import: read the file, validate it with the same gate used at
  // fetch/apply, then open the shared preview modal (apply on explicit confirm).
  async function importFile(file: File) {
    setError(null);
    try {
      const text = await file.text();
      let obj: unknown;
      try {
        obj = JSON.parse(text);
      } catch {
        setError(`${file.name} is not valid JSON.`);
        return;
      }
      const res = validateSide(obj);
      if (!res.ok || !res.theme) {
        setError(`${file.name} failed validation: ${res.errors.join("; ")}`);
        return;
      }
      setPreview({ theme: res.theme, meta: localFileMeta(res.theme, file.name) });
    } catch (e: any) {
      setError(e?.message ?? "failed to read file");
    }
  }

  function onFilePicked(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = ""; // allow re-picking the same file
    if (f) void importFile(f);
  }

  async function doPreview(entry: ManifestEntry) {
    setBusy(entry.url);
    setError(null);
    try {
      const meta = await resolveTheme(entry.url, entry.version);
      const theme = await fetchThemeFile(meta.url, meta.version);
      setPreview({ theme, meta });
    } catch (e: any) {
      if (e instanceof TamperError) {
        setError(`⚠ Tamper detected for ${e.info.url}@${e.info.version}: the content of an immutable version changed. Refusing to apply.`);
      } else {
        setError(e?.message ?? "failed to resolve theme");
      }
    } finally {
      setBusy(null);
    }
  }

  async function remove(u: string) {
    setBusy(u);
    try {
      const m = await removeSource(u);
      setSources(m.themes);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-[calc(12px_*_var(--text-scale))] font-semibold text-ink-primary">Theme sources</div>
        {active && (
          <button
            onClick={() => { clearSideTheme(); setActive(null); }}
            className="text-[calc(11px_*_var(--text-scale))] text-ink-muted hover:text-ink-primary"
          >
            Revert to bundled theme
          </button>
        )}
      </div>

      {active && (
        <div className="rounded-md border border-accent/30 bg-accent/[0.08] px-3 py-1.5 text-[calc(11.5px_*_var(--text-scale))] text-ink-primary">
          Active custom theme: <span className="font-semibold">{active.name}</span> <span className="text-ink-dim">v{active.version}</span>
        </div>
      )}

      {/* Bundled gallery — the curated themes that ship with s-ide. */}
      <div>
        <div className="mb-1.5 text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">Bundled</div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {BUILTIN_THEMES.map((t) => (
            <button
              key={t.name}
              onClick={() => setPreview({ theme: t, meta: builtinMeta(t) })}
              title={`Preview ${t.name}`}
              className="group flex flex-col gap-1.5 rounded-lg border border-divider bg-bg-base p-2 text-left hover:border-accent"
            >
              <ThemeMiniPreview theme={t} />
              <div className="flex items-center justify-between px-0.5">
                <span className="text-[calc(12px_*_var(--text-scale))] font-semibold text-ink-primary">{t.name}</span>
                {active?.name === t.name && <span className="h-1.5 w-1.5 rounded-full bg-accent" title="active" />}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Add a remote source. */}
      <div className="flex items-center justify-between">
        <div className="text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">Remote sources</div>
        <button
          onClick={() => fileInputRef.current?.click()}
          className="rounded-md border border-divider px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] text-accent hover:border-accent"
          title="Import a .side theme file from disk"
        >
          Import .side file…
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".side"
          onChange={onFilePicked}
          className="hidden"
        />
      </div>
      <div className="flex gap-2">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://github.com/you/your-theme  (git repo or raw .side URL)"
          className="flex-1 rounded-md border border-divider bg-bg-base px-2.5 py-1.5 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent"
        />
        <input
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          placeholder="version (optional)"
          className="w-32 rounded-md border border-divider bg-bg-base px-2.5 py-1.5 text-[calc(12px_*_var(--text-scale))] text-ink-primary outline-none focus:border-accent"
        />
        <button
          onClick={add}
          disabled={busy === "add" || !url.trim()}
          className="rounded-md bg-accent px-3 py-1.5 text-[calc(12px_*_var(--text-scale))] font-semibold text-bg-base hover:brightness-110 disabled:opacity-40"
        >
          Add
        </button>
      </div>

      {error && <div className="rounded-md bg-danger/10 px-3 py-2 text-[calc(11.5px_*_var(--text-scale))] text-danger">{error}</div>}

      {/* Sources list. */}
      <div className="flex flex-col gap-1.5">
        {sources.length === 0 ? (
          <div className="text-[calc(11.5px_*_var(--text-scale))] text-ink-dim">No sources added yet.</div>
        ) : (
          sources.map((s) => (
            <div key={s.url} className="flex items-center gap-2 rounded-md border border-divider bg-bg-base px-3 py-2">
              <span
                className={`rounded-full px-1.5 py-0.5 text-[calc(9px_*_var(--text-scale))] font-semibold uppercase ${
                  s.official ? "bg-accent/15 text-accent" : "bg-bg-card text-ink-muted ring-1 ring-divider"
                }`}
              >
                {s.official ? "official" : "community"}
              </span>
              <div className="min-w-0 flex-1">
                <div className="truncate font-mono text-[calc(11.5px_*_var(--text-scale))] text-ink-primary" title={s.url}>{s.url}</div>
                {s.version && <div className="font-mono text-[calc(10px_*_var(--text-scale))] text-ink-dim">pinned {s.version}</div>}
              </div>
              <button
                onClick={() => doPreview(s)}
                disabled={busy === s.url}
                className="rounded-md border border-divider px-2.5 py-1 text-[calc(11px_*_var(--text-scale))] text-accent hover:border-accent disabled:opacity-50"
              >
                {busy === s.url ? "Resolving…" : "Preview"}
              </button>
              <button onClick={() => remove(s.url)} title="Remove source" className="text-ink-dim hover:text-danger">×</button>
            </div>
          ))
        )}
      </div>

      <div className="text-[calc(10px_*_var(--text-scale))] text-ink-dim">
        Curated default manifest: <span className="font-mono">{defaultUrl || "—"}</span>. Themes are verified on fetch
        (hash-locked, immutable by version) and re-validated on apply. See the README “Creating themes” section.
      </div>

      {preview && (
        <ThemePreviewModal
          theme={preview.theme}
          meta={preview.meta}
          onClose={() => setPreview(null)}
          onApplied={() => {
            setActive(preview.theme);
            setPreview(null);
            notify({ kind: "success", message: `Theme applied — ${preview.theme.name}` });
          }}
        />
      )}
    </div>
  );
}
