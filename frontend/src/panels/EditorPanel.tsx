import { useCallback, useEffect, useState } from "react";
import Editor from "@monaco-editor/react";
import { authFetch, parseError } from "../api";

/**
 * Fix-in-place editor — opens a file from the lab container in Monaco, edits
 * it, and writes it back through `/labfs/{labId}/*` (routers/labfs.py).
 *
 * Mounted by the integrator as a dockview panel (see the integration note in
 * the stage summary), but it works standalone as a plain controlled component
 * given `{labId, path}` props.
 */

export interface EditorPanelProps {
  labId: string;
  path: string;
}

type Status =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "loaded" }
  | { kind: "saving" }
  | { kind: "saved" }
  | { kind: "error"; message: string };

/** Best-effort Monaco language from the file extension. */
function languageForPath(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    php: "php", js: "javascript", jsx: "javascript", mjs: "javascript",
    ts: "typescript", tsx: "typescript", py: "python", rb: "ruby",
    go: "go", java: "java", c: "c", h: "c", cpp: "cpp", cs: "csharp",
    sh: "shell", bash: "shell", json: "json", yml: "yaml", yaml: "yaml",
    xml: "xml", html: "html", htm: "html", css: "css", scss: "scss",
    sql: "sql", md: "markdown", ini: "ini", conf: "ini", toml: "ini",
  };
  return map[ext] ?? "plaintext";
}

export default function EditorPanel({ labId, path }: EditorPanelProps) {
  const [content, setContent] = useState<string>("");
  const [dirty, setDirty] = useState(false);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  const load = useCallback(async () => {
    setStatus({ kind: "loading" });
    try {
      const res = await authFetch(
        `/labfs/${encodeURIComponent(labId)}/read?path=${encodeURIComponent(path)}`,
      );
      if (!res.ok) {
        setStatus({ kind: "error", message: await parseError(res) });
        return;
      }
      const body = (await res.json()) as { path: string; content: string; rc: number };
      setContent(body.content ?? "");
      setDirty(false);
      if (body.rc !== 0) {
        setStatus({ kind: "error", message: `read failed (rc ${body.rc})` });
      } else {
        setStatus({ kind: "loaded" });
      }
    } catch (e) {
      setStatus({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, [labId, path]);

  useEffect(() => { void load(); }, [load]);

  const save = useCallback(async () => {
    setStatus({ kind: "saving" });
    try {
      const res = await authFetch(`/labfs/${encodeURIComponent(labId)}/write`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, content }),
      });
      if (!res.ok) {
        setStatus({ kind: "error", message: await parseError(res) });
        return;
      }
      const body = (await res.json()) as {
        path: string; rc: number; written: boolean; note?: string | null;
      };
      if (body.written) {
        setDirty(false);
        setStatus({ kind: "saved" });
      } else {
        setStatus({ kind: "error", message: body.note ?? `write failed (rc ${body.rc})` });
      }
    } catch (e) {
      setStatus({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, [labId, path, content]);

  return (
    <div className="flex h-full flex-col bg-bg-base">
      <div className="flex items-center gap-3 border-b border-divider px-3 py-1.5">
        <span className="font-mono text-xs text-ink-muted">{labId}</span>
        <span className="text-ink-dim">/</span>
        <span className="truncate font-mono text-xs text-ink-primary" title={path}>
          {path}
        </span>
        {dirty && <span className="text-amber" title="unsaved changes">●</span>}
        <div className="ml-auto flex items-center gap-2">
          <StatusBadge status={status} />
          <button
            type="button"
            onClick={() => void load()}
            disabled={status.kind === "loading" || status.kind === "saving"}
            className="rounded border border-divider px-2 py-0.5 text-xs text-ink-muted hover:bg-bg-hover disabled:opacity-40"
          >
            Reload
          </button>
          <button
            type="button"
            onClick={() => void save()}
            disabled={!dirty || status.kind === "saving" || status.kind === "loading"}
            className="rounded bg-accent px-3 py-0.5 text-xs text-bg-base hover:bg-accentBright disabled:opacity-40"
          >
            {status.kind === "saving" ? "Saving…" : "Save"}
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1">
        <Editor
          height="100%"
          theme="vs-dark"
          path={`${labId}/${path}`}
          language={languageForPath(path)}
          value={content}
          onChange={(v) => {
            setContent(v ?? "");
            setDirty(true);
            if (status.kind === "saved" || status.kind === "loaded") {
              setStatus({ kind: "idle" });
            }
          }}
          options={{
            fontSize: 12,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            automaticLayout: true,
            tabSize: 2,
          }}
        />
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: Status }) {
  switch (status.kind) {
    case "loading":
      return <span className="text-xs text-ink-dim">Loading…</span>;
    case "saving":
      return <span className="text-xs text-ink-dim">Saving…</span>;
    case "saved":
      return <span className="text-xs text-success">Saved</span>;
    case "loaded":
      return <span className="text-xs text-ink-dim">Loaded</span>;
    case "error":
      return (
        <span className="max-w-[24rem] truncate text-xs text-danger" title={status.message}>
          {status.message}
        </span>
      );
    default:
      return null;
  }
}
