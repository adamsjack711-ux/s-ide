import { useEffect, useMemo, useRef, useState } from "react";
import type { SideTheme } from "../themes/sideSchema";
import { PROTECTED_TOKENS } from "../themes/sideSchema";
import { validateSide } from "../themes/validate";
import { setSideTheme } from "../lib/theme";
import type { ResolveResult } from "../themes/api";

/**
 * Mandatory preview before any non-bundled theme is applied. Shows the theme's
 * source/version/hash + trust status, swatches, and a per-token diff vs the
 * currently-applied values. Apply happens only on explicit confirm and always
 * re-validates (setSideTheme → applySide is the authoritative gate).
 */
export default function ThemePreviewModal({
  theme,
  meta,
  onClose,
  onApplied,
}: {
  theme: SideTheme;
  meta: ResolveResult;
  onClose: () => void;
  onApplied: () => void;
}) {
  const [err, setErr] = useState<string[]>([]);
  const dialogRef = useRef<HTMLDivElement>(null);
  const applyRef = useRef<HTMLButtonElement>(null);

  // Re-validate here too so the preview can warn before the user commits.
  const validation = useMemo(() => validateSide(theme), [theme]);

  const current = (token: string): string => {
    if (typeof document === "undefined") return "";
    return getComputedStyle(document.documentElement).getPropertyValue(token).trim();
  };

  const rows = Object.entries(theme.theme).filter(([k]) => k.startsWith("--") && /^#|[A-Za-z]/.test(theme.theme[k]));

  function apply() {
    const res = setSideTheme(theme);
    if (res.ok) onApplied();
    else setErr(res.errors);
  }

  // Keyboard: Esc closes, Enter applies (only when the validator gate allows),
  // Tab is trapped within the dialog. Apply gets initial focus.
  useEffect(() => {
    applyRef.current?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === "Enter") {
        // Don't hijack Enter inside a textarea (none here today, but cheap).
        if ((e.target as HTMLElement)?.tagName === "TEXTAREA") return;
        if (validation.ok) {
          e.preventDefault();
          apply();
        }
        return;
      }
      if (e.key === "Tab") {
        const root = dialogRef.current;
        if (!root) return;
        const focusable = root.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const activeEl = document.activeElement as HTMLElement | null;
        if (e.shiftKey && (activeEl === first || !root.contains(activeEl))) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && activeEl === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
    // apply/onClose are stable enough for this modal's lifetime; re-bind only
    // when validity flips so Enter's gate stays correct.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [validation.ok]);

  const protectedSet = new Set(PROTECTED_TOKENS);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6" onClick={onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Preview theme ${theme.name}`}
        className="flex max-h-[85vh] w-[560px] flex-col overflow-hidden rounded-xl border border-divider bg-bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header + trust line. */}
        <div className="border-b border-divider px-5 py-3.5">
          <div className="flex items-center gap-2">
            <span className="text-[15px] font-bold text-ink-primary">{theme.name}</span>
            <span className="text-[11px] text-ink-dim">v{theme.version}</span>
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                meta.official ? "bg-accent/15 text-accent" : "bg-bg-base text-ink-muted ring-1 ring-divider"
              }`}
            >
              {meta.official ? "official" : "community"}
            </span>
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                meta.verified ? "bg-success/15 text-success" : "bg-medium/15 text-medium"
              }`}
              title={meta.source === "tofu" ? "First fetch — hash pinned now (trust on first use)" : "Hash matches the pinned/curated value"}
            >
              {meta.verified ? "verified" : "first-use (TOFU)"}
            </span>
          </div>
          <div className="mt-1 truncate font-mono text-[11px] text-ink-dim" title={meta.url}>{meta.url}</div>
          <div className="mt-0.5 font-mono text-[10px] text-ink-dim">{meta.hash}</div>
        </div>

        {/* Validator warnings (a fetched-from-cache file shouldn't fail, but be loud if it does). */}
        {!validation.ok && (
          <div className="border-b border-divider bg-danger/10 px-5 py-2 text-[11px] text-danger">
            {validation.errors.map((e, i) => <div key={i}>⚠ {e}</div>)}
          </div>
        )}

        {/* Token diff + swatches. */}
        <div className="min-h-0 flex-1 overflow-auto px-5 py-3">
          <div className="mb-2 text-[10px] uppercase tracking-wide text-ink-dim">Token changes</div>
          <div className="flex flex-col gap-1">
            {rows.map(([token, next]) => {
              const cur = current(token);
              const changed = cur && cur.toLowerCase() !== next.toLowerCase();
              const isHex = /^#/.test(next);
              return (
                <div key={token} className="flex items-center gap-2 text-[11.5px]">
                  {protectedSet.has(token) && <span className="h-1.5 w-1.5 rounded-full bg-accent" title="protected semantic token" />}
                  <span className={`font-mono ${protectedSet.has(token) ? "text-ink-primary" : "text-ink-muted"}`}>{token}</span>
                  <span className="ml-auto flex items-center gap-1.5">
                    {cur && (
                      <>
                        <span className="inline-block h-3.5 w-3.5 rounded-sm border border-divider" style={{ background: cur }} />
                        <span className="font-mono text-[10px] text-ink-dim">{cur || "—"}</span>
                        <span className="text-ink-dim">→</span>
                      </>
                    )}
                    {isHex && <span className="inline-block h-3.5 w-3.5 rounded-sm border border-divider" style={{ background: next }} />}
                    <span className={`font-mono text-[10px] ${changed ? "text-accent" : "text-ink-muted"}`}>{next}</span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {err.length > 0 && (
          <div className="border-t border-divider bg-danger/10 px-5 py-2 text-[11px] text-danger">
            {err.map((e, i) => <div key={i}>⚠ {e}</div>)}
          </div>
        )}

        {/* Actions. */}
        <div className="flex items-center justify-end gap-2 border-t border-divider px-5 py-3">
          <button onClick={onClose} className="rounded-md px-3 py-1.5 text-[12px] text-ink-muted hover:text-ink-primary">Cancel</button>
          <button
            ref={applyRef}
            onClick={apply}
            disabled={!validation.ok}
            className="rounded-md bg-accent px-3.5 py-1.5 text-[12px] font-semibold text-bg-base hover:brightness-110 disabled:opacity-40"
          >
            Apply theme
          </button>
        </div>
      </div>
    </div>
  );
}
