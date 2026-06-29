/**
 * Global toast / notification system (Foundation lane).
 *
 * ── CONTRACT FOR OTHER LANES ────────────────────────────────────────────────
 *
 *   import { useToast, notify, type ToastKind } from "../shell/toast";
 *
 * (a) Inside a React component:
 *
 *       const { notify } = useToast();
 *       notify({ kind: "success", message: "Promoted to finding" });
 *
 * (b) Outside React (event handlers, module-level helpers, bus callbacks):
 *
 *       import { notify } from "../shell/toast";
 *       notify({ kind: "error", message: "Scan failed" });
 *
 * Both paths funnel through the same module-level emitter, so a single
 * <ToastProvider> (mounted once in App.tsx) renders every toast regardless of
 * call site.
 *
 *   notify({
 *     kind: "success" | "error" | "info",
 *     message: string,
 *     action?: { label: string, onClick: () => void },
 *     duration?: number,   // ms; default 4000. Pass 0 to require manual dismiss.
 *   }) => string           // returns the toast id (dismiss(id) to close early)
 *
 * Auto-dismisses after ~4s, is manually dismissible (× button), and stacks in
 * the bottom-right corner. Styled strictly from existing design tokens:
 *   success → accent/phos, error → danger/critical, info → border-bright ink.
 * ────────────────────────────────────────────────────────────────────────────
 */
import { useEffect, useState, useCallback } from "react";

export type ToastKind = "success" | "error" | "info";

export type ToastAction = { label: string; onClick: () => void };

export type ToastInput = {
  kind: ToastKind;
  message: string;
  action?: ToastAction;
  /** Auto-dismiss delay in ms. Default 4000; pass 0 to disable auto-dismiss. */
  duration?: number;
};

export type Toast = ToastInput & { id: string; duration: number };

const DEFAULT_DURATION = 4000;

// ── Module-level emitter (so non-component call sites work) ──────────────────
type ToastListener = (toasts: Toast[]) => void;
let toasts: Toast[] = [];
const listeners = new Set<ToastListener>();
let seq = 0;

function publish() {
  for (const l of listeners) l(toasts);
}

/**
 * Imperative entry point — usable anywhere (inside or outside React).
 * Returns the toast id so callers can `dismiss(id)` early.
 */
export function notify(input: ToastInput): string {
  const id = `t${++seq}-${Date.now()}`;
  const toast: Toast = {
    id,
    duration: input.duration ?? DEFAULT_DURATION,
    ...input,
  };
  toasts = [...toasts, toast];
  publish();
  return id;
}

export function dismiss(id: string): void {
  toasts = toasts.filter((t) => t.id !== id);
  publish();
}

function subscribe(fn: ToastListener): () => void {
  listeners.add(fn);
  fn(toasts);
  return () => {
    listeners.delete(fn);
  };
}

/** React hook — returns the imperative API for ergonomic in-component use. */
export function useToast(): { notify: typeof notify; dismiss: typeof dismiss } {
  return { notify, dismiss };
}

// ── Rendering ────────────────────────────────────────────────────────────────

const KIND_RING: Record<ToastKind, string> = {
  success: "ring-accent/40",
  error: "ring-danger/40",
  info: "ring-borderBright",
};

const KIND_BAR: Record<ToastKind, string> = {
  success: "bg-accent",
  error: "bg-danger",
  info: "bg-borderBright",
};

const KIND_ICON: Record<ToastKind, { glyph: string; tint: string }> = {
  success: { glyph: "✓", tint: "text-accent" },
  error: { glyph: "✕", tint: "text-danger" },
  info: { glyph: "ℹ", tint: "text-ink-muted" },
};

function ToastCard({ toast }: { toast: Toast }) {
  useEffect(() => {
    if (!toast.duration) return;
    const h = setTimeout(() => dismiss(toast.id), toast.duration);
    return () => clearTimeout(h);
  }, [toast.id, toast.duration]);

  const icon = KIND_ICON[toast.kind];
  return (
    <div
      role="status"
      className={`animate-in pointer-events-auto flex w-80 items-start gap-2.5 overflow-hidden rounded-lg bg-bg-card pl-0 pr-3 py-2.5 shadow-2xl ring-1 ${KIND_RING[toast.kind]}`}
    >
      <span className={`w-[3px] shrink-0 self-stretch rounded-r ${KIND_BAR[toast.kind]}`} />
      <span className={`mt-px shrink-0 text-sm font-semibold ${icon.tint}`}>{icon.glyph}</span>
      <div className="min-w-0 flex-1">
        <div className="text-sm leading-snug text-ink-primary">{toast.message}</div>
        {toast.action && (
          <button
            onClick={() => {
              toast.action!.onClick();
              dismiss(toast.id);
            }}
            className="mt-1 text-xs font-medium text-accent hover:text-accentBright"
          >
            {toast.action.label}
          </button>
        )}
      </div>
      <button
        onClick={() => dismiss(toast.id)}
        title="Dismiss"
        className="mt-px shrink-0 text-ink-dim hover:text-ink-primary"
      >
        ×
      </button>
    </div>
  );
}

/**
 * Mounted exactly once near the root (App.tsx). Subscribes to the module-level
 * emitter and renders the live toast stack.
 */
export function ToastProvider() {
  const [list, setList] = useState<Toast[]>(toasts);
  const sync = useCallback((t: Toast[]) => setList(t), []);
  useEffect(() => subscribe(sync), [sync]);

  if (list.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex flex-col-reverse gap-2">
      {list.map((t) => (
        <ToastCard key={t.id} toast={t} />
      ))}
    </div>
  );
}
