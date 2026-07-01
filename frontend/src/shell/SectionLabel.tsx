import type { ReactNode } from "react";

/**
 * A lightweight section heading — small, uppercase, tracked. Replaces the heavy
 * `EyebrowPill` blobs that read like disabled buttons in panel headers.
 */
export default function SectionLabel({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[calc(10px_*_var(--text-scale))] font-semibold uppercase tracking-[0.12em] text-ink-dim">{children}</span>
      {right}
    </div>
  );
}
