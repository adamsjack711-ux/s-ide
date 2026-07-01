import { useEffect, useState } from "react";
import SectionLabel from "./SectionLabel";

import { on } from "./bus";

type Asset = { kind: string; key: string; props?: Record<string, unknown>; tool: string };

const KIND_ORDER = ["host", "service", "endpoint", "cert", "tech"];
const KIND_GLYPH: Record<string, string> = { host: "▪", service: "⬡", endpoint: "↳", cert: "⚿", tech: "⚙" };

/**
 * Discovered assets for the active scope — the asset-graph view. Fed live by the
 * `assetDiscovered` bus event that ToolPanel emits from each tool's parser.
 */
export default function AssetsTree() {
  const [assets, setAssets] = useState<Map<string, Asset>>(new Map());

  useEffect(
    () =>
      on("assetDiscovered", ({ assets: found, tool }) => {
        setAssets((prev) => {
          const next = new Map(prev);
          for (const a of found) next.set(`${a.kind}:${a.key}`, { ...a, tool });
          return next;
        });
      }),
    [],
  );

  if (assets.size === 0) return null;

  const byKind = KIND_ORDER.map((kind) => ({ kind, items: [...assets.values()].filter((a) => a.kind === kind) })).filter((g) => g.items.length);

  return (
    <div className="border-b border-divider pb-2">
      <div className="flex items-center justify-between px-3 pb-1 pt-3">
        <SectionLabel>Discovered</SectionLabel>
        <span className="text-[calc(11px_*_var(--text-scale))] text-ink-dim">{assets.size}</span>
      </div>
      {byKind.map((g) => (
        <div key={g.kind} className="pb-1">
          <div className="px-3 py-0.5 text-[calc(11px_*_var(--text-scale))] uppercase tracking-wide text-ink-dim">{g.kind}s</div>
          {g.items.map((a) => (
            <div key={a.key} className="truncate px-4 py-0.5 text-xs text-ink-muted" title={`${a.key} · via ${a.tool}`}>
              <span className="mr-1.5 text-accent">{KIND_GLYPH[a.kind] ?? "·"}</span>
              {a.key}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
