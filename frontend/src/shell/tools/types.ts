/**
 * Tool descriptor types — the contract every tool-group file builds against.
 *
 * A `ToolDescriptor` is everything the generic `ToolPanel` needs to render a
 * form and either open a WS stream (`transport: "ws"`) or fire a one-shot HTTP
 * call (`transport: "http"`), then turn the response into result rows + Output
 * lines. Capability fields (`tier`, `intrusive`) drive the off-until-enabled
 * sandbox gating in the Explorer / capability layer.
 */
import type { OutputLine } from "../bus";

export type ToolField = {
  name: string;
  label: string;
  type: "text" | "select" | "checkbox" | "path";
  placeholder?: string;
  options?: { value: string; label: string }[];
  default?: string;
  required?: boolean;
};

export type ResultRow = { cols: string[]; level?: OutputLine["level"] };
export type OutLine = Omit<OutputLine, "ts" | "tool">;

/** Capability tier: 1 = zero-setup, 2 = privilege/root, 3 = external setup. */
export type Tier = 1 | 2 | 3;

/** An asset-graph record parsed from a tool's output (host/service/cert/endpoint/tech). */
export type AssetKind = "host" | "service" | "cert" | "endpoint" | "tech";
export type AssetRecord = { kind: AssetKind; key: string; props?: Record<string, unknown> };

type BaseDescriptor = {
  id: string;
  label: string;
  group: string;
  blurb: string;
  /** Capability tier — drives default enablement (Tier 1 on, 2/3 off until enabled). */
  tier: Tier;
  /** Intrusive = actively attacks a target; requires authorization + scope + audit. */
  intrusive?: boolean;
  /** passive = observe only · active = touches/attacks the target. Defaults by tier/intrusive. */
  mode?: "passive" | "active";
  /** What this tool needs (binary / API key / Docker / AD creds) — shown in the setup panel. */
  requires?: string;
  /** Parse this run's events (WS) or [json] (HTTP) into asset-graph records. */
  parseAssets?: (events: any[], target: string) => AssetRecord[];
  fields: ToolField[];
  columns: string[];
};

/** Effective passive/active: explicit `mode`, else active when intrusive, else passive. */
export function toolMode(t: { mode?: "passive" | "active"; intrusive?: boolean }): "passive" | "active" {
  return t.mode ?? (t.intrusive ? "active" : "passive");
}

export type WsDescriptor = BaseDescriptor & {
  transport: "ws";
  wsPath: string;
  buildInit: (v: Record<string, string>) => Record<string, unknown>;
  toRow: (ev: any) => ResultRow | null;
  toOutput: (ev: any) => OutLine | null;
  doneText?: (ev: any) => string;
};

export type HttpDescriptor = BaseDescriptor & {
  transport: "http";
  run: (v: Record<string, string>) => Promise<any>;
  toRows: (json: any) => ResultRow[];
  toOutputs?: (json: any) => OutLine[];
  doneText?: (json: any) => string;
};

export type ToolDescriptor = WsDescriptor | HttpDescriptor;

/** Format a number to 1dp for "0.3s"-style done strings; passthrough otherwise. */
export function fmt(n: unknown): string {
  return typeof n === "number" ? n.toFixed(1) : String(n ?? "");
}
