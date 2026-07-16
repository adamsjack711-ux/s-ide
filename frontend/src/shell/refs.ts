/**
 * Canonical domain references (Foundation lane) — the FROZEN vocabulary every
 * feature panel speaks. This is the fourth leg of the shell contract, alongside
 * the bus (shell/bus.ts), the view registry (shell/views.ts) and the command
 * registry (shell/commands.ts).
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
 *
 * Cross-linking features (search → finding, graph node → step, finding → code
 * anchor) only compose if every feature identifies the same object the same
 * way. Before this module, a feature that wanted to "select a finding" had to
 * invent its own shape; two features would drift and desync. Here we define ONE
 * typed reference per domain object. Selection/navigation bus events (see
 * bus.ts) carry these refs; the read-only model API (shell/model.ts) returns
 * and accepts them. A feature NEVER redefines these shapes locally — it imports
 * them. (Phase-2 test T2 greps for divergent local copies and fails on any.)
 *
 * These are *references* (stable identity + the minimum to resolve it), not the
 * full records. To read the record, hand the ref to the model API. Keeping refs
 * thin means a publisher can broadcast a selection without loading the whole
 * object, and a subscriber resolves only what it needs.
 *
 * Field names are camelCase (frontend convention). The backend speaks snake_case
 * (`sub_target_id`, `target_id`, `finding_id`); shell/model.ts owns the
 * adapters between the two so features touch only this camelCase surface.
 */

/** An engagement's id (the project spine). `null` = no engagement active. */
export type EngagementId = string;

/** A Target — an inert, addressable thing under test (provenance + name). */
export type TargetRef = { targetId: string };

/**
 * A Sub-target — an addressable component of a Target, armed by an engagement
 * before anything may run against it. Carries its parent targetId so a
 * subscriber can roll up without a second lookup.
 */
export type SubTargetRef = { targetId: string; subTargetId: string };

/** The kinds of asset the graph/scan layer surfaces. */
export type AssetKind = "host" | "service" | "cert" | "endpoint" | "tech";

/**
 * An Asset — a concrete artefact discovered while probing a sub-target (an open
 * service, a certificate, an endpoint, a detected technology). `assetId` is
 * stable within its sub-target; `kind` disambiguates how to render/resolve it.
 */
export type AssetRef = {
  subTargetId: string;
  assetId: string;
  kind: AssetKind;
};

/**
 * A Finding — the provenance triple every cross-link uses. A bare finding id is
 * NOT enough: pivots roll a finding up to its sub-target and target, so a
 * FindingRef always carries all three. (The `findingCreated` bus event already
 * emits exactly this triple.)
 */
export type FindingRef = {
  findingId: string;
  subTargetId: string;
  targetId: string;
};

/**
 * A Step in a finding's evidence/reasoning chain. `stepId` is stable within the
 * finding. Steps are ordered and each is tagged FACT (action + captured
 * evidence) or INFERENCE (interpretation) — see Step in shell/model.ts.
 */
export type StepRef = { findingId: string; stepId: string };

/**
 * A root-cause anchor — where a finding "lives" in the code/route/config space,
 * so the editor / graph / timeline can jump to it. Exactly one of the three
 * kinds is meaningful per anchor:
 *   - file   → { file, line? }         a source location (opens in the editor)
 *   - route  → { route }               an HTTP route / path
 *   - config → { file?, key }          a configuration key (optionally in a file)
 * A finding with no anchor yet is represented by the ABSENCE of an Anchor (the
 * pivot surfaces "no root cause anchored yet"), never by a fabricated one.
 */
export type Anchor = {
  kind: "file" | "route" | "config";
  file?: string;
  line?: number;
  route?: string;
  key?: string;
  /**
   * Optional lab id the `file` path is rooted in — mirrors the openEditor bus
   * event's { labId, path } convention so a file anchor can open Monaco. Absent
   * for route/config anchors and for findings whose source lives outside a lab.
   */
  labId?: string;
};

/**
 * Confidence level of a finding or step. INVARIANT (enforced across features,
 * Phase-2 test T5): a `suspected` item must NEVER be rendered or persisted as
 * `confirmed`. Confidence is only ever *lowered* by evidence review, never
 * silently upgraded by a view. Derive it via confLevel() in shell/model.ts —
 * do not infer it ad hoc.
 */
export type ConfLevel = "confirmed" | "suspected";
