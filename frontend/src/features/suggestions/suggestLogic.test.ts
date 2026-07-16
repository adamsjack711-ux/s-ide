/**
 * Unit tests for suggestLogic — the pure suggestion-derivation core (F7).
 * No network, no React, no bus: fixtures in, suggestion list out. These lock
 * the three load-bearing rules from the spec:
 *   - coverage gap → next-step suggestion (only for un-covered areas),
 *   - asset → param suggestion (targetable kinds only),
 *   - un-armed OR out-of-scope inputs → NO suggestion.
 */
import { describe, it, expect } from "vitest";
import {
  deriveSuggestions,
  paramSuggestions,
  nextStepSuggestions,
  openAreas,
  assetTarget,
  inScope,
  type SuggestInput,
} from "./suggestLogic";
import type { Asset, EngagementCoverage } from "../../shell/model";
import type { CoverageArea } from "../../lib/engagement";
import type { SubTarget } from "../../lib/spine";

// ── Fixtures ─────────────────────────────────────────────────────────────────

const SID = "sub-1";
const OTHER_SID = "sub-2";

function subTarget(over: Partial<SubTarget> = {}): SubTarget {
  return {
    id: SID,
    target_id: "tgt-1",
    type: "host",
    address: "app.example.com",
    label: "app",
    metadata: {},
    created_at: "2026-01-01T00:00:00Z",
    armed: true,
    arming: null,
    ...over,
  };
}

function asset(over: Partial<Asset> = {}): Asset {
  return {
    subTargetId: SID,
    assetId: "host:app.example.com",
    kind: "host",
    key: "app.example.com",
    props: {},
    tool: "lan-scan",
    ...over,
  };
}

function area(over: Partial<CoverageArea> = {}): CoverageArea {
  return {
    key: "recon",
    label: "Recon",
    description: "Port + service discovery",
    covered: false,
    runs: 0,
    last_ts: null,
    last_tool: null,
    last_target: null,
    tools_seen: [],
    ...over,
  };
}

function coverage(areas: CoverageArea[]): EngagementCoverage {
  return {
    engagement_id: "eng-1",
    areas,
    covered_count: areas.filter((a) => a.covered).length,
    total: areas.length,
  };
}

function baseInput(over: Partial<SuggestInput> = {}): SuggestInput {
  return {
    engagementId: "eng-1",
    activeSubTargetId: SID,
    subTargets: [subTarget()],
    assets: [asset()],
    coverage: coverage([area()]),
    ...over,
  };
}

// ── Coverage gap → next-step mapping ─────────────────────────────────────────

describe("nextStepSuggestions", () => {
  it("emits one next-step per UN-covered area and none for covered areas", () => {
    const cov = coverage([
      area({ key: "recon", label: "Recon", covered: false }),
      area({ key: "web", label: "Web", covered: false }),
      area({ key: "report", label: "Report", covered: true }),
    ]);
    const out = nextStepSuggestions(cov);
    expect(out).toHaveLength(2);
    expect(out.every((s) => s.kind === "next-step")).toBe(true);
    expect(out.map((s) => s.areaKey)).toEqual(["recon", "web"]);
    // Gap maps to the tool that would close it.
    expect(out[0].toolId).toBe("port-scanner");
    expect(out[1].toolId).toBe("web-exploit");
  });

  it("returns nothing when coverage is complete", () => {
    const cov = coverage([area({ covered: true }), area({ key: "web", covered: true })]);
    expect(openAreas(cov)).toHaveLength(0);
    expect(nextStepSuggestions(cov)).toHaveLength(0);
  });

  it("treats null coverage as no next-steps", () => {
    expect(nextStepSuggestions(null)).toEqual([]);
  });
});

// ── Asset → param mapping ────────────────────────────────────────────────────

describe("paramSuggestions (asset → param)", () => {
  it("maps a host asset to a pre-filled param suggestion", () => {
    const out = paramSuggestions(baseInput());
    expect(out).toHaveLength(1);
    expect(out[0].kind).toBe("param");
    expect(out[0].toolId).toBe("port-scanner");
    expect(out[0].paramValue).toBe("app.example.com");
    expect(out[0].subTargetId).toBe(SID);
  });

  it("prefers an explicit address/url prop over the key", () => {
    expect(assetTarget(asset({ props: { url: "https://app.example.com/login" } })))
      .toBe("https://app.example.com/login");
    const out = paramSuggestions(
      baseInput({
        assets: [asset({ kind: "endpoint", key: "/login", props: { url: "https://app.example.com/login" } })],
      }),
    );
    expect(out[0].toolId).toBe("web-exploit");
    expect(out[0].paramValue).toBe("https://app.example.com/login");
  });

  it("ignores non-targetable asset kinds (cert / tech)", () => {
    const out = paramSuggestions(
      baseInput({ assets: [asset({ kind: "cert", key: "CN=app" }), asset({ kind: "tech", key: "nginx" })] }),
    );
    expect(out).toEqual([]);
  });

  it("de-duplicates the same (tool, value) pair", () => {
    const out = paramSuggestions(
      baseInput({ assets: [asset(), asset({ assetId: "host:dup" })] }),
    );
    expect(out).toHaveLength(1);
  });

  it("ignores assets recorded under a different sub-target scope", () => {
    const out = paramSuggestions(
      baseInput({ assets: [asset({ subTargetId: OTHER_SID })] }),
    );
    expect(out).toEqual([]);
  });
});

// ── Security: un-armed → NO suggestion ───────────────────────────────────────

describe("arm gate — un-armed sub-target yields no param suggestions", () => {
  it("produces NO param suggestion when the active sub-target is un-armed", () => {
    const out = paramSuggestions(baseInput({ subTargets: [subTarget({ armed: false })] }));
    expect(out).toEqual([]);
  });

  it("produces NO param suggestion when the active sub-target is unknown", () => {
    const out = paramSuggestions(baseInput({ subTargets: [] }));
    expect(out).toEqual([]);
  });

  it("un-armed still surfaces next-steps (coverage is engagement-wide, not sub-target-armed)", () => {
    const out = deriveSuggestions(baseInput({ subTargets: [subTarget({ armed: false })] }));
    expect(out.every((s) => s.kind === "next-step")).toBe(true);
    expect(out.length).toBeGreaterThan(0);
  });
});

// ── Security: out-of-scope → NO suggestion ───────────────────────────────────

describe("scope gate — out-of-scope target yields no param suggestion", () => {
  it("drops an asset whose target is outside the engagement scope", () => {
    const out = paramSuggestions(
      baseInput({
        assets: [asset({ key: "evil.attacker.test", props: { host: "evil.attacker.test" } })],
        scope: ["app.example.com", "*.example.com"],
      }),
    );
    expect(out).toEqual([]);
  });

  it("keeps an in-scope asset (exact + subdomain + wildcard match)", () => {
    expect(inScope("app.example.com", ["app.example.com"])).toBe(true);
    expect(inScope("https://api.example.com/x", ["*.example.com"])).toBe(true);
    expect(inScope("evil.test", ["*.example.com"])).toBe(false);
    const out = paramSuggestions(
      baseInput({
        assets: [asset({ key: "api.example.com", props: { host: "api.example.com" } })],
        scope: ["*.example.com"],
      }),
    );
    expect(out).toHaveLength(1);
    expect(out[0].paramValue).toBe("api.example.com");
  });

  it("an empty scope list imposes no constraint (arm gate still bounds it)", () => {
    const out = paramSuggestions(baseInput({ scope: [] }));
    expect(out).toHaveLength(1);
  });
});

// ── Top-level derivation + empty states ──────────────────────────────────────

describe("deriveSuggestions", () => {
  it("returns params first, then next-steps", () => {
    const out = deriveSuggestions(
      baseInput({
        coverage: coverage([area({ covered: false }), area({ key: "report", covered: true })]),
      }),
    );
    expect(out[0].kind).toBe("param");
    expect(out[out.length - 1].kind).toBe("next-step");
  });

  it("returns nothing without an active engagement", () => {
    expect(deriveSuggestions(baseInput({ engagementId: null }))).toEqual([]);
  });

  it("is empty when coverage is complete and there are no assets (no suggestions)", () => {
    const out = deriveSuggestions(
      baseInput({ assets: [], coverage: coverage([area({ covered: true })]) }),
    );
    expect(out).toEqual([]);
  });
});
