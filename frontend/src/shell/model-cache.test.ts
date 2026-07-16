/**
 * The model getters memoize their backing list-fetch and invalidate on the
 * matching `modelChanged` signal (the same signal views re-read on). Proven here:
 * N reads share ONE fetch, and a mutation event forces a fresh fetch — so the
 * cache is a transparent read dedupe, never a stale private cache.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";

const spine = vi.hoisted(() => ({ listAllPairingFindings: vi.fn() }));
const eng = vi.hoisted(() => ({ listEngagements: vi.fn() }));
vi.mock("../lib/spine", async (orig) => ({ ...(await orig()), ...spine }));
vi.mock("../lib/engagement", async (orig) => ({ ...(await orig()), ...eng }));

import { getFinding, listFindings, getEngagement } from "./model";
import { emit } from "./bus";

const F = (id: string, engagement_id = "e-1"): any => ({
  id, engagement_id, sub_target_id: "st-1", target_id: "t-1",
  title: `F ${id}`, severity: "high", status: "suspected",
});
const E = (id: string): any => ({ id, name: `Eng ${id}`, scope: [], status: "active" });

beforeEach(() => {
  // Clear both memoized snapshots via the real invalidation path, then reset mocks.
  emit("modelChanged", { entity: "finding", id: "_", op: "update" });
  emit("modelChanged", { entity: "engagement", id: "_", op: "update" });
  (spine.listAllPairingFindings as Mock).mockReset().mockResolvedValue([F("f-1"), F("f-2")]);
  (eng.listEngagements as Mock).mockReset().mockResolvedValue([E("e-1"), E("e-2")]);
});

describe("findings snapshot", () => {
  it("resolves N ids with a single backing fetch (O(1) by id)", async () => {
    expect((await getFinding("f-1"))?.id).toBe("f-1");
    expect((await getFinding("f-2"))?.id).toBe("f-2");
    expect(await getFinding("nope")).toBeNull();
    await listFindings("e-1"); // shares the same snapshot
    expect(spine.listAllPairingFindings).toHaveBeenCalledTimes(1);
  });

  it("re-fetches after a modelChanged{finding} (no stale cache)", async () => {
    await getFinding("f-1");
    expect(spine.listAllPairingFindings).toHaveBeenCalledTimes(1);

    // A finding mutation invalidates the snapshot; the next read re-fetches and
    // reflects the new data.
    (spine.listAllPairingFindings as Mock).mockResolvedValue([F("f-1"), F("f-3")]);
    emit("modelChanged", { entity: "finding", id: "f-3", op: "create" });

    expect((await getFinding("f-3"))?.id).toBe("f-3");
    expect(spine.listAllPairingFindings).toHaveBeenCalledTimes(2);
  });

  it("a modelChanged{engagement} does NOT invalidate the findings snapshot", async () => {
    await getFinding("f-1");
    emit("modelChanged", { entity: "engagement", id: "e-1", op: "update" });
    await getFinding("f-2");
    expect(spine.listAllPairingFindings).toHaveBeenCalledTimes(1);
  });
});

describe("engagements snapshot", () => {
  it("memoizes getEngagement and invalidates on modelChanged{engagement}", async () => {
    expect((await getEngagement("e-1"))?.id).toBe("e-1");
    expect((await getEngagement("e-2"))?.id).toBe("e-2");
    expect(eng.listEngagements).toHaveBeenCalledTimes(1);

    (eng.listEngagements as Mock).mockResolvedValue([E("e-1"), E("e-2"), E("e-9")]);
    emit("modelChanged", { entity: "engagement", id: "e-9", op: "create" });

    expect((await getEngagement("e-9"))?.id).toBe("e-9");
    expect(eng.listEngagements).toHaveBeenCalledTimes(2);
  });
});
