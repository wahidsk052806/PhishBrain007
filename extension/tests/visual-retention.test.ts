/**
 * Retention policy for stored screenshot evidence.
 *
 * A picture of a page the user visited is the most sensitive thing the
 * extension stores, so it is purged on its own, shorter clock than the result
 * it belongs to. These tests pin the contract: the aged sweep strips images
 * (and only images), and "clear all" strips everything now while keeping the
 * stored verdicts.
 *
 * `lib/browser` captures the extension API at import time, so the chrome
 * storage mock is installed before the module under test is imported.
 */
import { beforeEach, describe, expect, it } from "vitest";
import type { AnalysisResult } from "../src/types/analysis";

const store: Record<string, unknown> = {};

function installChromeMock(): void {
  const local = {
    get(keys: unknown, cb: (result: unknown) => void): void {
      if (keys === null || keys === undefined) {
        cb({ ...store });
        return;
      }
      if (typeof keys === "string") {
        cb(keys in store ? { [keys]: store[keys] } : {});
        return;
      }
      if (Array.isArray(keys)) {
        const out: Record<string, unknown> = {};
        for (const key of keys) if (key in store) out[key as string] = store[key as string];
        cb(out);
        return;
      }
      if (typeof keys === "object") {
        const out: Record<string, unknown> = { ...(keys as Record<string, unknown>) };
        for (const key of Object.keys(keys as Record<string, unknown>)) {
          if (key in store) out[key] = store[key];
        }
        cb(out);
        return;
      }
      cb({});
    },
    set(items: Record<string, unknown>, cb: () => void): void {
      Object.assign(store, items);
      cb();
    },
    remove(keys: string | string[], cb: () => void): void {
      for (const key of Array.isArray(keys) ? keys : [keys]) delete store[key];
      cb();
    },
    onChanged: { addListener: () => undefined },
  };
  (globalThis as unknown as { chrome: unknown }).chrome = { storage: { local } };
}

installChromeMock();
const retention = await import("../src/background/visual-retention");

function result(over: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    analysis_id: "a1",
    url: "https://paypa1-security.top/signin",
    threat_score: 61,
    risk_level: "SUSPICIOUS",
    confidence: 0.7,
    indicators: ["lookalike domain"],
    layers: {
      url: { risk: 40, indicators: [], evidence: {} },
      domain: { risk: 50, indicators: [], evidence: {} },
      webpage: {
        risk: 60,
        indicators: [],
        evidence: { has_password_field: true, screenshot_data_url: "data:image/jpeg;base64,AAAA" },
      },
      email: { risk: 0, indicators: [], evidence: {} },
    },
    visual: {
      status: "ok",
      screenshot_thumbnail: "data:image/jpeg;base64,AAAA",
      reference_thumbnail: "data:image/png;base64,BBBB",
      possible_brand: "paypal",
    },
    explanation: "test",
    recommended_action: "test",
    latency_ms: 1,
    degraded: [],
    demo: false,
    ...over,
  };
}

beforeEach(() => {
  for (const key of Object.keys(store)) delete store[key];
});

describe("shouldStoreImages", () => {
  it("treats zero as store-none and any positive window as store", () => {
    expect(retention.shouldStoreImages(0)).toBe(false);
    expect(retention.shouldStoreImages(1)).toBe(true);
    expect(retention.shouldStoreImages(365)).toBe(true);
  });
});

describe("stripVisualEvidence", () => {
  it("removes both stored images while keeping the verdict", () => {
    const stripped = retention.stripVisualEvidence(result());

    expect(stripped.visual?.screenshot_thumbnail).toBeNull();
    expect(stripped.visual?.reference_thumbnail).toBeNull();
    expect(stripped.visual?.possible_brand).toBe("paypal");
    expect(stripped.threat_score).toBe(61);
    expect(stripped.indicators).toEqual(["lookalike domain"]);
  });

  it("removes a screenshot carried on the webpage layer's evidence", () => {
    const stripped = retention.stripVisualEvidence(result());

    expect(stripped.layers.webpage.evidence).not.toHaveProperty("screenshot_data_url");
    expect(stripped.layers.webpage.evidence.has_password_field).toBe(true);
  });

  it("returns the same object when there is nothing to strip", () => {
    const clean = result({
      visual: { status: "unavailable", possible_brand: null },
      layers: {
        url: { risk: 40, indicators: [], evidence: {} },
        domain: { risk: 50, indicators: [], evidence: {} },
        webpage: { risk: 60, indicators: [], evidence: { has_password_field: true } },
        email: { risk: 0, indicators: [], evidence: {} },
      },
    });

    expect(retention.stripVisualEvidence(clean)).toBe(clean);
    expect(retention.hasStoredVisualEvidence(clean)).toBe(false);
  });
});

describe("sweepStoredVisualEvidence", () => {
  const now = 1_700_000_000_000;
  const day = 24 * 60 * 60 * 1000;

  it("strips only results older than the retention window", async () => {
    store.result_1 = { result: result({ analysis_id: "old" }), cachedAt: now - 3 * day };
    store.result_2 = { result: result({ analysis_id: "fresh" }), cachedAt: now - 1 * day };

    const stripped = await retention.sweepStoredVisualEvidence(2, now);

    expect(stripped).toBe(1);
    expect(
      (store.result_1 as { result: AnalysisResult }).result.visual?.screenshot_thumbnail,
    ).toBeNull();
    expect((store.result_2 as { result: AnalysisResult }).result.visual?.screenshot_thumbnail).toBe(
      "data:image/jpeg;base64,AAAA",
    );
  });

  it("ignores non-result keys", async () => {
    store.backendUrl = "http://127.0.0.1:8000";
    store.visualLearnedRefs = { paypal: "f65488ae2739c8ae" };

    expect(await retention.sweepStoredVisualEvidence(0, now)).toBe(0);
    expect(store.backendUrl).toBe("http://127.0.0.1:8000");
  });

  it("treats a zero-day window as store-none", async () => {
    store.result_5 = { result: result(), cachedAt: now - 1 };

    expect(await retention.sweepStoredVisualEvidence(0, now)).toBe(1);
    expect(
      retention.hasStoredVisualEvidence((store.result_5 as { result: AnalysisResult }).result),
    ).toBe(false);
  });
});

describe("clearAllVisualEvidence", () => {
  it("strips every stored image and forgets learned fingerprints", async () => {
    store.result_1 = { result: result(), cachedAt: Date.now() };
    store.result_2 = { result: result({ analysis_id: "b2" }), cachedAt: Date.now() };
    store.visualLearnedRefs = { paypal: "f65488ae2739c8ae" };

    const cleared = await retention.clearAllVisualEvidence();

    expect(cleared).toBe(2);
    expect(
      retention.hasStoredVisualEvidence((store.result_1 as { result: AnalysisResult }).result),
    ).toBe(false);
    expect(store.visualLearnedRefs).toBeUndefined();
  });
});

describe("visualEvidenceStats", () => {
  it("counts stored screenshots and learned fingerprints", async () => {
    store.result_1 = { result: result(), cachedAt: Date.now() };
    store.result_2 = {
      result: retention.stripVisualEvidence(result({ analysis_id: "b2" })),
      cachedAt: Date.now(),
    };
    store.visualLearnedRefs = { paypal: "f65488ae2739c8ae", google: "0000000000000001" };

    const stats = await retention.visualEvidenceStats();

    expect(stats.screenshots).toBe(1);
    expect(stats.learned).toBe(2);
  });
});
