import { describe, expect, it } from "vitest";
import { hammingDistanceHex, phashHex, type RawImage } from "../src/background/phash";
import { comparePhash, applyVisualToResult } from "../src/background/visual";
import type { AnalysisResult } from "../src/types/analysis";

function solidImage(width: number, height: number, leftDark: boolean): RawImage {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const dark = leftDark ? x < width / 2 : x >= width / 2;
      const v = dark ? 10 : 245;
      const idx = (y * width + x) * 4;
      data[idx] = v;
      data[idx + 1] = v;
      data[idx + 2] = v;
      data[idx + 3] = 255;
    }
  }
  return { width, height, data };
}

type AnyLayer = { risk: number; indicators: string[]; evidence: Record<string, unknown>; status: string };
type FixtureLayers = { url: AnyLayer; domain: AnyLayer; webpage: AnyLayer; email: AnyLayer };

function baseResult(layers: FixtureLayers, over: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    analysis_id: "live-test-1",
    url: "https://paypa1-security.top/signin",
    threat_score: 27,
    risk_level: "SAFE",
    confidence: 0.5,
    indicators: [],
    layers: layers as unknown as AnalysisResult["layers"],
    explanation: "Risk assessment:\n\n1. [DOMAIN] Domain registered 6 days ago.",
    recommended_action: "No action required.",
    latency_ms: 800,
    degraded: [],
    demo: false,
    ...over,
  };
}

function layered(url: number, domain: number, webpage: number): FixtureLayers {
  return {
    url: { risk: url, indicators: [], evidence: {}, status: "ok" },
    domain: { risk: domain, indicators: [], evidence: {}, status: "ok" },
    webpage: { risk: webpage, indicators: [], evidence: {}, status: "ok" },
    email: { risk: 0, indicators: [], evidence: {}, status: "not_applicable" },
  };
}

describe("phash", () => {
  it("is deterministic and self-comparison distance is 0", () => {
    const img = solidImage(1280, 800, true);
    const a = phashHex(img);
    const b = phashHex(img);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(a).toBe(b);
    expect(hammingDistanceHex(a, b)).toBe(0);
  });

  it("mirrored layouts differ by a meaningful distance", () => {
    const a = phashHex(solidImage(1280, 800, true));
    const b = phashHex(solidImage(1280, 800, false));
    expect(hammingDistanceHex(a, b)).toBeGreaterThan(16);
  });
});

describe("comparePhash", () => {
  const refs = { paypal: "f65488ae2739c8ae" };

  it("reports no references when the ref set is empty", () => {
    const outcome = comparePhash("f65488ae2739c8ae", {}, "https://paypa1-security.top/signin");
    expect(outcome.status).toBe("unavailable");
  });

  it("flags a lookalike domain as a possible brand clone", () => {
    const outcome = comparePhash("f65488ae2739c8ae", refs, "https://paypa1-security.top/signin");
    expect(outcome.status).toBe("ok");
    expect(outcome.possible_brand).toBe("paypal");
    expect(outcome.visual_indicators[0]).toContain("visual clone");
  });

  it("never flags the genuine brand domain as a clone of itself", () => {
    const outcome = comparePhash("f65488ae2739c8ae", refs, "https://www.paypal.com/signin");
    expect(outcome.status).toBe("ok");
    expect(outcome.possible_brand).toBeNull();
    expect(outcome.visual_indicators[0]).toContain("official domain");
  });
});

describe("applyVisualToResult", () => {
  it("adds clone evidence, re-scores and escalates the verdict", () => {
    // url 0, domain 40, webpage 40 (active; email excluded)
    // Before visual: (0+40+40)/3 = 26.7 -> 27 SAFE
    // After +26 visual on webpage: (0+40+66)/3 = 35.3 -> 35 SUSPICIOUS
    const result = baseResult(layered(0, 40, 40));
    const outcome = comparePhash("f65488ae2739c8ae", { paypal: "f65488ae2739c8ae" }, result.url);
    const merged = applyVisualToResult(result, outcome);

    expect((merged.visual as Record<string, unknown>)?.status).toBe("ok");
    expect((merged.visual as Record<string, unknown>)?.possible_brand).toBe("paypal");
    expect(merged.threat_score).toBe(35);
    expect(merged.risk_level).toBe("SUSPICIOUS");
    const ev = merged.layers.webpage.evidence as Record<string, unknown>;
    expect(ev.possible_brand).toBe("paypal");
    expect(merged.indicators.some((i) => i.includes("visual clone"))).toBe(true);
    expect(merged.recommended_action).toContain("Review the evidence");
  });

  it("leaves the score untouched when there is no clone match", () => {
    const result = baseResult(layered(0, 40, 40));
    // A hash far from every reference: no match, no extra risk.
    const outcome = comparePhash("0000000000000000", { paypal: "f65488ae2739c8ae" }, result.url);
    const merged = applyVisualToResult(result, outcome);
    expect(merged.threat_score).toBe(result.threat_score);
    expect(merged.risk_level).toBe("SAFE");
    expect((merged.visual as Record<string, unknown>)?.possible_brand).toBeNull();
  });
});
