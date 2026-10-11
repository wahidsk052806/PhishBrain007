import { describe, expect, it } from "vitest";
import { hammingDistanceHex, phashHex, sobelEdges, type RawImage } from "../src/background/phash";
import {
  comparePhash,
  applyVisualToResult,
  normalizeRefMap,
  visualRiskContribution,
} from "../src/background/visual";
import { isOfficialHost, officialHostsFor } from "../src/background/brand-refs";
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

type AnyLayer = {
  risk: number;
  indicators: string[];
  evidence: Record<string, unknown>;
  status: string;
};
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

describe("normalizeRefMap", () => {
  it("reads the legacy flat { brand: hash } schema", () => {
    expect(normalizeRefMap({ paypal: "f65488ae2739c8ae" })).toEqual({
      paypal: "f65488ae2739c8ae",
    });
  });

  it("reads the backend's structured references schema and skips metadata", () => {
    const structured = {
      version: 3,
      generated_at: "2026-09-21T18:57:33+00:00",
      description: "Brand references",
      favicons: { paypal: [{ url: "https://x/f.ico", phash: "1111111111111111" }] },
      references: {
        paypal: [{ url: "https://www.paypal.com/signin", phash: "f65488ae2739c8ae" }],
        apple: [],
      },
    };
    expect(normalizeRefMap(structured)).toEqual({ paypal: "f65488ae2739c8ae" });
  });

  it("ignores junk values instead of producing fake brands", () => {
    const map = normalizeRefMap({ paypal: "nope", extra: 42, "": "f65488ae2739c8ae" });
    expect(map).toEqual({});
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
    expect(outcome.visual_signal).toBe("layout");
    expect(outcome.visual_indicators[0]).toContain("visual clone");
  });

  it("never flags the genuine brand domain as a clone of itself", () => {
    const outcome = comparePhash("f65488ae2739c8ae", refs, "https://www.paypal.com/signin");
    expect(outcome.status).toBe("ok");
    expect(outcome.possible_brand).toBeNull();
    expect(outcome.visual_indicators.join("\n")).toContain("official domain");
  });

  it("uses the page icon as the primary clone signal", () => {
    // Screenshot matches nothing; the page icon is the brand's own icon
    // (distance 0) on an unrelated host.
    const outcome = comparePhash("0000000000000000", refs, "https://paypa1-security.top/signin", {
      iconPhash: "f65488ae2739c8ae",
      iconRefs: { paypal: "f65488ae2739c8ae" },
    });
    expect(outcome.status).toBe("ok");
    expect(outcome.visual_signal).toBe("favicon");
    expect(outcome.possible_brand).toBe("paypal");
    expect(outcome.favicon_distance).toBe(0);
    expect(outcome.visual_indicators[0]).toContain("brand mark");
    expect(visualRiskContribution(outcome)).toBe(30);
  });

  it("does not call a brand's own icon a clone on the brand's domain", () => {
    const outcome = comparePhash("0000000000000000", refs, "https://www.paypal.com/us/signin", {
      iconPhash: "f65488ae2739c8ae",
      iconRefs: { paypal: "f65488ae2739c8ae" },
    });
    expect(outcome.possible_brand).toBeNull();
    expect(outcome.visual_signal).toBe("none");
    expect(outcome.favicon_brand).toBe("paypal");
    expect(visualRiskContribution(outcome)).toBe(0);
    expect(outcome.visual_indicators.join("\n")).toContain("expected, not a clone");
  });

  it("prefers the icon signal over the layout signal", () => {
    const outcome = comparePhash("f65488ae2739c8ae", refs, "https://paypa1-security.top/signin", {
      iconPhash: "f65488ae2739c8ae",
      iconRefs: { google: "f65488ae2739c8ae" },
    });
    expect(outcome.visual_signal).toBe("favicon");
    expect(outcome.possible_brand).toBe("google");
  });

  it("reports the icon comparison honestly when it finds nothing", () => {
    // Nothing matches: the screenshot is far from the layout ref and the page
    // icon is far from the icon ref.
    const outcome = comparePhash("0000000000000000", refs, "https://example.com/", {
      iconPhash: "ffffffffffffffff",
      iconRefs: { paypal: "0000000000000000" },
    });
    expect(outcome.favicon_status).toBe("ok");
    expect(outcome.favicon_brand).toBe("paypal");
    expect(outcome.possible_brand).toBeNull();
    expect(outcome.visual_indicators.join("\n")).toContain("does not match any tracked brand mark");
  });
});

describe("sobelEdges (wireframe privacy mode)", () => {
  function uniform(width: number, height: number, v: number): Uint8ClampedArray {
    const data = new Uint8ClampedArray(width * height * 4);
    for (let i = 0; i < data.length; i += 4) {
      data[i] = data[i + 1] = data[i + 2] = v;
      data[i + 3] = 255;
    }
    return data;
  }

  it("turns a flat image into pure background, with no lines", () => {
    const out = sobelEdges(16, 16, uniform(16, 16, 180));
    for (let i = 0; i < out.length; i += 4) {
      expect(out[i]).toBe(255);
    }
  });

  it("draws the boundary between two regions as black-on-white lines", () => {
    const width = 24;
    const height = 24;
    const data = uniform(width, height, 240);
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width / 2; x += 1) {
        const i = (y * width + x) * 4;
        data[i] = data[i + 1] = data[i + 2] = 20;
      }
    }

    const out = sobelEdges(width, height, data);
    let dark = 0;
    let mid = 0;
    for (let i = 0; i < out.length; i += 4) {
      if (out[i] === 0) dark += 1;
      else if (out[i] !== 255) mid += 1;
    }

    expect(dark).toBeGreaterThan(0);
    // Binarised: no grey survives, so nothing legible can remain.
    expect(mid).toBe(0);
  });
});

describe("brand host ownership", () => {
  it("recognises a brand's own hosts and their subdomains", () => {
    expect(isOfficialHost("paypal", "www.paypal.com")).toBe(true);
    expect(isOfficialHost("paypal", "mail.paypal.com")).toBe(true);
    expect(isOfficialHost("paypal", "paypa1-security.top")).toBe(false);
    expect(isOfficialHost("microsoft", "login.microsoftonline.com")).toBe(true);
    expect(isOfficialHost("google", "accounts.google.com")).toBe(true);
    expect(isOfficialHost("google", "google.com.evil.tk")).toBe(false);
  });

  it("ships a source list for every brand it can flag", () => {
    expect(officialHostsFor("nonexistent-brand")).toEqual([]);
    expect(officialHostsFor("netflix").length).toBeGreaterThan(0);
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

  it("carries the captured screenshot thumbnail through to the result", () => {
    const result = baseResult(layered(0, 40, 40));
    const outcome = comparePhash("f65488ae2739c8ae", { paypal: "f65488ae2739c8ae" }, result.url);
    outcome.screenshot_thumbnail = "data:image/jpeg;base64,c2hvdA==";

    const merged = applyVisualToResult(result, outcome);

    expect((merged.visual as Record<string, unknown>)?.screenshot_thumbnail).toBe(
      "data:image/jpeg;base64,c2hvdA==",
    );
  });

  it("reports a null thumbnail when capture produced no image", () => {
    const result = baseResult(layered(0, 40, 40));
    const outcome = comparePhash("0000000000000000", { paypal: "f65488ae2739c8ae" }, result.url);

    const merged = applyVisualToResult(result, outcome);

    expect((merged.visual as Record<string, unknown>)?.screenshot_thumbnail).toBeNull();
  });
});
