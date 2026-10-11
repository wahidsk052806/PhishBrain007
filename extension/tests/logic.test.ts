import { describe, it, expect } from "vitest";
import {
  shouldScanUrl,
  badgeForResult,
  badgeForUnavailable,
  shouldShowBanner,
  isCacheFresh,
  parseIncomingMessage,
} from "../src/background/logic";
import type { AnalysisResult } from "../src/types/analysis";

function makeResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    analysis_id: "abc",
    url: "https://example.com",
    threat_score: 10,
    risk_level: "SAFE",
    confidence: 0.9,
    indicators: [],
    layers: {
      email: { risk: 0, indicators: [], evidence: {} },
      url: { risk: 0, indicators: [], evidence: {} },
      domain: { risk: 0, indicators: [], evidence: {} },
      webpage: { risk: 0, indicators: [], evidence: {} },
    },
    explanation: "looks fine",
    recommended_action: "none",
    latency_ms: 5,
    degraded: [],
    ...overrides,
  };
}

describe("shouldScanUrl", () => {
  it("returns false when autoScan disabled", () => {
    expect(shouldScanUrl("https://example.com", { autoScan: false, allowlist: [] })).toBe(false);
  });

  it("returns false for invalid urls", () => {
    expect(shouldScanUrl("not a url", { autoScan: true, allowlist: [] })).toBe(false);
  });

  it("returns false for non http(s) protocols", () => {
    expect(shouldScanUrl("chrome://extensions", { autoScan: true, allowlist: [] })).toBe(false);
  });

  it("returns false when domain is allowlisted", () => {
    expect(
      shouldScanUrl("https://sub.example.com/path", { autoScan: true, allowlist: ["example.com"] }),
    ).toBe(false);
  });

  it("returns true for a normal http(s) url not allowlisted", () => {
    expect(shouldScanUrl("https://example.com", { autoScan: true, allowlist: [] })).toBe(true);
  });
});

describe("badgeForResult", () => {
  it("returns unknown badge when result is null", () => {
    expect(badgeForResult(null).text).toBe("?");
  });

  it("returns OK badge for SAFE", () => {
    expect(badgeForResult(makeResult({ risk_level: "SAFE" })).text).toBe("OK");
  });

  it("returns ! badge for SUSPICIOUS", () => {
    expect(badgeForResult(makeResult({ risk_level: "SUSPICIOUS" })).text).toBe("!");
  });

  it("returns !! badge for HIGH_RISK", () => {
    expect(badgeForResult(makeResult({ risk_level: "HIGH_RISK" })).text).toBe("!!");
  });
});

describe("badgeForUnavailable", () => {
  it("returns a neutral unknown badge", () => {
    const badge = badgeForUnavailable();
    expect(badge.text).toBe("?");
    expect(badge.title).toMatch(/unavailable/i);
  });
});

describe("shouldShowBanner", () => {
  it("never shows banner in silent mode", () => {
    expect(
      shouldShowBanner(makeResult({ risk_level: "HIGH_RISK", threat_score: 99 }), {
        bannerMode: "silent",
        riskThreshold: 10,
      }),
    ).toBe(false);
  });

  it("never shows banner for SAFE results", () => {
    expect(
      shouldShowBanner(makeResult({ risk_level: "SAFE", threat_score: 90 }), {
        bannerMode: "banner",
        riskThreshold: 10,
      }),
    ).toBe(false);
  });

  it("shows banner when score meets threshold", () => {
    expect(
      shouldShowBanner(makeResult({ risk_level: "SUSPICIOUS", threat_score: 60 }), {
        bannerMode: "banner",
        riskThreshold: 50,
      }),
    ).toBe(true);
  });

  it("does not show banner when score is below threshold", () => {
    expect(
      shouldShowBanner(makeResult({ risk_level: "SUSPICIOUS", threat_score: 40 }), {
        bannerMode: "banner",
        riskThreshold: 50,
      }),
    ).toBe(false);
  });
});

describe("isCacheFresh", () => {
  const result = makeResult({ url: "https://example.com" });

  it("returns false when entry is undefined", () => {
    expect(isCacheFresh(undefined, "https://example.com", 1000, 0)).toBe(false);
  });

  it("returns false when url does not match", () => {
    expect(isCacheFresh({ result, cachedAt: 0 }, "https://other.com", 1000, 500)).toBe(false);
  });

  it("returns false when entry is stale", () => {
    expect(isCacheFresh({ result, cachedAt: 0 }, "https://example.com", 1000, 2000)).toBe(false);
  });

  it("returns true when entry is fresh and url matches", () => {
    expect(isCacheFresh({ result, cachedAt: 0 }, "https://example.com", 1000, 500)).toBe(true);
  });
});

describe("parseIncomingMessage", () => {
  it("returns null for invalid input", () => {
    expect(parseIncomingMessage(null)).toBeNull();
    expect(parseIncomingMessage("string")).toBeNull();
    expect(parseIncomingMessage({ type: "UNKNOWN" })).toBeNull();
  });

  it("parses GET_RESULT", () => {
    expect(parseIncomingMessage({ type: "GET_RESULT", tabId: 1 })).toEqual({
      type: "GET_RESULT",
      tabId: 1,
    });
  });

  it("parses RESCAN", () => {
    expect(parseIncomingMessage({ type: "RESCAN", tabId: 1, url: "https://a.com" })).toEqual({
      type: "RESCAN",
      tabId: 1,
      url: "https://a.com",
    });
  });

  it("parses PROCEED_ANYWAY", () => {
    expect(parseIncomingMessage({ type: "PROCEED_ANYWAY", hostname: "a.com" })).toEqual({
      type: "PROCEED_ANYWAY",
      hostname: "a.com",
    });
  });

  it("parses PAGE_SUMMARY", () => {
    expect(
      parseIncomingMessage({
        type: "PAGE_SUMMARY",
        tabId: 1,
        url: "https://a.com",
        summary: { title: "x" },
      }),
    ).toEqual({
      type: "PAGE_SUMMARY",
      tabId: 1,
      url: "https://a.com",
      summary: { title: "x" },
    });
  });

  it("parses EMAIL_SUMMARY", () => {
    const msg = {
      type: "EMAIL_SUMMARY",
      tabId: 1,
      url: "https://mail.google.com",
      email: { sender: "a@b.com" },
    };
    expect(parseIncomingMessage(msg)).toEqual(msg);
  });

  it("parses OPEN_DASHBOARD", () => {
    expect(parseIncomingMessage({ type: "OPEN_DASHBOARD", url: "https://dash.com" })).toEqual({
      type: "OPEN_DASHBOARD",
      url: "https://dash.com",
    });
  });
});
