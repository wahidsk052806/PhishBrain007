import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../src/lib/browser", () => ({
  storage: { get: vi.fn(async () => ({})) },
}));

import {
  analyzeUrl,
  getHealth,
  ApiError,
  normalizeServerResult,
  DEFAULT_DASHBOARD_URL,
} from "../src/services/api";

const originalFetch = global.fetch;

describe("api error handling", () => {
  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("throws BACKEND_UNAVAILABLE when fetch rejects (network error)", async () => {
    global.fetch = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;

    await expect(
      analyzeUrl({ url: "https://example.com" }, "http://127.0.0.1:9999"),
    ).rejects.toMatchObject({
      code: "BACKEND_UNAVAILABLE",
    });
  });

  it("throws TIMEOUT when the request is aborted", async () => {
    global.fetch = vi.fn(async () => {
      throw new DOMException("Aborted", "AbortError");
    }) as unknown as typeof fetch;

    await expect(
      analyzeUrl({ url: "https://example.com" }, "http://127.0.0.1:9999"),
    ).rejects.toMatchObject({
      code: "TIMEOUT",
    });
  });

  it("throws HTTP_ERROR on non-ok responses", async () => {
    global.fetch = vi.fn(
      async () =>
        new Response("Internal error", { status: 500, statusText: "Internal Server Error" }),
    ) as unknown as typeof fetch;

    await expect(getHealth("http://127.0.0.1:9999")).rejects.toMatchObject({
      code: "HTTP_ERROR",
      status: 500,
    });
  });

  it("throws PARSE_ERROR when response body is not valid JSON", async () => {
    global.fetch = vi.fn(
      async () => new Response("not json", { status: 200 }),
    ) as unknown as typeof fetch;

    await expect(getHealth("http://127.0.0.1:9999")).rejects.toMatchObject({ code: "PARSE_ERROR" });
  });

  it("resolves with parsed JSON on success", async () => {
    global.fetch = vi.fn(
      async () => new Response(JSON.stringify({ status: "ok" }), { status: 200 }),
    ) as unknown as typeof fetch;

    await expect(getHealth("http://127.0.0.1:9999")).resolves.toEqual({ status: "ok" });
  });

  it("ApiError instances carry a code and message", () => {
    const err = new ApiError("HTTP_ERROR", "boom", 503);
    expect(err.code).toBe("HTTP_ERROR");
    expect(err.status).toBe(503);
    expect(err.message).toBe("boom");
  });
});

describe("backend result normalization", () => {
  // Regression: the backend sends `layer_evidence`, but the extension scores
  // and merges against `layers`. Without normalization the visual brand-clone
  // merge found no webpage layer and silently never changed the score.
  const serverPayload = {
    analysis_id: "abc",
    target: "https://paypa1-secure.top/login",
    threat_score: 82,
    risk_level: "HIGH_RISK" as const,
    confidence: 0.9,
    indicators: ["Typosquatting"],
    explanation: "high risk",
    recommended_action: "do not proceed",
    latency_ms: 120,
    degraded: [],
    layer_evidence: [
      {
        layer: "url",
        risk_score: 70,
        indicators: ["Suspicious keyword: login"],
        details: { url_length: 31 },
      },
      {
        layer: "webpage",
        risk_score: 88,
        indicators: ["Credential form posts off-domain"],
        details: { has_password_field: true },
      },
      { layer: "email", risk_score: 0, indicators: [], details: {}, unavailable: true },
      // Unknown layers must not create bogus keys.
      { layer: "carrier-pigeon", risk_score: 99, indicators: [], details: {} },
    ],
  };

  it("builds a keyed layers record from layer_evidence", () => {
    const result = normalizeServerResult(serverPayload);
    expect(result.layers.url.risk).toBe(70);
    expect(result.layers.url.indicators).toEqual(["Suspicious keyword: login"]);
    expect(result.layers.url.evidence).toEqual({ url_length: 31 });
    expect(result.layers.webpage.risk).toBe(88);
    expect(result.layers.webpage.evidence).toEqual({ has_password_field: true });
    expect(Object.keys(result.layers)).toEqual(["url", "domain", "webpage", "email"]);
  });

  it("maps the backend's `target` onto `url`", () => {
    expect(normalizeServerResult(serverPayload).url).toBe("https://paypa1-secure.top/login");
  });

  it("treats an unavailable layer as zero risk instead of undefined", () => {
    expect(normalizeServerResult(serverPayload).layers.email.risk).toBe(0);
  });

  it("leaves an already-normalized result untouched", () => {
    const normalized = normalizeServerResult(serverPayload);
    const again = normalizeServerResult(normalized);
    expect(again.layers).toEqual(normalized.layers);
    expect(again.url).toBe(normalized.url);
  });

  it("surfaces the backend's screenshot comparison as `visual`", () => {
    // Regression: the popup reads `result.visual`, but only the webpage
    // layer's details carried the comparison. Every server result therefore
    // said "visual analysis unavailable" even when a screenshot had been
    // captured and scored.
    const withVisual = {
      ...serverPayload,
      layer_evidence: [
        {
          layer: "webpage",
          risk_score: 12,
          indicators: [],
          details: {
            has_password_field: false,
            visual_similarity_score: 0.81,
            possible_brand: "netflix",
            visual_indicators: ["Screenshot compared against 43 reference images"],
            screenshot_data_url: "data:image/png;base64,AAAA",
          },
        },
      ],
    };

    const visual = normalizeServerResult(withVisual).visual;

    expect(visual?.status).toBe("ok");
    expect(visual?.visual_similarity_score).toBe(0.81);
    expect(visual?.possible_brand).toBe("netflix");
    expect(visual?.screenshot_thumbnail).toBe("data:image/png;base64,AAAA");
    expect(visual?.visual_indicators).toEqual([
      "Screenshot compared against 43 reference images",
    ]);
  });

  it("does not invent a visual verdict when the scan had none", () => {
    expect(normalizeServerResult(serverPayload).visual).toBeUndefined();
  });

  it("points 'Open dashboard' at the dashboard port, not the API port", () => {
    expect(DEFAULT_DASHBOARD_URL).toBe("http://127.0.0.1:8080");
  });
});

describe("scan request body", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("forwards use_llm and fetch_page so a fast pass can skip the slow layers", async () => {
    let sent: Record<string, unknown> | null = null;
    global.fetch = vi.fn(async (_url: string, init: RequestInit) => {
      sent = JSON.parse(String(init.body)) as Record<string, unknown>;
      return new Response(
        JSON.stringify({
          analysis_id: "x",
          target: "https://example.com",
          threat_score: 1,
          risk_level: "SAFE",
          confidence: 0.5,
          indicators: [],
          explanation: "",
          recommended_action: "",
          latency_ms: 1,
          degraded: [],
          layer_evidence: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    await analyzeUrl(
      { url: "https://example.com", use_llm: false, fetch_page: false },
      "http://127.0.0.1:9999",
    );

    expect(sent).toMatchObject({ use_llm: false, fetch_page: false });
  });
});
