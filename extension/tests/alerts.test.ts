import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ALERT_ATTEMPTS,
  ALERT_ATTEMPT_TIMEOUT_MS,
  buildSocAlert,
  buildTestAlert,
  sendSocAlert,
  shouldSendAlert,
  targetHost,
} from "../src/background/alerts";
import { parseIncomingMessage } from "../src/background/logic";
import type { AnalysisResult } from "../src/types/analysis";
import { installHarness, waitFor, type HarnessOptions } from "./helpers/browser-harness";

function resultOf(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    analysis_id: "a-1",
    url: "https://paypa1-security.top/login/verify",
    domain: "paypa1-security.top",
    threat_score: 91,
    risk_level: "HIGH_RISK",
    confidence: 0.9,
    indicators: ["typosquat", "young domain"],
    recommended_action: "Do not enter credentials.",
    degraded: ["RDAP unavailable"],
    latency_ms: 10,
    layers: {
      url: { risk: 80, indicators: [], evidence: {} },
      domain: { risk: 60, indicators: [], evidence: {} },
      webpage: { risk: 0, indicators: [], evidence: {} },
      email: { risk: 0, indicators: [], evidence: {} },
    },
    ...overrides,
  } as AnalysisResult;
}

const GATE = {
  alertsEnabled: true,
  alertWebhookUrl: "https://soc.example/hook",
  riskThreshold: 50,
};

describe("buildSocAlert", () => {
  it("forwards the backend's own SOC event, keeping the id a SIEM deduplicates on", () => {
    const result = resultOf({
      soc_event: {
        event_id: "11111111-1111-1111-1111-111111111111",
        analysis_id: "a-1",
        timestamp: "2026-10-16T10:00:00Z",
        source: "phishbrain",
        event_type: "phishing_analysis",
        severity: "high",
        threat_score: 91,
        risk_level: "HIGH_RISK",
        indicators: ["typosquat"],
        target_identifier: "https://paypa1-security.top/login/verify",
        degraded: ["RDAP unavailable"],
        prefilter: { model_trained: true, weight: 0.15 },
      },
    });

    const alert = buildSocAlert(result);

    expect(alert.event_id).toBe("11111111-1111-1111-1111-111111111111");
    expect(alert.event_type).toBe("phishing_analysis");
    expect(alert.severity).toBe("high");
    expect(alert.indicators).toEqual(["typosquat"]);
    expect(alert.degraded).toEqual(["RDAP unavailable"]);
    expect(alert.prefilter).toEqual({ model_trained: true, weight: 0.15 });
    // Provenance is the one thing the collector always adds.
    expect(alert.collector).toBe("phishbrain-extension");
    expect(alert.source).toBe("phishbrain");
  });

  it("reconstructs the canonical event when the engine supplied none (hosted scan)", () => {
    const alert = buildSocAlert(resultOf({ risk_level: "SUSPICIOUS", threat_score: 70 }));

    expect(typeof alert.event_id).toBe("string");
    expect((alert.event_id as string).length).toBeGreaterThan(8);
    expect(alert.event_type).toBe("phishing_analysis");
    expect(alert.source).toBe("phishbrain");
    expect(alert.severity).toBe("medium");
    expect(alert.risk_level).toBe("SUSPICIOUS");
    expect(alert.target_identifier).toBe("https://paypa1-security.top/login/verify");
    expect(alert.degraded).toEqual(["RDAP unavailable"]);
    expect(typeof alert.timestamp).toBe("string");
  });

  it("maps every risk level to a severity", () => {
    expect(buildSocAlert(resultOf({ risk_level: "SAFE" })).severity).toBe("low");
    expect(buildSocAlert(resultOf({ risk_level: "SUSPICIOUS" })).severity).toBe("medium");
    expect(buildSocAlert(resultOf({ risk_level: "HIGH_RISK" })).severity).toBe("high");
  });

  it("derives the host when the result has no domain field", () => {
    // Backend results name the target `target`, not `domain` — the old payload
    // read `result.domain` and silently serialised the field away.
    const alert = buildSocAlert(resultOf({ domain: undefined }));
    expect(alert.domain).toBe("paypa1-security.top");
    expect(targetHost(resultOf({ domain: undefined }))).toBe("paypa1-security.top");
    expect(targetHost(resultOf({ url: "not a url", domain: undefined }))).toBe("");
  });

  it("keeps the fields version 1.0.0 sent, so existing relays keep working", () => {
    const alert = buildSocAlert(resultOf());
    expect(alert.url).toBe("https://paypa1-security.top/login/verify");
    expect(typeof alert.detected_at).toBe("string");
    expect(alert.recommended_action).toBe("Do not enter credentials.");
  });

  it("caps indicators and ignores non-strings", () => {
    const many = Array.from({ length: 30 }, (_, i) => `indicator ${i}`);
    const alert = buildSocAlert(
      resultOf({ indicators: [...many, 42 as unknown as string] as string[] }),
    );
    expect((alert.indicators as string[]).length).toBe(20);
    expect((alert.indicators as string[]).every((i) => typeof i === "string")).toBe(true);
  });

  it("marks a test event so a SOC can tell a drill from a detection", () => {
    const alert = buildTestAlert(new Date("2026-10-16T12:00:00Z"));
    expect(alert.test).toBe(true);
    expect(alert.risk_level).toBe("HIGH_RISK");
    expect(alert.collector).toBe("phishbrain-extension");
  });
});

describe("shouldSendAlert", () => {
  it("is off unless the user opted in", () => {
    expect(shouldSendAlert(resultOf(), { ...GATE, alertsEnabled: false })).toBe(false);
  });

  it("needs a webhook to send to", () => {
    expect(shouldSendAlert(resultOf(), { ...GATE, alertWebhookUrl: "" })).toBe(false);
    expect(shouldSendAlert(resultOf(), { ...GATE, alertWebhookUrl: "   " })).toBe(false);
  });

  it("fires at the threshold, not only above it", () => {
    expect(shouldSendAlert(resultOf({ threat_score: 49 }), GATE)).toBe(false);
    expect(shouldSendAlert(resultOf({ threat_score: 50 }), GATE)).toBe(true);
  });
});

describe("sendSocAlert", () => {
  const alert = { event_type: "phishing_analysis" };

  it("reports a delivered event with its status", async () => {
    const post = vi.fn(async (_url?: unknown, _init?: RequestInit) => new Response("ok"));
    const delivery = await sendSocAlert("https://soc.example/hook", alert, {
      post: post as unknown as typeof fetch,
    });
    expect(delivery).toMatchObject({ delivered: true, status: 200, attempts: 1, error: null });
    const [url, init] = post.mock.calls[0];
    expect(url).toBe("https://soc.example/hook");
    expect(init?.method).toBe("POST");
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" });
    expect(JSON.parse(String(init?.body))).toEqual(alert);
    expect(init?.keepalive).toBe(true);
  });

  it("retries once on a server error", async () => {
    const post = vi
      .fn(async (_url?: unknown, _init?: RequestInit) => new Response("boom", { status: 503 }))
      .mockResolvedValueOnce(new Response("boom", { status: 503 }))
      .mockResolvedValueOnce(new Response("ok", { status: 200 }));
    const delivery = await sendSocAlert("https://soc.example/hook", alert, {
      post: post as unknown as typeof fetch,
    });
    expect(delivery).toMatchObject({ delivered: true, status: 200, attempts: 2 });
  });

  it("does not retry a client error, and reports what the webhook said", async () => {
    const post = vi.fn(
      async (_url?: unknown, _init?: RequestInit) =>
        new Response("no such channel", { status: 404 }),
    );
    const delivery = await sendSocAlert("https://soc.example/hook", alert, {
      post: post as unknown as typeof fetch,
    });
    expect(delivery.delivered).toBe(false);
    expect(delivery.attempts).toBe(1);
    expect(delivery.status).toBe(404);
    expect(delivery.error).toContain("404");
    expect(delivery.error).toContain("no such channel");
    expect(post).toHaveBeenCalledTimes(1);
  });

  it("reports a network failure after the last attempt", async () => {
    const post = vi.fn(async (_url?: unknown, _init?: RequestInit): Promise<Response> => {
      throw new TypeError("Failed to fetch");
    });
    const delivery = await sendSocAlert("https://soc.example/hook", alert, {
      post: post as unknown as typeof fetch,
    });
    expect(delivery).toMatchObject({ delivered: false, status: null, attempts: ALERT_ATTEMPTS });
    expect(delivery.error).toContain("Failed to fetch");
  });

  it("times out a webhook that never answers, instead of hanging", async () => {
    const post = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError")),
          );
        }),
    );
    vi.useFakeTimers();
    try {
      const pending = sendSocAlert("https://soc.example/hook", alert, {
        post: post as unknown as typeof fetch,
        attempts: 1,
        timeoutMs: 50,
      });
      await vi.advanceTimersByTimeAsync(60);
      const delivery = await pending;
      expect(delivery.delivered).toBe(false);
      expect(delivery.error).toContain("did not answer within 50 ms");
    } finally {
      vi.useRealTimers();
    }
  });

  it("ships sane default budgets", () => {
    expect(ALERT_ATTEMPTS).toBeLessThanOrEqual(3);
    expect(ALERT_ATTEMPT_TIMEOUT_MS).toBeLessThan(30_000);
  });
});

describe("background integration: SOC alerts when enabled", () => {
  let harness: ReturnType<typeof installHarness>;

  const load = async (options: HarnessOptions = {}) => {
    harness = installHarness({
      ...options,
      settings: { autoScan: true, bannerMode: "banner", riskThreshold: 50, ...options.settings },
    });
    vi.resetModules();
    await import("../src/background/service-worker");
    return harness;
  };

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    // Keep the mocked fetch from leaking into the next suite.
    harness?.fetchMock.mockClear();
  });

  it("POSTs the canonical SOC event and records the delivery", async () => {
    await load({
      settings: { alertsEnabled: true, alertWebhookUrl: "https://soc.example/hook" },
    });

    harness.emitTabsUpdated(7, "https://paypa1-security.top/login/verify");
    expect(await waitFor(() => harness.posts.length > 0)).toBe(true);

    expect(harness.posts[0].url).toBe("https://soc.example/hook");
    expect(harness.posts[0].body).toMatchObject({
      event_id: "11111111-1111-1111-1111-111111111111",
      event_type: "phishing_analysis",
      severity: "high",
      risk_level: "HIGH_RISK",
      collector: "phishbrain-extension",
      domain: "paypa1-security.top",
    });

    expect(await waitFor(() => Boolean(harness.store.lastAlert))).toBe(true);
    expect(harness.store.lastAlert).toMatchObject({ delivered: true, test: false });
  });

  it("stays silent while the user has not opted in", async () => {
    await load({ settings: { alertsEnabled: false, alertWebhookUrl: "https://soc.example/hook" } });

    harness.emitTabsUpdated(7, "https://paypa1-security.top/login/verify");
    // Give the scan and any alert it might have queued time to run.
    expect(await waitFor(() => harness.badges.length > 0)).toBe(true);
    await new Promise((r) => setTimeout(r, 50));

    expect(harness.posts).toHaveLength(0);
    expect(harness.store.lastAlert).toBeUndefined();
  });

  it("stays silent below the threshold", async () => {
    await load({
      settings: { alertsEnabled: true, alertWebhookUrl: "https://soc.example/hook" },
      backendResult: { threat_score: 20, risk_level: "SAFE" },
    });

    harness.emitTabsUpdated(7, "https://safe.example/");
    expect(await waitFor(() => harness.badges.length > 0)).toBe(true);
    await new Promise((r) => setTimeout(r, 50));

    expect(harness.posts).toHaveLength(0);
  });

  it("records a failed delivery so the options page can show it", async () => {
    await load({
      settings: { alertsEnabled: true, alertWebhookUrl: "https://soc.example/hook" },
      webhookResponder: () => new Response("channel not found", { status: 404 }),
    });

    harness.emitTabsUpdated(7, "https://paypa1-security.top/login/verify");
    expect(await waitFor(() => Boolean(harness.store.lastAlert))).toBe(true);

    expect(harness.store.lastAlert).toMatchObject({ delivered: false, status: 404 });
    expect(String((harness.store.lastAlert as { error: string }).error)).toContain("404");
  });

  it("answers the options page's test-alert request", async () => {
    await load({
      settings: { alertsEnabled: true, alertWebhookUrl: "https://soc.example/hook" },
    });

    const response = (await harness.sendRuntimeMessage({ type: "TEST_ALERT" })) as {
      delivered: boolean;
      status: number | null;
    };

    expect(response).toMatchObject({ delivered: true, status: 200 });
    expect(harness.posts[0].body).toMatchObject({ test: true, event_type: "phishing_analysis" });
    expect(harness.store.lastAlert).toMatchObject({ delivered: true, test: true });
  });

  it("refuses to test an unset webhook instead of failing obscurely", async () => {
    await load({ settings: { alertsEnabled: true, alertWebhookUrl: "  " } });

    const response = (await harness.sendRuntimeMessage({ type: "TEST_ALERT" })) as {
      delivered: boolean;
      error: string;
    };

    expect(response.delivered).toBe(false);
    expect(response.error).toContain("No alert webhook URL");
    expect(harness.posts).toHaveLength(0);
  });

  it("reports the last alert to the options page, and nothing when there is none", async () => {
    await load({ settings: { alertsEnabled: true, alertWebhookUrl: "https://soc.example/hook" } });

    expect(await harness.sendRuntimeMessage({ type: "LAST_ALERT" })).toBeNull();

    harness.emitTabsUpdated(7, "https://paypa1-security.top/login/verify");
    expect(await waitFor(() => Boolean(harness.store.lastAlert))).toBe(true);

    const stored = (await harness.sendRuntimeMessage({ type: "LAST_ALERT" })) as {
      delivered: boolean;
    };
    expect(stored.delivered).toBe(true);
  });
});

describe("message parsing for the alert actions", () => {
  it("accepts the two new message types and rejects malformed ones", () => {
    expect(parseIncomingMessage({ type: "TEST_ALERT" })).toEqual({ type: "TEST_ALERT" });
    expect(parseIncomingMessage({ type: "LAST_ALERT" })).toEqual({ type: "LAST_ALERT" });
    expect(parseIncomingMessage({ type: "SEND_ALERT_NOW" })).toBeNull();
    expect(parseIncomingMessage("TEST_ALERT")).toBeNull();
  });
});
