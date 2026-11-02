/**
 * A minimal, honest browser harness for the background service worker.
 *
 * It is deliberately *not* a full chrome.* emulation: only the surfaces the
 * service worker actually touches are implemented, and only in the
 * callback form Chrome uses, so `lib/browser.ts` takes its Chromium path
 * (the promise path is Firefox-only). Tests therefore drive the real module —
 * real listeners, real fetch calls, real storage writes — rather than a
 * reimplementation of it.
 */
import { vi } from "vitest";
import type { AnalysisResult } from "../../src/types/analysis";

type AnyFn = (...args: never[]) => unknown;

type Listener = (...args: unknown[]) => unknown;

export interface RecordedPost {
  url: string;
  body: unknown;
}

export interface HarnessOptions {
  /** Persisted settings; merged over the extension defaults. */
  settings?: Record<string, unknown>;
  /** What the backend answers a scan with. */
  backendResult?: Partial<AnalysisResult>;
  /** Answer for a webhook POST. Return a Response, or throw to simulate a network error. */
  webhookResponder?: (url: string, init?: RequestInit) => Promise<Response> | Response;
}

const DEFAULT_BACKEND_RESULT: AnalysisResult = {
  analysis_id: "ext-test-1",
  url: "https://paypa1-security.top/login/verify",
  domain: "paypa1-security.top",
  threat_score: 91,
  risk_level: "HIGH_RISK",
  confidence: 0.93,
  indicators: ["Credential form on a typosquatted domain", "Domain registered 3 days ago"],
  recommended_action: "Do not enter credentials.",
  explanation: "The URL imitates a brand and serves a credential form.",
  degraded: ["RDAP unavailable"],
  latency_ms: 42,
  layers: {
    url: { risk: 80, indicators: [], evidence: {} },
    domain: { risk: 60, indicators: [], evidence: {} },
    webpage: { risk: 0, indicators: [], evidence: {} },
    email: { risk: 0, indicators: [], evidence: {} },
  },
  prefilter: {
    model_trained: true,
    score: 74,
    method: "catboost",
    weight: 0.15,
    blended: true,
    note: "",
  },
  soc_event: {
    event_id: "11111111-1111-1111-1111-111111111111",
    analysis_id: "ext-test-1",
    timestamp: "2026-10-16T10:00:00Z",
    source: "phishbrain",
    event_type: "phishing_analysis",
    severity: "high",
    threat_score: 91,
    risk_level: "HIGH_RISK",
    indicators: ["Credential form on a typosquatted domain"],
    target_identifier: "https://paypa1-security.top/login/verify",
    degraded: ["RDAP unavailable"],
    prefilter: null,
  },
};

export function installHarness(options: HarnessOptions = {}) {
  const store: Record<string, unknown> = { ...(options.settings ?? {}) };
  const listeners: Record<string, Listener[]> = {};
  const posts: RecordedPost[] = [];
  const notifications: { title: string; message: string }[] = [];
  const badges: { tabId: number; text: string }[] = [];
  const banners: unknown[] = [];

  const on = (name: string) => ({
    addListener: (cb: Listener) => {
      (listeners[name] ||= []).push(cb);
    },
  });

  /** Chrome's callback style: the callback is always the last argument. */
  const cbStyle =
    <A extends unknown[]>(fn: (...args: A) => unknown) =>
    (...args: unknown[]) => {
      const call = [...args];
      const cb =
        typeof call[call.length - 1] === "function"
          ? (call.pop() as (...a: unknown[]) => void)
          : undefined;
      cb?.(fn(...(call as unknown as A)));
    };

  const chrome = {
    storage: {
      local: {
        get: cbStyle((keys: unknown) =>
          Array.isArray(keys)
            ? Object.fromEntries(
                (keys as string[]).filter((k) => k in store).map((k) => [k, store[k]]),
              )
            : { ...store },
        ),
        set: cbStyle((items: Record<string, unknown>) => Object.assign(store, items)),
        remove: cbStyle((keys: unknown) => {
          for (const key of [keys].flat() as string[]) delete store[key];
        }),
      },
      onChanged: on("storage.onChanged"),
    },
    tabs: {
      onUpdated: on("tabs.onUpdated"),
      onActivated: on("tabs.onActivated"),
      onRemoved: on("tabs.onRemoved"),
      get: cbStyle(() => ({ id: 1, url: "https://example.com/" })),
      query: cbStyle(() => []),
      sendMessage: cbStyle((_tabId: number, message: { type?: string }) => {
        banners.push(message);
      }),
      create: cbStyle(() => ({})),
      captureVisibleTab: cbStyle(() => ""),
    },
    runtime: {
      onMessage: on("runtime.onMessage"),
      onStartup: on("runtime.onStartup"),
      onInstalled: on("runtime.onInstalled"),
      getURL: (p: string) => `chrome-extension://phishbrain-test/${p}`,
      sendMessage: cbStyle(() => undefined),
    },
    action: {
      setBadgeText: cbStyle((d: { tabId: number; text: string }) =>
        badges.push({ tabId: d.tabId, text: d.text }),
      ),
      setBadgeBackgroundColor: cbStyle(() => undefined),
      setTitle: cbStyle(() => undefined),
    },
    notifications: {
      create: cbStyle((id: string, opts: { title: string; message: string }) => {
        notifications.push({ title: opts.title, message: opts.message });
        return id;
      }),
    },
    scripting: { executeScript: cbStyle(() => []) },
  };

  (globalThis as unknown as { chrome: unknown }).chrome = chrome;

  const backendResult = { ...DEFAULT_BACKEND_RESULT, ...(options.backendResult ?? {}) };
  const fetchMock = vi.fn(async (url: unknown, init?: RequestInit) => {
    const href = String(url);
    if (href.includes("/api/v1/analyze/")) {
      return new Response(JSON.stringify(backendResult), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    posts.push({ url: href, body: init?.body ? JSON.parse(String(init.body)) : null });
    if (options.webhookResponder) return options.webhookResponder(href, init);
    return new Response("ok", { status: 200 });
  });
  globalThis.fetch = fetchMock as unknown as typeof fetch;

  return {
    store,
    posts,
    notifications,
    badges,
    banners,
    fetchMock,
    /** True once the module under test has registered its listeners. */
    listener(name: string) {
      return listeners[name]?.[0];
    },
    /** Every listener a name has been given (a name may have several). */
    listenerCount(name: string) {
      return listeners[name]?.length ?? 0;
    },
    emitTabsUpdated(tabId: number, url: string) {
      listeners["tabs.onUpdated"]?.[0]?.(tabId, { status: "complete" }, { id: tabId, url });
    },
    /** Deliver a runtime message the way a content script or options page does. */
    sendRuntimeMessage(message: unknown, timeoutMs = 5000): Promise<unknown> {
      return new Promise((resolve) => {
        let settled = false;
        const done = (value: unknown) => {
          if (settled) return;
          settled = true;
          resolve(value);
        };
        // `true` means "an answer is coming"; anything else was answered inline.
        const async = listeners["runtime.onMessage"]?.[0]?.(message, { tab: { id: 1 } }, done);
        if (async !== true) done(undefined);
        else setTimeout(() => done(undefined), timeoutMs);
      });
    },
  };
}

/** Wait for a condition, polling — the alert path is intentionally unawaited. */
export async function waitFor(
  predicate: () => boolean,
  { timeoutMs = 3000, stepMs = 10 } = {},
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return predicate();
}
