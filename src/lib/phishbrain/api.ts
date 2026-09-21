import type { AnalysisResult, HealthStatus } from "./types";
import { normalizeAnalysisResult } from "./normalize";
import { loadSettings } from "./settings";

export class BackendUnavailableError extends Error {
  constructor(public readonly detail: string) {
    super("Backend unavailable");
    this.name = "BackendUnavailableError";
  }
}

/**
 * The backend answered and deliberately refused this request (4xx).
 *
 * Distinct from `BackendUnavailableError` on purpose: "the backend rejected
 * this URL, here is why" is a *result*, not an outage. Treating both the same
 * made the Analyze page quietly re-run the target through the built-in scanner
 * whenever the backend declined it, so a real refusal was presented as a
 * legitimate report with no ML pre-filter, no LLM reasoning and no visual
 * layer — which reads as a broken product rather than an answered question.
 */
export class BackendRejectedError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string,
  ) {
    super(`Backend refused the request (HTTP ${status})`);
    this.name = "BackendRejectedError";
  }
}

function detailFromBody(status: number, body: string): string {
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    if (typeof parsed.detail === "string" && parsed.detail) return parsed.detail;
  } catch {
    /* not JSON */
  }
  return body.trim().slice(0, 300) || `HTTP ${status}`;
}

async function request<T>(path: string, init?: RequestInit, timeoutMs = 30_000): Promise<T> {
  const base = loadSettings().backendUrl.replace(/\/+$/, "");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${base}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      if (res.status >= 400 && res.status < 500) {
        throw new BackendRejectedError(res.status, detailFromBody(res.status, text));
      }
      throw new BackendUnavailableError(`HTTP ${res.status} from ${path}. ${text.slice(0, 300)}`);
    }
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof BackendRejectedError || err instanceof BackendUnavailableError) throw err;
    throw new BackendUnavailableError(
      err instanceof Error ? err.message : "Unknown network failure",
    );
  } finally {
    clearTimeout(timer);
  }
}

/** Analyzer round trips can include a page fetch plus local LLM reasoning on CPU. */
const ANALYZE_TIMEOUT_MS = 120_000;

export const api = {
  health: () => request<HealthStatus>("/api/v1/health", { method: "GET" }, 6000),
  config: () => request<Record<string, unknown>>("/api/v1/config", { method: "GET" }, 6000),
  // `fetch_page` tells the backend to retrieve the page itself so the webpage
  // layer (forms, credential fields, brand mismatch) is populated.
  analyzeUrl: (url: string, fetchPage = true) =>
    request<unknown>(
      "/api/v1/analyze/url",
      {
        method: "POST",
        body: JSON.stringify({ url, fetch_page: fetchPage }),
      },
      ANALYZE_TIMEOUT_MS,
    ).then(normalizeAnalysisResult),
  analyzeEmail: (payload: Record<string, unknown>) =>
    request<unknown>(
      "/api/v1/analyze/email",
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
      ANALYZE_TIMEOUT_MS,
    ).then(normalizeAnalysisResult),
  analysis: (id: string) =>
    request<unknown>(`/api/v1/analysis/${id}`, { method: "GET" }).then(normalizeAnalysisResult),
  history: async (limit = 100) => {
    const res = await request<{ items?: unknown[] }>(`/api/v1/history?limit=${limit}`, {
      method: "GET",
    });
    return { items: (res.items ?? []).map(normalizeAnalysisResult) };
  },
  alerts: async (limit = 50) => {
    const res = await request<{ items?: unknown[] }>(`/api/v1/alerts?limit=${limit}`, {
      method: "GET",
    });
    return { items: (res.items ?? []).map(normalizeAnalysisResult) };
  },
  clearHistory: () => request<{ deleted: number }>("/api/v1/history/clear", { method: "POST" }),
  feedback: (analysis_id: string, verdict: string, note: string) =>
    request<{ ok: boolean }>("/api/v1/feedback", {
      method: "POST",
      body: JSON.stringify({ analysis_id, verdict, note }),
    }),
  exportUrl: (id: string, format: "json" | "csv") =>
    `${loadSettings().backendUrl.replace(/\/+$/, "")}/api/v1/export/${id}?format=${format}`,
};
