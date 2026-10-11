import type { AnalysisResult, HealthStatus } from "./types";
import { normalizeAnalysisResult, normalizeTargetInput } from "./normalize";
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

/**
 * One frame of the backend's Server-Sent Event stream for `/analyze/url/stream`.
 *
 * `provisional` carries a scored result over the deterministic layers only, so
 * it can arrive in seconds while the LLM verdict is still being computed.
 */
export type UrlStreamEvent =
  | { type: "started"; target?: string }
  | { type: "layer" | "layers"; layer_evidence?: unknown[] }
  | { type: "prefilter"; prefilter?: unknown }
  | ({ type: "provisional"; provisional?: boolean } & Record<string, unknown>)
  | { type: "llm"; llm_assessment?: unknown; layer_evidence?: unknown[] }
  | { type: "final"; result?: unknown }
  | { type: "error"; message?: string };

/**
 * Fold one streamed frame into the accumulator.
 *
 * Each frame is a *delta* over the same response shape the non-streaming
 * endpoint returns, which is deliberate: it means `normalizeAnalysisResult`
 * can be reused unchanged for interim renders.
 */
function applyStreamEvent(acc: Record<string, unknown>, event: UrlStreamEvent): void {
  switch (event.type) {
    case "started":
      if (typeof event.target === "string") acc["target"] = event.target;
      break;
    case "layer":
    case "layers":
      if (Array.isArray(event.layer_evidence)) acc["layer_evidence"] = event.layer_evidence;
      break;
    case "prefilter":
      if (event.prefilter) acc["prefilter"] = event.prefilter;
      break;
    case "provisional": {
      const { type: _type, ...fields } = event;
      Object.assign(acc, fields);
      acc["provisional"] = true;
      break;
    }
    case "llm":
      acc["llm_assessment"] = event.llm_assessment ?? null;
      if (Array.isArray(event.layer_evidence)) acc["layer_evidence"] = event.layer_evidence;
      acc["provisional"] = false;
      break;
    default:
      break;
  }
}

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
        // Every request goes through the same normaliser as the form, so no
        // caller can reintroduce the scheme-less target that used to be
        // refused with "Scheme '' is not allowed".
        body: JSON.stringify({ url: normalizeTargetInput(url), fetch_page: fetchPage }),
      },
      ANALYZE_TIMEOUT_MS,
    ).then(normalizeAnalysisResult),
  /**
   * Scan a URL and stream the result as it is produced.
   *
   * The local LLM verdict is the slow part of a scan on CPU-only hardware
   * (~30-45s of a ~40s scan). This hands the caller each deterministic layer,
   * the pre-filter contribution and a labelled provisional score as soon as
   * they exist, then the verdict — so the report fills in progressively instead
   * of showing nothing until the whole pipeline finishes.
   */
  analyzeUrlStream: async (
    url: string,
    handlers: {
      /** Interim, normalised result. Already flagged `provisional: true`. */
      onPartial?: (partial: AnalysisResult) => void;
      onFinal: (result: AnalysisResult) => void;
    },
  ): Promise<void> => {
    const base = loadSettings().backendUrl.replace(/\/+$/, "");
    let res: Response;
    try {
      res = await fetch(`${base}/api/v1/analyze/url/stream`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "text/event-stream" },
        body: JSON.stringify({ url: normalizeTargetInput(url), fetch_page: true }),
      });
    } catch (err) {
      throw new BackendUnavailableError(
        err instanceof Error ? err.message : "Unknown network failure",
      );
    }
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      if (res.status >= 400 && res.status < 500) {
        throw new BackendRejectedError(res.status, detailFromBody(res.status, text));
      }
      throw new BackendUnavailableError(
        `HTTP ${res.status} from /api/v1/analyze/url/stream. ${text.slice(0, 300)}`,
      );
    }
    if (!res.body) throw new BackendUnavailableError("The backend returned no event stream.");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const acc: Record<string, unknown> = {};
    let buffer = "";
    let settled = false;

    const handleFrame = (raw: string): void => {
      const dataLine = raw.split("\n").find((line) => line.startsWith("data:"));
      if (!dataLine) return;
      let event: UrlStreamEvent;
      try {
        event = JSON.parse(dataLine.slice(5).trim()) as UrlStreamEvent;
      } catch {
        return; // A malformed frame is skipped, not fatal to the scan.
      }
      if (event.type === "error") {
        throw new BackendUnavailableError(
          event.message ?? "The backend stopped the scan before producing a verdict.",
        );
      }
      if (event.type === "final") {
        settled = true;
        handlers.onFinal(normalizeAnalysisResult(event.result ?? acc));
        return;
      }
      applyStreamEvent(acc, event);
      if (handlers.onPartial) {
        handlers.onPartial({ ...normalizeAnalysisResult(acc), provisional: true });
      }
    };

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let boundary = buffer.indexOf("\n\n");
        while (boundary >= 0) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          handleFrame(frame);
          if (settled) return;
          boundary = buffer.indexOf("\n\n");
        }
      }
    } finally {
      // Releasing the reader lets the backend's generator see the disconnect.
      await reader.cancel().catch(() => undefined);
    }

    if (!settled) throw new BackendUnavailableError("The scan stream ended without a verdict.");
  },
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
  /** The backend's active screenshot-evidence retention policy. */
  visualEvidencePolicy: () =>
    request<{ retention_days: number; auto_purge_enabled: boolean; screenshot_mode: string }>(
      "/api/v1/visual-evidence/policy",
      { method: "GET" },
      6000,
    ),
  /**
   * Strip every stored screenshot thumbnail now, keeping the analyses. The
   * backend purges aged evidence on its own clock; this is the one-click
   * "stop storing what I looked at" action.
   */
  clearVisualEvidence: () =>
    request<{ cleared: number }>("/api/v1/visual-evidence/clear", { method: "POST" }),
  feedback: (analysis_id: string, verdict: string, note: string) =>
    request<{ ok: boolean }>("/api/v1/feedback", {
      method: "POST",
      body: JSON.stringify({ analysis_id, verdict, note }),
    }),
  exportUrl: (id: string, format: "json" | "csv") =>
    `${loadSettings().backendUrl.replace(/\/+$/, "")}/api/v1/export/${id}?format=${format}`,
};
