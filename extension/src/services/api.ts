import { storage } from "../lib/browser";
import type {
  AnalysisResult,
  LayerEvidenceWire,
  LayersBreakdown,
  LayerResult,
  ServerAnalysisResult,
} from "../types/analysis";

export const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";
/**
 * The dashboard is the Vite app, which serves on 8080 — not the API port.
 * Pointing "Open dashboard" at 8000 landed the user on the FastAPI JSON root.
 */
export const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:8080";
/** Health/config probes are quick. */
const DEFAULT_TIMEOUT_MS = 8000;
/**
 * A full analysis can include a server-side page fetch AND local LLM
 * reasoning. On CPU the Ollama verdict alone can take ~45-60s, so scans must
 * wait far longer than a health probe or they silently fall back to hosted.
 */
const ANALYZE_TIMEOUT_MS = 120_000;

export class ApiError extends Error {
  code: "BACKEND_UNAVAILABLE" | "TIMEOUT" | "HTTP_ERROR" | "PARSE_ERROR";
  status?: number;

  constructor(code: ApiError["code"], message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

export interface HealthResponse {
  status: string;
  [key: string]: unknown;
}

export interface ConfigResponse {
  [key: string]: unknown;
}

export interface UrlAnalyzeRequest {
  url: string;
  /** Ask the backend to fetch the page itself (populates the webpage layer). */
  fetch_page?: boolean;
}

export interface PageAnalyzeRequest {
  url: string;
  /** Client-side DOM summary; the backend treats it as text if it cannot fetch. */
  dom_summary?: string;
  /** Ask the backend to fetch the page itself (the preferred source of truth). */
  fetch_page?: boolean;
}

export interface EmailAnalyzeRequest {
  sender?: string;
  reply_to?: string;
  display_name?: string;
  subject?: string;
  body_text?: string;
  links?: string[];
  spf?: string;
  dkim?: string;
  dmarc?: string;
}

export async function getBackendBaseUrl(): Promise<string> {
  const stored = await storage.get<{ backendUrl?: string }>("backendUrl");
  return stored.backendUrl || DEFAULT_BACKEND_URL;
}

export async function getDashboardUrl(): Promise<string> {
  const stored = await storage.get<{ dashboardUrl?: string }>("dashboardUrl");
  return stored.dashboardUrl || DEFAULT_DASHBOARD_URL;
}

function emptyLayer(): LayerResult {
  return { risk: 0, indicators: [], evidence: {} };
}

/**
 * Convert the backend's `layer_evidence` list into the keyed `layers` record.
 *
 * The backend sends `layer_evidence: [{layer, risk_score, indicators, details}]`
 * while every other part of the extension works with `layers.url.risk` etc.
 * Without this step a server result had no `layers`, so the visual brand-clone
 * merge (`applyVisualToResult`) silently found no webpage layer and never moved
 * the score — the feature looked wired up but did nothing on server results.
 * Results that already carry `layers` pass through untouched.
 */
export function normalizeServerResult(raw: ServerAnalysisResult): AnalysisResult {
  const existing = raw.layers;
  if (existing && typeof existing === "object") {
    return { ...raw, url: raw.url ?? raw.target ?? "", layers: existing };
  }

  const layers: LayersBreakdown = {
    url: emptyLayer(),
    domain: emptyLayer(),
    webpage: emptyLayer(),
    email: emptyLayer(),
  };
  const evidence: LayerEvidenceWire[] = Array.isArray(raw.layer_evidence) ? raw.layer_evidence : [];
  for (const entry of evidence) {
    const key = entry.layer as keyof LayersBreakdown;
    if (!(key in layers)) continue;
    layers[key] = {
      risk: entry.unavailable ? 0 : Number(entry.risk_score) || 0,
      indicators: Array.isArray(entry.indicators) ? entry.indicators : [],
      evidence: { ...(entry.details ?? {}) },
      raw_risk: Number(entry.risk_score) || 0,
      unavailable: entry.unavailable ?? false,
      notes: entry.notes ?? null,
    };
  }

  return { ...raw, url: raw.url ?? raw.target ?? "", layers };
}

async function request<T>(
  path: string,
  init: RequestInit,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
  baseUrlOverride?: string,
): Promise<T> {
  const baseUrl = baseUrlOverride ?? (await getBackendBaseUrl());
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(`${baseUrl.replace(/\/$/, "")}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(init.headers ?? {}),
      },
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("TIMEOUT", "Request to PhishBrain backend timed out.");
    }
    throw new ApiError(
      "BACKEND_UNAVAILABLE",
      "Backend unavailable. Check that PhishBrain backend is running and configured correctly.",
    );
  }
  clearTimeout(timer);

  if (!response.ok) {
    let bodyText = "";
    try {
      bodyText = await response.text();
    } catch {
      /* ignore */
    }
    throw new ApiError(
      "HTTP_ERROR",
      `Backend returned ${response.status}: ${bodyText || response.statusText}`,
      response.status,
    );
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError("PARSE_ERROR", "Could not parse backend response.");
  }
}

export function analyzeUrl(
  payload: UrlAnalyzeRequest,
  baseUrlOverride?: string,
): Promise<AnalysisResult> {
  return request<ServerAnalysisResult>(
    "/api/v1/analyze/url",
    {
      method: "POST",
      body: JSON.stringify({ url: payload.url, fetch_page: payload.fetch_page ?? true }),
    },
    ANALYZE_TIMEOUT_MS,
    baseUrlOverride,
  ).then(normalizeServerResult);
}

export function analyzePage(
  payload: PageAnalyzeRequest,
  baseUrlOverride?: string,
): Promise<AnalysisResult> {
  return request<ServerAnalysisResult>(
    "/api/v1/analyze/page",
    {
      method: "POST",
      body: JSON.stringify({
        url: payload.url,
        dom_summary: payload.dom_summary,
        fetch_page: payload.fetch_page ?? true,
      }),
    },
    ANALYZE_TIMEOUT_MS,
    baseUrlOverride,
  ).then(normalizeServerResult);
}

export function analyzeEmail(
  payload: EmailAnalyzeRequest,
  baseUrlOverride?: string,
): Promise<AnalysisResult> {
  // The backend's EmailAnalyzeRequest expects `body` (`body_text` is ignored).
  return request<ServerAnalysisResult>(
    "/api/v1/analyze/email",
    {
      method: "POST",
      body: JSON.stringify({
        sender: payload.sender ?? "",
        reply_to: payload.reply_to,
        display_name: payload.display_name,
        subject: payload.subject ?? "",
        body: payload.body_text ?? "",
        links: payload.links ?? [],
      }),
    },
    ANALYZE_TIMEOUT_MS,
    baseUrlOverride,
  ).then(normalizeServerResult);
}

export function getHealth(baseUrlOverride?: string): Promise<HealthResponse> {
  return request<HealthResponse>("/api/v1/health", { method: "GET" }, 5000, baseUrlOverride);
}

export function getConfig(baseUrlOverride?: string): Promise<ConfigResponse> {
  return request<ConfigResponse>("/api/v1/config", { method: "GET" }, 5000, baseUrlOverride);
}

/**
 * Hosted PhishBrain live-scan endpoint. Used when the self-hosted backend is
 * unreachable so the extension keeps working without a local Docker stack.
 */
export const DEFAULT_CLOUD_SCAN_URL = "https://www.phishbrain07.app/api/public/scan";

/**
 * Hosted PhishBrain email analysis endpoint. The extension cannot read a
 * mailbox server-side, so sender/subject/body evidence is sent here for the
 * deterministic email layer (and the first link, when present, is live
 * scanned by the server). Mirrors /api/public/scan but for messages.
 */
export const DEFAULT_CLOUD_EMAIL_URL = "https://www.phishbrain07.app/api/public/email-scan";

export async function analyzeEmailCloud(
  payload: EmailAnalyzeRequest,
  cloudUrl?: string,
): Promise<AnalysisResult> {
  const endpoint = (cloudUrl || DEFAULT_CLOUD_EMAIL_URL).replace(/\/$/, "");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: payload.sender,
        reply_to: payload.reply_to,
        display_name: payload.display_name,
        subject: payload.subject,
        body: payload.body_text,
        links: payload.links ?? [],
      }),
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("TIMEOUT", "Live email scan timed out.");
    }
    throw new ApiError("BACKEND_UNAVAILABLE", "Live email scan service unreachable.");
  }
  clearTimeout(timer);
  if (!response.ok) {
    throw new ApiError(
      "HTTP_ERROR",
      `Live email scan returned ${response.status}`,
      response.status,
    );
  }
  try {
    return normalizeServerResult((await response.json()) as ServerAnalysisResult);
  } catch {
    throw new ApiError("PARSE_ERROR", "Could not parse live email scan response.");
  }
}

export async function analyzeUrlCloud(
  payload: UrlAnalyzeRequest,
  cloudUrl?: string,
): Promise<AnalysisResult> {
  const endpoint = (cloudUrl || DEFAULT_CLOUD_SCAN_URL).replace(/\/$/, "");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: payload.url }),
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("TIMEOUT", "Live scan timed out.");
    }
    throw new ApiError("BACKEND_UNAVAILABLE", "Live scan service unreachable.");
  }
  clearTimeout(timer);
  if (!response.ok) {
    throw new ApiError("HTTP_ERROR", `Live scan returned ${response.status}`, response.status);
  }
  try {
    return normalizeServerResult((await response.json()) as ServerAnalysisResult);
  } catch {
    throw new ApiError("PARSE_ERROR", "Could not parse live scan response.");
  }
}
