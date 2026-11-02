import { storage } from "../lib/browser";
import type {
  AnalysisResult,
  LayerEvidenceWire,
  LayersBreakdown,
  LayerResult,
  ServerAnalysisResult,
} from "../types/analysis";

/**
 * A build-time default, so a build made for *your* deployment needs no setup on
 * a user's machine.
 *
 * A store build has to work on a stranger's device, where "Backend URL" left at
 * 127.0.0.1 points at their own computer and every scan fails. Setting
 * `VITE_PHISHBRAIN_BACKEND_URL` / `VITE_PHISHBRAIN_DASHBOARD_URL` when building
 * bakes in the deployed origins, so the first install analyses pages without a
 * trip to Options. A local `npm run dev` build leaves them unset and keeps the
 * loopback defaults, so nothing here changes day-to-day development.
 *
 * The value is validated rather than trusted: Vite stringifies whatever it is
 * given, and a stray `https://host/` (trailing slash) or a typo without a scheme
 * would otherwise become a default the extension can never reach.
 */
function buildDefault(value: string | undefined, fallback: string): string {
  const trimmed = (value ?? "").trim().replace(/\/+$/, "");
  return /^https?:\/\/[^\s]+$/i.test(trimmed) ? trimmed : fallback;
}

/**
 * The deployed API and dashboard (`deploy/README.md`).
 *
 * These are the defaults of a **production build**, because that is the build a
 * store ships to strangers: their `127.0.0.1:8000` is their own computer, which
 * has no backend, so a shipped loopback default made every scan fail on every
 * device except the developer's — and the popup then showed "Backend
 * unavailable" even though the hosted service was healthy. A development build
 * (`npm run dev`, `vite build --mode development`, the test suite) keeps the
 * loopback pair so local work still hits the local stack.
 */
export const PRODUCTION_BACKEND_URL = "https://api.phishbrain007.app";
export const PRODUCTION_DASHBOARD_URL = "https://phishbrain007.app";

/** The loopback pair used by `npm run dev` and by the test suite. */
export const DEVELOPMENT_BACKEND_URL = "http://127.0.0.1:8000";
export const DEVELOPMENT_DASHBOARD_URL = "http://127.0.0.1:8080";

/**
 * The self-hosted engine's address on *this* computer.
 *
 * Always tried, whatever the build or the stored setting says, because the two
 * situations it rescues are common and both look like a broken product:
 *
 *  - a release build ships the public API origin, so a developer running the
 *    FastAPI stack next to the browser had every scan sent to the internet and
 *    the popup announced “Backend unavailable” while `127.0.0.1:8000` was
 *    answering;
 *  - somebody who typed their server's address into Options and then went back
 *    to developing locally.
 *
 * On a stranger's device the probe is a connection refused in milliseconds, so
 * the cost of trying it there is negligible — while the cost of *not* trying it
 * is losing the only engine that can capture a screenshot and run the local
 * model.
 */
export const LOOPBACK_BACKEND_URL = "http://127.0.0.1:8000";

/** True for an address that can only ever reach this computer. */
export function isLoopbackUrl(url: string): boolean {
  try {
    const host = new URL(url.trim()).hostname.trim().toLowerCase().replace(/^\[|\]$/g, "");
    return (
      host === "localhost" ||
      host === "::1" ||
      host === "0.0.0.0" ||
      host.startsWith("127.") ||
      host.endsWith(".localhost")
    );
  } catch {
    return false;
  }
}

/**
 * Bases to try for the self-hosted engine, in order: the configured one first,
 * then loopback when they differ.
 *
 * The fallback is the literal `127.0.0.1` rather than `localhost`: on a machine
 * whose hosts file resolves `localhost` to `::1`, uvicorn bound to IPv4 answers
 * `127.0.0.1` and refuses `localhost` — which is one way a perfectly healthy
 * backend comes to look dead.
 */
export function backendCandidates(configured: string): string[] {
  const trimmed = (configured ?? "").trim().replace(/\/+$/, "");
  const candidates = trimmed ? [trimmed] : [];
  if (!isLoopbackUrl(trimmed)) candidates.push(LOOPBACK_BACKEND_URL);
  return candidates;
}

/**
 * First self-hosted base that answers its health check, or null.
 *
 * Used by the popup, the Options page and the worker so all three agree on
 * which engine is actually in use, instead of each probing one hard-coded
 * address and disagreeing.
 */
export async function findReachableBackend(configured: string): Promise<string | null> {
  for (const base of backendCandidates(configured)) {
    try {
      await getHealth(base);
      return base;
    } catch {
      /* try the next candidate */
    }
  }
  return null;
}

/**
 * Pick the defaults a build ships with.
 *
 * Extracted so the choice is testable: a store build must ship the deployed
 * origins, a development build must ship loopback, and an explicit
 * `VITE_PHISHBRAIN_*` value overrides either.
 */
export function buildDefaults(input: {
  deployed: boolean;
  backendOverride?: string;
  dashboardOverride?: string;
}): { backend: string; dashboard: string } {
  const fallbackBackend = input.deployed ? PRODUCTION_BACKEND_URL : DEVELOPMENT_BACKEND_URL;
  const fallbackDashboard = input.deployed ? PRODUCTION_DASHBOARD_URL : DEVELOPMENT_DASHBOARD_URL;
  return {
    backend: buildDefault(input.backendOverride, fallbackBackend),
    dashboard: buildDefault(input.dashboardOverride, fallbackDashboard),
  };
}

const BUILD_DEFAULTS = buildDefaults({
  deployed: Boolean(import.meta.env?.PROD),
  backendOverride: import.meta.env?.VITE_PHISHBRAIN_BACKEND_URL,
  dashboardOverride: import.meta.env?.VITE_PHISHBRAIN_DASHBOARD_URL,
});

export const DEFAULT_BACKEND_URL = BUILD_DEFAULTS.backend;
/**
 * The dashboard is the Vite app, which serves on 8080 — not the API port.
 * Pointing "Open dashboard" at 8000 landed the user on the FastAPI JSON root.
 * On a deployment this is the public site origin, which also serves the hosted
 * `/api/public/*` scans the extension falls back to.
 */
export const DEFAULT_DASHBOARD_URL = BUILD_DEFAULTS.dashboard;
/** Health/config probes are quick. */
const DEFAULT_TIMEOUT_MS = 8000;
/**
 * A full analysis can include a server-side page fetch AND local LLM
 * reasoning. On CPU the Ollama verdict alone can take ~45-60s, so scans must
 * wait far longer than a health probe or they silently fall back to hosted.
 */
/**
 * How long a full scan may take before the worker gives up on it.
 *
 * Must exceed the backend's own worst case, not the happy path: the pipeline
 * allows ANALYSIS_TIMEOUT_SECONDS (20 s) for the network layers,
 * LLM_TIMEOUT_SECONDS (150 s) for the verdict and VISUAL_TIMEOUT_SECONDS
 * (30 s) for the render, so a legitimate scan can approach 200 s. Measured on
 * this machine: 182.6 s for `netflix.com` with the model under load. The old
 * 120 s cap aborted such scans mid-verdict, which left the popup showing the
 * phase-1 quick verdict forever — no model card, no screenshot — and read as
 * "the LLM and visual layers do not work".
 */
const ANALYZE_TIMEOUT_MS = 300_000;

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
  /**
   * Run the local LLM verdict. `false` gives the deterministic layers (URL,
   * domain, pre-filter, DOM) in about a second, which is what lets the popup
   * show a verdict immediately and replace it when the model answers.
   */
  use_llm?: boolean;
}

export interface PageAnalyzeRequest {
  url: string;
  /** Client-side DOM summary; the backend treats it as text if it cannot fetch. */
  dom_summary?: string;
  /** Ask the backend to fetch the page itself (the preferred source of truth). */
  fetch_page?: boolean;
}

export interface EmailAnalyzeRequest {
  /** Same fast path as URL scans: skip the local model for a quick verdict. */
  use_llm?: boolean;
  sender?: string;
  reply_to?: string;
  display_name?: string;
  subject?: string;
  body_text?: string;
  /**
   * `text|href` pairs when the parser has both (Gmail/Outlook), bare hrefs
   * otherwise. The pair form is what lets the email layer compare a link's
   * visible text against the domain it really goes to.
   */
  links?: string[];
  has_attachments?: boolean;
  /** The sender quoted an earlier message; that quoted text was not scored. */
  has_quoted_content?: boolean;
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

  // The backend attaches the screenshot comparison to the webpage layer's
  // details (`visual_similarity_score`, `screenshot_data_url`, …), while the
  // popup renders `result.visual`. Nothing copied one to the other, so every
  // server result told the user visual analysis was “unavailable for this
  // result” even on a scan that had captured and compared a screenshot.
  const page = layers.webpage.evidence as Record<string, unknown>;
  const similarity =
    typeof page.visual_similarity_score === "number" ? page.visual_similarity_score : null;
  const visualNotes = Array.isArray(page.visual_indicators)
    ? page.visual_indicators.filter((v): v is string => typeof v === "string")
    : [];
  const thumbnail =
    typeof page.screenshot_data_url === "string" && page.screenshot_data_url
      ? page.screenshot_data_url
      : null;
  const visual =
    similarity !== null || visualNotes.length || thumbnail
      ? {
          status: similarity !== null ? "ok" : "unavailable",
          visual_similarity_score: similarity,
          possible_brand: typeof page.possible_brand === "string" ? page.possible_brand : null,
          visual_indicators: visualNotes,
          screenshot_thumbnail: thumbnail,
        }
      : null;

  // The backend omits `llm_assessment` when it deliberately did not ask the
  // model (the deterministic layers already fixed the verdict), which read as
  // "no LLM layer was applied" — the same wording a broken Ollama produced.
  // Name the decision so the popup does not blame a missing feature.
  const skippedLlm = (Array.isArray(raw.degraded) ? raw.degraded : []).includes(
    "llm.not_needed",
  );
  const llmAssessment =
    raw.llm_assessment ??
    (skippedLlm
      ? {
          status: "skipped",
          explanation:
            "Not consulted: the URL, domain and page layers already fixed this verdict, so the model's bounded adjustment could not have changed it. The scan skipped its CPU time rather than restating the answer.",
        }
      : null);

  return {
    ...raw,
    url: raw.url ?? raw.target ?? "",
    layers,
    ...(visual ? { visual } : {}),
    ...(llmAssessment ? { llm_assessment: llmAssessment } : {}),
  };
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
      body: JSON.stringify({
        url: payload.url,
        fetch_page: payload.fetch_page ?? true,
        use_llm: payload.use_llm ?? true,
      }),
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
        has_attachments: payload.has_attachments ?? false,
        has_quoted_content: payload.has_quoted_content ?? false,
        use_llm: payload.use_llm ?? true,
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
 *
 * Deliberately **empty**: the public scan routes ship inside the dashboard
 * deployment, so the endpoint belongs to the user's own dashboard origin and is
 * derived from it (`lib/hosted.ts`). Shipping a hard-coded third-party domain
 * here meant a fresh install on a device without a local backend pointed its
 * fallback at somebody else's host — or at one that no longer resolves — and
 * scanned nothing.
 */
export const DEFAULT_CLOUD_SCAN_URL = "";

/**
 * Hosted PhishBrain email analysis endpoint. The extension cannot read a
 * mailbox server-side, so sender/subject/body evidence is sent here for the
 * deterministic email layer (and the first link, when present, is live
 * scanned by the server). Mirrors /api/public/scan but for messages.
 *
 * Empty by default for the same reason as `DEFAULT_CLOUD_SCAN_URL`.
 */
export const DEFAULT_CLOUD_EMAIL_URL = "";

/** A hosted scan without an endpoint is a configuration error, not a network one. */
function requireEndpoint(raw: string, kind: "scan" | "email"): string {
  const endpoint = raw.trim().replace(/\/+$/, "");
  if (!endpoint) {
    throw new ApiError(
      "BACKEND_UNAVAILABLE",
      `No hosted ${kind} endpoint is configured. Deploy the dashboard, then set its URL as the Dashboard URL in the extension options (the live-scan endpoint is derived from it).`,
    );
  }
  return endpoint;
}

export async function analyzeEmailCloud(
  payload: EmailAnalyzeRequest,
  cloudUrl?: string,
): Promise<AnalysisResult> {
  const endpoint = requireEndpoint(cloudUrl || DEFAULT_CLOUD_EMAIL_URL, "email");
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
        has_attachments: payload.has_attachments ?? false,
        has_quoted_content: payload.has_quoted_content ?? false,
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
  const endpoint = requireEndpoint(cloudUrl || DEFAULT_CLOUD_SCAN_URL, "scan");
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
