/**
 * Adapter between the self-hosted FastAPI backend response and the
 * dashboard's AnalysisResult contract.
 *
 * The backend (`backend/app/schemas/analysis.py`) emits a different shape than
 * the dashboard consumes: it returns `layer_evidence` as a *list* (each entry
 * has `layer`/`risk_score`/`details`/`unavailable`) and omits `layers`,
 * `visual` and `prefilter`. Rendering that response directly crashes the
 * report view, so backend results are normalised here at the API boundary.
 *
 * Results produced locally by the demo / live-scan engine already match the
 * dashboard contract (they have a `layers` object) and are returned untouched.
 */

import type { AnalysisResult, LayerEvidence, LayerName, RiskLevel } from "./types";

const LAYER_NAMES: LayerName[] = ["url", "domain", "webpage", "email"];

/**
 * Schemes a person may paste that are not web targets. They are passed through
 * untouched so the backend guard can refuse them by name.
 */
const NON_WEB_SCHEMES = [
  "javascript",
  "data",
  "file",
  "ftp",
  "ftps",
  "blob",
  "about",
  "chrome",
  "mailto",
  "tel",
  "sms",
  "ws",
  "wss",
  "view-source",
];

/**
 * Turn what a person types into an absolute http(s) URL.
 *
 * Typing `hianime.to` used to be sent to the backend verbatim, where the SSRF
 * guard read an empty scheme and refused the whole request with
 * `Scheme '' is not allowed`. Rejecting a bare hostname is not a security
 * decision — every address bar accepts it — so it is normalised here, at the
 * boundary, before either the backend or the built-in scanner sees it.
 *
 * Mirrors `normalize_url_input` in `backend/app/core/security.py`; the backend
 * normalises as well, because it must not depend on its callers for this.
 */
/**
 * The href out of a link entry.
 *
 * The browser extension sends mail links as `text|href` (the pair form the
 * email layer compares so "paypal.com" rendered over `evil.top` is visible),
 * while the dashboard's email form sends bare URLs. Both arrive here.
 */
export function hrefOfLink(entry: string): string {
  const separator = entry.indexOf("|");
  return (separator >= 0 ? entry.slice(separator + 1) : entry).trim();
}

/**
 * The first entry that is a real web destination, hrefs unwrapped from the
 * `text|href` pair form. Used to pick the one link a scan fetches live.
 */
export function firstHttpHref(links: readonly string[]): string | null {
  for (const link of links) {
    const href = hrefOfLink(link);
    if (/^https?:\/\//i.test(href)) return href;
  }
  return null;
}

export function normalizeTargetInput(raw: string): string {
  if (typeof raw !== "string") return "";
  let text = raw.trim();
  if (!text) return "";
  text = text
    .replace(/^[<"']+/, "")
    .replace(/[>"']+$/, "")
    .trim();
  if (!text) return "";
  // Only the first whitespace-separated token: pasting a sentence containing a
  // link is common, and the rest is never a host.
  // A pasted sentence usually contains exactly one target. Prefer the token
  // that is shaped like one (has a scheme, or contains a dot) over the first
  // word, which is often prose.
  const tokens = text.split(/\s+/).filter(Boolean);
  text = (
    tokens.find((t) => /^(https?:\/\/|\/\/)/i.test(t)) ??
    tokens.find((t) => t.includes(".") && !t.startsWith(".")) ??
    tokens[0] ??
    text
  ).slice(0, 2048);

  const lower = text.toLowerCase();
  if (NON_WEB_SCHEMES.some((scheme) => lower.startsWith(`${scheme}:`))) return text;

  const explicit = /^(https?):(\/*)(.*)$/i.exec(text);
  if (explicit) {
    const scheme = (explicit[1] ?? "https").toLowerCase();
    const slashes = explicit[2] ?? "";
    const rest = explicit[3] ?? "";
    if (slashes === "//" && rest) return `${scheme}://${rest}`;
    // `https:/example.com` and `https:example.com` are both typos for a URL.
    if (rest) return `${scheme}://${rest.replace(/^\/+/, "")}`;
    return text;
  }

  if (text.startsWith("//")) return `https:${text}`;
  return `https://${text}`;
}

/**
 * Explain a machine-readable `degraded` code in a sentence.
 *
 * The report used to print the codes themselves (`webpage.fetch_failed`,
 * `ml.deterministic_fallback`), which told a reader nothing about what was
 * missing or why. Codes that are already sentences (the built-in scanner emits
 * prose) are returned unchanged.
 */
const FETCH_FAILURE_REASONS: Record<string, string> = {
  ConnectTimeout:
    "the connection attempt timed out — the host is unreachable from this network (firewall, geo-block, or the site is down)",
  ConnectError: "the host refused or dropped the connection",
  ReadTimeout: "the host accepted the connection but sent no data before the timeout",
  WriteTimeout: "the request could not be sent to the host",
  PoolTimeout: "the fetch timed out waiting for a free connection",
  TimeoutException: "the host did not respond before the timeout",
  SSLError: "the TLS handshake failed, so the certificate could not be trusted",
  TooManyRedirects: "the request was redirected too many times",
  RemoteProtocolError: "the server closed the connection mid-response",
  UnsupportedProtocol: "the URL scheme is not one the scanner fetches",
  InvalidURL: "the URL could not be parsed",
};

const DEGRADED_NOTES: Record<string, string> = {
  "ml.deterministic_fallback":
    "ML pre-filter: no trained CatBoost model was applied, so the deterministic feature-weighted fallback scored this target.",
  "llm.deterministic_fallback":
    "Local LLM: the on-device model did not return a verdict, so the assessment is derived from deterministic rule evidence.",
  "llm.timeout":
    "Local LLM: the model did not answer within the scan deadline, so no model verdict was applied.",
  "llm.error": "Local LLM: the model call failed for this scan.",
  "llm.busy":
    "Local LLM: the server was already running as many model verdicts as its CPU can handle, so this scan finished without one. The score is from the deterministic layers.",
  "llm.not_needed":
    "Local LLM: not consulted — the deterministic layers already fixed this verdict, and the model's bounded adjustment could not have changed it. This saves the model's CPU time rather than reporting a fault.",
  "visual.busy":
    "Visual layer: the server's screenshot slots were busy with other scans, so this page was not rendered for the brand comparison.",
  "visual.error": "Visual brand-clone comparison failed for this scan.",
  "visual.timeout":
    "Visual layer: the page took longer to render than the screenshot budget, so no brand comparison was made.",
  "webpage.unavailable":
    "Webpage layer: no page content was available, so nothing was parsed for credential forms or brand mismatches.",
  "webpage.timeout": "Webpage layer: the page fetch exceeded its time budget.",
  "webpage.blocked":
    "Webpage layer: the page URL was refused by the outbound safety guard, so nothing was fetched.",
  "webpage.error": "Webpage layer: the page analysis step failed.",
  "webpage.fetch_blocked":
    "Webpage layer: the page URL was refused by the outbound safety guard, so nothing was fetched.",
  "webpage.truncated":
    "Webpage layer: the page was larger than the size cap and was truncated before parsing.",
  "domain.timeout": "Domain layer: the registration and DNS lookups exceeded their time budget.",
  "domain.blocked": "Domain layer: the domain lookup was refused by the outbound safety guard.",
  "domain.error": "Domain layer: the registration or DNS lookup failed.",
  "url.error": "URL layer: the lexical URL analysis failed for this target.",
  "email.error": "Email layer: the message analysis failed.",
};

const CODE_SHAPE = /^[a-z][a-z0-9_]*\.[a-z0-9_.:]+$/i;

export function describeDegraded(code: string): string {
  const direct = DEGRADED_NOTES[code];
  if (direct) return direct;
  if (code.startsWith("webpage.http_")) {
    const status = code.slice("webpage.http_".length);
    return `Webpage layer: the host answered HTTP ${status}, so no page was served (an error body is the server's own notice, not the page).`;
  }
  if (code.startsWith("webpage.fetch_failed")) {
    const kind = code.includes(":") ? code.split(":")[1] : "";
    const reason =
      FETCH_FAILURE_REASONS[kind ?? ""] ?? "the page fetch failed before any content was read";
    return `Webpage layer: ${reason}.`;
  }
  // Already a sentence (the built-in scanner reports prose, not codes).
  if (!CODE_SHAPE.test(code)) return code;
  return code.replace(/\./g, ": ").replace(/_/g, " ");
}

/** The response shape produced by the FastAPI backend. */
interface BackendLayerEvidence {
  layer?: string;
  risk_score?: number;
  indicators?: string[];
  details?: Record<string, unknown>;
  unavailable?: boolean;
  notes?: string | null;
}

interface BackendLlmAssessment {
  verdict?: string;
  phishing_likelihood?: number;
  confidence?: number;
  key_indicators?: string[];
  reasoning_summary?: string;
  recommended_action?: string;
  score_adjustment?: number;
  /** Local model that produced the verdict; absent on the rule-based fallback. */
  model?: string | null;
}

interface BackendPrefilter {
  model_trained?: boolean;
  score?: number | null;
  method?: string;
  weight?: number;
  blended?: boolean;
  note?: string;
  layer_score?: number | null;
  /** Class-weighted probability before any calibration was applied. */
  raw_score?: number | null;
  calibrated?: boolean;
  /** Deployment-gate tier the deployed model cleared (`strict` | `triage`). */
  gate_tier?: string | null;
  gate_passed?: boolean | null;
  split?: string | null;
  trained_at?: string | null;
  /** Operating point in probability space (0-1). */
  decision_threshold?: number | null;
  score_above_threshold?: boolean | null;
}

interface BackendSocEvent {
  event_id?: string;
  analysis_id?: string;
  timestamp?: string;
  source?: string;
  event_type?: string;
  severity?: string;
  threat_score?: number;
  risk_level?: string;
  indicators?: string[];
  target_identifier?: string;
  degraded?: string[];
  prefilter?: BackendPrefilter | null;
}

interface BackendAnalysisResult {
  analysis_id?: string;
  created_at?: string;
  input_type?: string;
  target?: string;
  threat_score?: number;
  risk_level?: string;
  confidence?: number;
  indicators?: string[];
  layer_evidence?: BackendLayerEvidence[];
  prefilter?: BackendPrefilter | null;
  llm_assessment?: BackendLlmAssessment | null;
  explanation?: string;
  recommended_action?: string;
  soc_event?: BackendSocEvent | null;
  latency_ms?: number;
  degraded?: string[];
  demo?: boolean;
  /** Present only when the payload already follows the dashboard contract. */
  layers?: unknown;
  domain?: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function hostnameOf(target: string): string {
  try {
    return new URL(target.includes("://") ? target : `http://${target}`).hostname;
  } catch {
    return "";
  }
}

function emptyLayer(status: LayerEvidence["status"]): LayerEvidence {
  return { risk: 0, indicators: [], evidence: {}, status };
}

function emptyLayers(): Record<LayerName, LayerEvidence> {
  return {
    url: emptyLayer("not_applicable"),
    domain: emptyLayer("not_applicable"),
    webpage: emptyLayer("not_applicable"),
    email: emptyLayer("not_applicable"),
  };
}

function toPrefilter(
  raw: BackendPrefilter | null | undefined,
  fallbackNote: string,
): AnalysisResult["prefilter"] {
  return {
    model_trained: raw?.model_trained ?? null,
    score: typeof raw?.score === "number" ? raw.score : null,
    method: asString(raw?.method, ""),
    weight: asNumber(raw?.weight, 0),
    blended: raw?.blended === true,
    layer_score: typeof raw?.layer_score === "number" ? raw.layer_score : null,
    note: raw?.note ?? fallbackNote,
    ...provenanceOf(raw),
  };
}

/** Model provenance, shared by the main result and the SOC-event copy of it. */
function provenanceOf(raw: BackendPrefilter | null | undefined): {
  raw_score: number | null;
  calibrated: boolean;
  gate_tier: string | null;
  gate_passed: boolean | null;
  split: string | null;
  trained_at: string | null;
  decision_threshold: number | null;
  score_above_threshold: boolean | null;
} {
  return {
    raw_score: typeof raw?.raw_score === "number" ? raw.raw_score : null,
    calibrated: raw?.calibrated === true,
    gate_tier: asString(raw?.gate_tier, "") || null,
    gate_passed: typeof raw?.gate_passed === "boolean" ? raw.gate_passed : null,
    split: asString(raw?.split, "") || null,
    trained_at: asString(raw?.trained_at, "") || null,
    decision_threshold: typeof raw?.decision_threshold === "number" ? raw.decision_threshold : null,
    score_above_threshold:
      typeof raw?.score_above_threshold === "boolean" ? raw.score_above_threshold : null,
  };
}

function toClassification(value: unknown): "safe" | "suspicious" | "high_risk" | null {
  if (typeof value !== "string") return null;
  const v = value.toLowerCase();
  if (v === "safe" || v === "suspicious" || v === "high_risk") return v;
  return null;
}

export function normalizeAnalysisResult(raw: unknown): AnalysisResult {
  const r = raw as BackendAnalysisResult;

  // Already in the dashboard contract (demo engine / live-scan output).
  if (r.layers && typeof r.layers === "object" && !Array.isArray(r.layers)) {
    return raw as AnalysisResult;
  }

  const target = r.target ?? "";
  const domain = r.domain ?? hostnameOf(target);
  const threatScore = asNumber(r.threat_score);
  const riskLevel = (r.risk_level ?? "SAFE") as RiskLevel;
  const confidence = asNumber(r.confidence);
  const indicators = asStringArray(r.indicators);
  const recommendedAction = r.recommended_action ?? "";
  const degraded = asStringArray(r.degraded);

  // Backend `layer_evidence` list -> dashboard `layers` record.
  const layers = emptyLayers();
  const rawLayers = Array.isArray(r.layer_evidence) ? r.layer_evidence : [];
  for (const entry of rawLayers) {
    const leName = entry.layer as LayerName;
    if (!LAYER_NAMES.includes(leName)) continue;
    layers[leName] = {
      risk: asNumber(entry.risk_score),
      indicators: asStringArray(entry.indicators),
      evidence: entry.details ?? {},
      status: entry.unavailable === true ? "unavailable" : "ok",
    };
  }

  // An *unavailable* layer with no indicators rendered as a bare "Unavailable"
  // chip: the reader could not tell whether the feature was missing from the
  // build or the page simply never answered. Carry the backend's own reason
  // into the indicator list so it is visible in the report.
  for (const name of LAYER_NAMES) {
    const layer = layers[name];
    if (layer.status !== "unavailable" || layer.indicators.length) continue;
    const failure = layer.evidence["page_fetch_failed"];
    layer.indicators = [
      typeof failure === "string" && failure
        ? `The page could not be read: ${failure}.`
        : "No evidence was collected for this layer in this scan.",
    ];
  }

  // Visual evidence is attached to the webpage layer by the pipeline; surface
  // a best-effort view and never claim a match that was not produced.
  const pageEvidence = layers.webpage.evidence;
  const visualScore = asNumber(pageEvidence["visual_similarity_score"], Number.NaN);
  const hasVisual = Number.isFinite(visualScore);
  const possibleBrand = pageEvidence["possible_brand"];
  // The pipeline records *why* a comparison is missing (screenshot not
  // capturable, Playwright absent, page blocked, ...). Report the backend's own
  // reason rather than a generic "not included" line, which hid a real
  // explanation and read as if the feature did not exist.
  const backendVisualNotes = asStringArray(pageEvidence["visual_indicators"]);
  // The pipeline attaches a downscaled data URL of the screenshot it compared
  // (see backend `/api/v1/analyze/*`); surface it so the report can show the
  // evidence, not just the distance.
  const screenshotThumbnail = asString(pageEvidence["screenshot_data_url"], "");
  const visual: AnalysisResult["visual"] = {
    status: hasVisual ? "ok" : "unavailable",
    visual_similarity_score: hasVisual ? visualScore : null,
    possible_brand: typeof possibleBrand === "string" ? possibleBrand : null,
    screenshot_thumbnail: screenshotThumbnail || null,
    visual_indicators: hasVisual
      ? backendVisualNotes.length
        ? backendVisualNotes
        : ["Perceptual-hash comparison against the local reference set."]
      : backendVisualNotes.length
        ? backendVisualNotes
        : ["The backend reported no screenshot or perceptual-hash comparison for this target."],
  };

  // The backend reports whether the ML prefilter actually contributed to the
  // threat score (and at what weight), so the report can show it rather than
  // guess from the `degraded` list.
  const rawPrefilter = r.prefilter ?? undefined;
  const fallbackOnly = degraded.includes("ml.deterministic_fallback");
  const prefilterScore = typeof rawPrefilter?.score === "number" ? rawPrefilter.score : null;
  const prefilterWeight = asNumber(rawPrefilter?.weight, 0);
  const prefilterNote =
    rawPrefilter?.note ??
    (fallbackOnly
      ? "No trained CatBoost model; the deterministic feature-weighted fallback was used."
      : "CatBoost prefilter result reported by the backend.");
  const prefilter: AnalysisResult["prefilter"] = {
    // Null, not a guess: if the backend omits the field, this client has not
    // been told whether a trained model exists, and the `degraded` list is a
    // report about this run, not about the deployed artifact.
    model_trained: rawPrefilter?.model_trained ?? null,
    score: prefilterScore,
    method: asString(rawPrefilter?.method, ""),
    weight: prefilterWeight,
    blended: rawPrefilter?.blended === true,
    layer_score: typeof rawPrefilter?.layer_score === "number" ? rawPrefilter.layer_score : null,
    note: prefilterNote,
    // Provenance of the deployed artifact. Without these a reader cannot tell
    // whether a 42/100 score is over the model's own validated operating point
    // (it is not) or whether the model ever cleared its deployment gate.
    ...provenanceOf(rawPrefilter),
  };

  const rawLlm = r.llm_assessment ?? undefined;
  const hasLlm = rawLlm !== undefined;
  // A deliberate skip is not a fallback: the model was not asked because its
  // answer could not change the verdict (see `llm.not_needed`).
  const llmSkipped = degraded.includes("llm.not_needed");
  const llmFallback = !llmSkipped && degraded.some((d) => d.startsWith("llm."));
  const llmAssessment: AnalysisResult["llm_assessment"] = {
    status: llmSkipped ? "skipped" : hasLlm ? (llmFallback ? "fallback" : "ok") : "unavailable",
    // Named by the backend when a real local model produced the verdict; null
    // when the deterministic fallback ran, which is then truthful.
    model: asString(rawLlm?.model, "") || null,
    classification: toClassification(rawLlm?.verdict),
    confidence: typeof rawLlm?.confidence === "number" ? rawLlm.confidence : null,
    explanation: rawLlm?.reasoning_summary ?? "",
    reasoning_summary: rawLlm?.reasoning_summary ?? null,
    // The backend synthesises an assessment from deterministic evidence when
    // Ollama is unreachable; label it as such rather than as a model verdict.
    key_indicators: asStringArray(rawLlm?.key_indicators),
    recommended_action: rawLlm?.recommended_action ?? recommendedAction,
    uncertainties: [],
  };

  const rawSoc = r.soc_event;
  const socIndicators = asStringArray(rawSoc?.indicators);
  const socEvent: AnalysisResult["soc_event"] = {
    event_type: asString(rawSoc?.event_type, "phishing_detection"),
    timestamp: asString(rawSoc?.timestamp, r.created_at ?? new Date().toISOString()),
    analysis_id: asString(rawSoc?.analysis_id, r.analysis_id ?? ""),
    url: target,
    domain,
    threat_score: asNumber(rawSoc?.threat_score, threatScore),
    risk_level: (rawSoc?.risk_level ?? riskLevel) as RiskLevel,
    confidence,
    indicators: socIndicators.length ? socIndicators : indicators,
    recommended_action: recommendedAction,
    source: asString(rawSoc?.source, "phishbrain"),
    // The backend embeds the same evidence in the SOC event; fall back to the
    // top-level copy so the event never silently loses the ML contribution.
    prefilter: rawSoc?.prefilter ? toPrefilter(rawSoc.prefilter, prefilterNote) : prefilter,
  };

  return {
    analysis_id: r.analysis_id ?? "",
    created_at: r.created_at ?? new Date().toISOString(),
    target,
    domain,
    threat_score: threatScore,
    risk_level: riskLevel,
    confidence,
    indicators,
    layers,
    visual,
    prefilter,
    llm_assessment: llmAssessment,
    explanation: r.explanation ?? "",
    recommended_action: recommendedAction,
    soc_event: socEvent,
    latency_ms: asNumber(r.latency_ms),
    degraded,
    demo: r.demo === true,
  };
}
