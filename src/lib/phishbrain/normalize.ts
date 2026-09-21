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
    model_trained: raw?.model_trained ?? false,
    score: typeof raw?.score === "number" ? raw.score : null,
    method: asString(raw?.method, ""),
    weight: asNumber(raw?.weight, 0),
    blended: raw?.blended === true,
    layer_score: typeof raw?.layer_score === "number" ? raw.layer_score : null,
    note: raw?.note ?? fallbackNote,
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
  const visual: AnalysisResult["visual"] = {
    status: hasVisual ? "ok" : "unavailable",
    visual_similarity_score: hasVisual ? visualScore : null,
    possible_brand: typeof possibleBrand === "string" ? possibleBrand : null,
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
    model_trained: rawPrefilter?.model_trained ?? !fallbackOnly,
    score: prefilterScore,
    method: asString(rawPrefilter?.method, ""),
    weight: prefilterWeight,
    blended: rawPrefilter?.blended === true,
    layer_score: typeof rawPrefilter?.layer_score === "number" ? rawPrefilter.layer_score : null,
    note: prefilterNote,
  };

  const rawLlm = r.llm_assessment ?? undefined;
  const hasLlm = rawLlm !== undefined;
  const llmFallback = degraded.some((d) => d.startsWith("llm."));
  const llmAssessment: AnalysisResult["llm_assessment"] = {
    status: hasLlm ? (llmFallback ? "fallback" : "ok") : "unavailable",
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
