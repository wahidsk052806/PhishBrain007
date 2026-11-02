/**
 * Shared PhishBrain analysis contract.
 * Mirrors the Pydantic schemas exposed by the FastAPI backend
 * (backend/app/schemas/analysis.py) and the extension type mirror
 * (extension/src/types/analysis.ts).
 */

export type RiskLevel = "SAFE" | "SUSPICIOUS" | "HIGH_RISK";
export type LayerName = "email" | "url" | "domain" | "webpage";

export interface LayerEvidence {
  /** 0-100 layer risk produced by deterministic feature extraction. */
  risk: number;
  indicators: string[];
  /** Raw structured evidence. Values may be the string "unavailable". */
  evidence: Record<string, unknown>;
  status: "ok" | "unavailable" | "not_applicable";
}

export interface VisualEvidence {
  status: "ok" | "unavailable";
  visual_similarity_score: number | null;
  possible_brand: string | null;
  visual_indicators: string[];
  /**
   * Downscaled data URL of the screenshot this verdict was scored on, when the
   * backend is configured to return it (VITE/BACKEND `VISUAL_SCREENSHOT_MODE`).
   * `pixels` gives a JPEG, `wireframe` an edge-only PNG. Null when off.
   */
  screenshot_thumbnail?: string | null;
}

export interface LLMAssessment {
  /**
   * `skipped` is a deliberate decision, not a fault: the deterministic layers
   * already fixed the verdict, so the model's bounded adjustment could not have
   * changed it and its CPU time was not spent. See `llm.not_needed`.
   */
  status: "ok" | "unavailable" | "fallback" | "skipped";
  model: string | null;
  classification: "safe" | "suspicious" | "high_risk" | null;
  confidence: number | null;
  explanation: string;
  /** Human-readable summary of the model's structured assessment (self-hosted backend with Ollama). */
  reasoning_summary?: string | null;
  /** Concrete signals the model based its verdict on. */
  key_indicators?: string[];
  recommended_action: string;
  uncertainties: string[];
}

export interface SocEvent {
  event_type: string;
  timestamp: string;
  analysis_id: string;
  url: string;
  domain: string;
  threat_score: number;
  risk_level: RiskLevel;
  confidence: number;
  indicators: string[];
  recommended_action: string;
  source: string;
  /** Machine-learning contribution to the score, for SIEM/SOAR consumers. */
  prefilter: PrefilterEvidence | null;
}

/**
 * What the ML prefilter contributed to the final score.
 *
 * `blended` is false whenever the deterministic fallback produced the number
 * (or no URL was available), in which case `score` contributed nothing.
 */
export interface PrefilterEvidence {
  /**
   * Whether a trained CatBoost model exists **and was consulted** for this
   * result. Null means the question was never asked — the in-browser engines
   * (demo and built-in live scanner) never call the backend's prefilter, so
   * they have nothing to say about the deployed artifact. Reporting `false`
   * there claimed "no trained model" on a deployment that has one.
   */
  model_trained: boolean | null;
  score: number | null;
  /**
   * `catboost` when a trained model scored it, `deterministic_fallback` when the
   * backend fell back to its rule-based scoring, `not_consulted` when no
   * prefilter ran at all (in-browser engines).
   */
  method: string;
  /** Share of the base score the prefilter carried (0 when not blended). */
  weight: number;
  blended: boolean;
  note: string;
  /** Multi-layer score before the prefilter was folded in. */
  layer_score: number | null;
  /** The model's own class-weighted probability, before calibration. */
  raw_score: number | null;
  calibrated: boolean;
  /**
   * Which deployment-gate tier the deployed model cleared, if it declares one
   * (`strict` = fit to decide alone, `triage` = fit to be one disclosed signal
   * among several). Null when the metadata predates the tiering.
   */
  gate_tier: string | null;
  gate_passed: boolean | null;
  /** The split the model's metrics were measured on. */
  split: string | null;
  trained_at: string | null;
  /**
   * The operating point the model was validated at, in probability space. A
   * score below it is not "suspicious" however large the number looks, which is
   * what `score_above_threshold` reports directly.
   */
  decision_threshold: number | null;
  score_above_threshold: boolean | null;
}

export interface AnalysisResult {
  analysis_id: string;
  created_at: string;
  target: string;
  domain: string;
  threat_score: number;
  risk_level: RiskLevel;
  confidence: number;
  indicators: string[];
  layers: Record<LayerName, LayerEvidence>;
  visual: VisualEvidence;
  prefilter: PrefilterEvidence;
  llm_assessment: LLMAssessment;
  explanation: string;
  recommended_action: string;
  soc_event: SocEvent;
  latency_ms: number;
  /** Human-readable notes about degraded / unavailable sub-systems. */
  degraded: string[];
  /** True when the result was produced by the labelled demo pipeline. */
  demo: boolean;
  /**
   * True while this is an interim result: the deterministic layers and the
   * pre-filter have finished but the local LLM verdict is still being produced
   * server-side (see `api.analyzeUrlStream`). The score is real, but it can
   * still move when the LLM adjustment is applied.
   */
  provisional?: boolean;
}

/**
 * `/api/v1/health` as the backend actually answers it.
 *
 * The old shape (`version` + a `components` map) never matched the API, so the
 * badge could only ever read `status` — the one field that says "degraded"
 * without saying which subsystem was down.
 */
export interface HealthStatus {
  status: "ok" | "degraded";
  ollama: string;
  database: string;
  cache: string;
  app_env: string;
  database_backend?: string;
  cache_backend?: string;
}

export const RISK_LABEL: Record<RiskLevel, string> = {
  SAFE: "Safe",
  SUSPICIOUS: "Suspicious",
  HIGH_RISK: "High risk",
};

export function riskFromScore(
  score: number,
  safeThreshold = 30,
  suspiciousThreshold = 70,
): RiskLevel {
  if (score <= safeThreshold) return "SAFE";
  if (score <= suspiciousThreshold) return "SUSPICIOUS";
  return "HIGH_RISK";
}
