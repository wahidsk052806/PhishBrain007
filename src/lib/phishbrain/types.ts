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
}

export interface LLMAssessment {
  status: "ok" | "unavailable" | "fallback";
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
  model_trained: boolean;
  score: number | null;
  /** `catboost` when a trained model scored it, `deterministic_fallback` otherwise. */
  method: string;
  /** Share of the base score the prefilter carried (0 when not blended). */
  weight: number;
  blended: boolean;
  note: string;
  /** Multi-layer score before the prefilter was folded in. */
  layer_score: number | null;
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
}

export interface HealthStatus {
  status: "ok" | "degraded";
  version: string;
  components: Record<string, "ok" | "unavailable" | string>;
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
