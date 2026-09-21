/**
 * TypeScript mirror of the backend AnalysisResult schema.
 * Keep in sync with the Python backend's Pydantic model.
 */

export type RiskLevel = "SAFE" | "SUSPICIOUS" | "HIGH_RISK";

export interface LayerResult {
  risk: number;
  indicators: string[];
  evidence: Record<string, unknown>;
}

export interface LayersBreakdown {
  email: LayerResult;
  url: LayerResult;
  domain: LayerResult;
  webpage: LayerResult;
}

/**
 * Layer evidence as the backend actually sends it.
 *
 * The Python `AnalysisResult` carries a *list* (`layer_evidence`), each entry
 * holding `layer`, `risk_score`, `indicators`, `details` and the optional
 * `unavailable` / `notes` flags — not a keyed record. `normalizeServerResult()`
 * in services/api.ts converts it into `LayersBreakdown`, which is why
 * `layers` is optional on the wire type: server payloads do not have it.
 */
export interface LayerEvidenceWire {
  layer: string;
  risk_score: number;
  indicators?: string[];
  details?: Record<string, unknown>;
  unavailable?: boolean;
  notes?: string | null;
}

export interface VisualAnalysis {
  [key: string]: unknown;
}

export interface LlmAssessment {
  [key: string]: unknown;
}

export interface SocEvent {
  [key: string]: unknown;
}

export type ServerAnalysisResult = Omit<AnalysisResult, "layers" | "url"> & {
  /** The backend names the analysed target `target`, not `url`. */
  target?: string;
  url?: string;
  /** Keyed form, only sent by endpoints that already normalize server-side. */
  layers?: LayersBreakdown;
  /** The shape the Python `AnalysisResult` model actually serialises. */
  layer_evidence?: LayerEvidenceWire[];
};

export interface AnalysisResult {
  analysis_id: string;
  url: string;
  /** Registrable domain of the analysed target (present on server results). */
  domain?: string;
  threat_score: number;
  risk_level: RiskLevel;
  confidence: number;
  indicators: string[];
  /** Normalized layer record. Guaranteed present on results in memory. */
  layers: LayersBreakdown;
  visual?: VisualAnalysis | null;
  llm_assessment?: LlmAssessment | null;
  explanation: string;
  recommended_action: string;
  soc_event?: SocEvent | null;
  latency_ms: number;
  degraded: string[];
  demo?: boolean;
}
