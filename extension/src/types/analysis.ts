/**
 * TypeScript mirror of the backend AnalysisResult schema.
 * Keep in sync with the Python backend's Pydantic model.
 */

export type RiskLevel = "SAFE" | "SUSPICIOUS" | "HIGH_RISK";

export interface LayerResult {
  risk: number;
  indicators: string[];
  evidence: Record<string, unknown>;
  /** Raw risk score before the layer's own unavailable/not-applicable treament. */
  raw_risk?: number;
  /** True when the layer produced no evidence (e.g. no email context supplied). */
  unavailable?: boolean;
  notes?: string | null;
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
  status?: string;
  visual_similarity_score?: number | null;
  possible_brand?: string | null;
  visual_indicators?: string[];
  hash_distance?: number | null;
  phash?: string | null;
  visual_signal?: string;
  /** Downscaled JPEG data URL of the captured screenshot, for display. */
  screenshot_thumbnail?: string | null;
  /** Bundled preview of the matched brand, for a side-by-side comparison. */
  reference_thumbnail?: string | null;
  [key: string]: unknown;
}

export interface LlmAssessment {
  [key: string]: unknown;
}

export interface SocEvent {
  [key: string]: unknown;
}

/**
 * The ML pre-filter's contribution, exactly as the backend sends it.
 *
 * The provenance fields are what let a popup answer "is 42/100 bad?":
 * `decision_threshold` is the operating point the model was validated at and
 * `score_above_threshold` compares the score to it, while `gate_tier` records
 * which deployment bar the model cleared (`strict` = fit to decide alone,
 * `triage` = fit to be one disclosed signal among several).
 */
export interface PrefilterEvidenceWire {
  /**
   * Whether a trained CatBoost model exists and was consulted. Null means the
   * prefilter was never asked (results produced without the backend).
   */
  model_trained: boolean | null;
  score: number | null;
  method: string;
  weight: number;
  blended: boolean;
  note: string;
  layer_score?: number | null;
  /** Class-weighted probability before any calibration was applied. */
  raw_score?: number | null;
  calibrated?: boolean;
  gate_tier?: string | null;
  gate_passed?: boolean | null;
  /** The split the model's metrics were measured on. */
  split?: string | null;
  trained_at?: string | null;
  decision_threshold?: number | null;
  score_above_threshold?: boolean | null;
}

export type ServerAnalysisResult = Omit<AnalysisResult, "layers" | "url"> & {
  /** The backend names the analysed target `target`, not `url`. */
  target?: string;
  url?: string;
  /** Keyed form, only sent by endpoints that already normalize server-side. */
  layers?: LayersBreakdown;
  /** The shape the Python `AnalysisResult` model actually serialises. */
  layer_evidence?: LayerEvidenceWire[];
  /** ML pre-filter contribution and the provenance of the deployed model. */
  prefilter?: PrefilterEvidenceWire | null;
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
  /** ML pre-filter contribution and model provenance (server results only). */
  prefilter?: PrefilterEvidenceWire | null;
  visual?: VisualAnalysis | null;
  llm_assessment?: LlmAssessment | null;
  explanation: string;
  recommended_action: string;
  soc_event?: SocEvent | null;
  latency_ms: number;
  degraded: string[];
  demo?: boolean;
}
