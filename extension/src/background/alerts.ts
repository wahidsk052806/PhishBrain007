/**
 * SOC / SIEM alerting: turning a finished analysis into the event a security
 * team's tooling actually ingests, and getting it there verifiably.
 *
 * Why this is its own module rather than four lines inside `maybeAlert`:
 *
 * - **One schema.** The backend already builds a `SOCEvent` (event_id,
 *   severity, degraded, prefilter — see backend/app/soc/events.py) and ships it
 *   on every analysis result. The extension used to hand-roll a *different,
 *   lossier* payload instead, so a SIEM parser written against the dashboard's
 *   event did not match the same product's browser alerts. The backend's event
 *   is forwarded verbatim when present and reconstructed in the identical shape
 *   when it is not (hosted scan or demo fallback).
 * - **Verifiable delivery.** A fire-and-forget POST means a wrong webhook URL
 *   looks exactly like a working one. Delivery now has a timeout, one bounded
 *   retry, and a returned outcome the options page can show.
 */
import type { AnalysisResult, RiskLevel } from "../types/analysis";
import type { Settings } from "../lib/settings";

/** The canonical event type, matching the backend's `build_soc_event`. */
export const SOC_EVENT_TYPE = "phishing_analysis";
/** The product name a SIEM filters on. Any deployment reads `source=phishbrain`. */
export const SOC_SOURCE = "phishbrain";

/** Per-attempt budget. A webhook that accepts a connection and then stalls is
 * the common misconfiguration, so this is deliberately short. */
export const ALERT_ATTEMPT_TIMEOUT_MS = 4000;
/** One retry: enough to ride out a transient blip without holding the scan. */
export const ALERT_ATTEMPTS = 2;

const SEVERITY_BY_RISK: Record<RiskLevel, string> = {
  SAFE: "low",
  SUSPICIOUS: "medium",
  HIGH_RISK: "high",
};

/** What the backend's SOCEvent carries, plus the extension's provenance. */
export type SocAlert = Record<string, unknown>;

export interface AlertDelivery {
  delivered: boolean;
  /** HTTP status of the last attempt, when the webhook answered at all. */
  status: number | null;
  attempts: number;
  error: string | null;
  /** Epoch ms of the last attempt, so the options page can say "2 min ago". */
  at: number;
}

/** The webhook's own explanation, trimmed — a SIEM endpoint that rejects the
 * event usually says why, and that reason is the whole diagnostic. */
const MAX_ERROR_BODY_CHARS = 200;

function newEventId(): string {
  const c = globalThis.crypto as Crypto | undefined;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  return `ext-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * The alert's subject. Prefers an explicit `domain` (hosted results carry one),
 * then the analysed URL's host. The URL can be a mailbox-page string rather
 * than a URL at all, hence the guard.
 */
export function targetHost(result: AnalysisResult): string {
  if (typeof result.domain === "string" && result.domain) return result.domain;
  try {
    return new URL(result.url).hostname;
  } catch {
    return "";
  }
}

function asStringArray(value: unknown, limit?: number): string[] {
  if (!Array.isArray(value)) return [];
  const out = value.filter((v): v is string => typeof v === "string");
  return limit ? out.slice(0, limit) : out;
}

/**
 * Should this result be alerted on?
 *
 * `alertsEnabled` is the opt-in gate (nothing leaves the browser while it is
 * off) and the threshold is the same one the banner uses, so "what warns me"
 * and "what pages my SOC" cannot drift apart.
 */
export function shouldSendAlert(
  result: AnalysisResult,
  settings: Pick<Settings, "alertsEnabled" | "alertWebhookUrl" | "riskThreshold">,
): boolean {
  if (!settings.alertsEnabled) return false;
  if (!settings.alertWebhookUrl || !settings.alertWebhookUrl.trim()) return false;
  return (result.threat_score ?? 0) >= settings.riskThreshold;
}

/**
 * Build the event posted to the webhook.
 *
 * The backend's own `soc_event` wins whenever the result has one, because it is
 * the authoritative record — it carries the `event_id` a SIEM will deduplicate
 * on and the prefilter provenance. Missing fields are filled from the result so
 * a hosted or demo result still produces a complete, parseable event.
 *
 * `url`, `detected_at` and `recommended_action` are kept alongside the
 * canonical fields: they are what version 1.0.0 sent, and a relay or Slack
 * template already written against them keeps working.
 */
export function buildSocAlert(result: AnalysisResult, now: Date = new Date()): SocAlert {
  const raw =
    result.soc_event && typeof result.soc_event === "object" ? (result.soc_event as SocAlert) : {};
  const iso = now.toISOString();
  const indicators = asStringArray(raw.indicators);
  const resultIndicators = asStringArray(result.indicators);

  return {
    event_id: typeof raw.event_id === "string" && raw.event_id ? raw.event_id : newEventId(),
    analysis_id:
      typeof raw.analysis_id === "string" && raw.analysis_id ? raw.analysis_id : result.analysis_id,
    timestamp: typeof raw.timestamp === "string" && raw.timestamp ? raw.timestamp : iso,
    source: SOC_SOURCE,
    event_type:
      typeof raw.event_type === "string" && raw.event_type ? raw.event_type : SOC_EVENT_TYPE,
    severity:
      typeof raw.severity === "string" && raw.severity
        ? raw.severity
        : (SEVERITY_BY_RISK[result.risk_level] ?? "medium"),
    threat_score: typeof raw.threat_score === "number" ? raw.threat_score : result.threat_score,
    risk_level: typeof raw.risk_level === "string" ? raw.risk_level : result.risk_level,
    // The backend caps this at 20; the same cap keeps the payload SIEM-sized.
    indicators: (indicators.length ? indicators : resultIndicators).slice(0, 20),
    target_identifier:
      typeof raw.target_identifier === "string" && raw.target_identifier
        ? raw.target_identifier
        : result.url,
    degraded: asStringArray(raw.degraded).length
      ? asStringArray(raw.degraded)
      : asStringArray(result.degraded),
    prefilter: raw.prefilter ?? result.prefilter ?? null,

    // Provenance: which collector saw it, and where.
    collector: "phishbrain-extension",
    detected_at: iso,
    url: result.url,
    domain: targetHost(result),
    // A SOC analyst triaging from Slack wants the recommended action inline.
    recommended_action: result.recommended_action,
  };
}

/** 5xx and rate limiting are worth one retry; 4xx means the URL is wrong. */
function isRetryable(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

export interface SendAlertOptions {
  attempts?: number;
  timeoutMs?: number;
  /** Injectable for tests; defaults to the global `fetch`. */
  post?: typeof fetch;
}

/**
 * POST the event and report what actually happened.
 *
 * Never throws: alerting is best-effort and a broken webhook must not fail a
 * scan. The returned outcome is what lets the caller record and display it.
 */
export async function sendSocAlert(
  webhookUrl: string,
  alert: SocAlert,
  options: SendAlertOptions = {},
): Promise<AlertDelivery> {
  const attempts = Math.max(1, options.attempts ?? ALERT_ATTEMPTS);
  const timeoutMs = Math.max(1, options.timeoutMs ?? ALERT_ATTEMPT_TIMEOUT_MS);
  const post = options.post ?? fetch;

  let status: number | null = null;
  let error = "Alert was not delivered.";

  for (let attempt = 1; attempt <= attempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await post(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(alert),
        signal: controller.signal,
        // Lets the request finish if the service worker is being torn down.
        keepalive: true,
      });
      status = response.status;
      if (response.ok) {
        return { delivered: true, status, attempts: attempt, error: null, at: Date.now() };
      }
      let body = "";
      try {
        body = (await response.text()).slice(0, MAX_ERROR_BODY_CHARS);
      } catch {
        /* the status alone is still useful */
      }
      error = `Webhook answered HTTP ${response.status}${body ? `: ${body}` : ""}`;
      if (!isRetryable(response.status)) {
        return { delivered: false, status, attempts: attempt, error, at: Date.now() };
      }
    } catch (err) {
      const aborted = err instanceof DOMException && err.name === "AbortError";
      error = aborted
        ? `Webhook did not answer within ${timeoutMs} ms.`
        : `Webhook request failed (${err instanceof Error ? err.message : String(err)}).`;
    } finally {
      clearTimeout(timer);
    }
  }

  return { delivered: false, status, attempts, error, at: Date.now() };
}

/**
 * A synthetic event for the options page's "send test alert" button. Marked
 * `test: true` so a SOC operator can tell a drill from a real detection, and
 * given a score above any sane threshold so it always has a reason to exist.
 */
export function buildTestAlert(now: Date = new Date()): SocAlert {
  const iso = now.toISOString();
  const result = {
    analysis_id: `test-alert-${now.getTime().toString(36)}`,
    url: "https://phishbrain-test.example/login/verify",
    domain: "phishbrain-test.example",
    threat_score: 95,
    risk_level: "HIGH_RISK" as RiskLevel,
    confidence: 0.9,
    indicators: [
      "TEST EVENT — sent by the PhishBrain007 options page to verify webhook delivery",
      "No real page was analysed; no user was browsing this URL",
    ],
    recommended_action: "None. This is a delivery check.",
    degraded: [],
    prefilter: null,
  } as unknown as AnalysisResult;

  return { ...buildSocAlert(result, now), test: true, detected_at: iso };
}
