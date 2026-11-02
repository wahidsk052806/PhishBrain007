import type { AnalysisResult, RiskLevel } from "../types/analysis";
import { isDomainAllowlisted, type Settings } from "../lib/settings";

export function shouldScanUrl(
  url: string,
  settings: Pick<Settings, "autoScan" | "allowlist">,
): boolean {
  if (!settings.autoScan) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  if (isDomainAllowlisted(parsed.hostname, settings.allowlist)) return false;
  return true;
}

export function badgeForResult(result: AnalysisResult | null): {
  text: string;
  color: string;
  title: string;
} {
  if (!result) {
    return { text: "?", color: "#64748b", title: "PhishBrain: not scanned" };
  }
  switch (result.risk_level) {
    case "SAFE":
      return {
        text: "OK",
        color: "#10b981",
        title: `PhishBrain: Safe (score ${Math.round(result.threat_score)})`,
      };
    case "SUSPICIOUS":
      return {
        text: "!",
        color: "#f59e0b",
        title: `PhishBrain: Suspicious (score ${Math.round(result.threat_score)})`,
      };
    case "HIGH_RISK":
      return {
        text: "!!",
        color: "#ef4444",
        title: `PhishBrain: High Risk (score ${Math.round(result.threat_score)})`,
      };
    default:
      return { text: "?", color: "#64748b", title: "PhishBrain: unknown" };
  }
}

export function badgeForUnavailable(): { text: string; color: string; title: string } {
  return { text: "?", color: "#64748b", title: "PhishBrain: backend unavailable" };
}

export function shouldShowBanner(
  result: AnalysisResult,
  settings: Pick<Settings, "bannerMode" | "riskThreshold">,
): boolean {
  if (settings.bannerMode === "silent") return false;
  if (result.risk_level === "SAFE") return false;
  return result.threat_score >= settings.riskThreshold;
}

export interface CacheEntry {
  result: AnalysisResult;
  cachedAt: number;
  /** When the optional screenshot/visual pass last ran for this tab. */
  visualAt?: number;
}

export function isCacheFresh(
  entry: CacheEntry | undefined,
  url: string,
  maxAgeMs: number,
  now: number,
): entry is CacheEntry {
  if (!entry) return false;
  if (entry.result.url !== url) return false;
  return now - entry.cachedAt < maxAgeMs;
}

export interface EmailSummaryPayload {
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

export type IncomingMessage =
  | { type: "GET_RESULT"; tabId: number }
  | { type: "RESCAN"; tabId: number; url: string }
  | { type: "PROCEED_ANYWAY"; hostname: string }
  | { type: "PAGE_SUMMARY"; tabId: number; url: string; summary: Record<string, unknown> }
  | { type: "EMAIL_SUMMARY"; tabId: number; url: string; email: EmailSummaryPayload }
  | { type: "OPEN_DASHBOARD"; url: string }
  | { type: "CLEAR_VISUAL_EVIDENCE" }
  | { type: "VISUAL_EVIDENCE_STATS" }
  /** Delivery check for the opt-in SOC webhook (options page button). */
  | { type: "TEST_ALERT" }
  | { type: "LAST_ALERT" };

export function parseIncomingMessage(raw: unknown): IncomingMessage | null {
  if (!raw || typeof raw !== "object") return null;
  const msg = raw as Record<string, unknown>;
  if (msg.type === "GET_RESULT" && typeof msg.tabId === "number") {
    return { type: "GET_RESULT", tabId: msg.tabId };
  }
  if (msg.type === "RESCAN" && typeof msg.tabId === "number" && typeof msg.url === "string") {
    return { type: "RESCAN", tabId: msg.tabId, url: msg.url };
  }
  if (msg.type === "PROCEED_ANYWAY" && typeof msg.hostname === "string") {
    return { type: "PROCEED_ANYWAY", hostname: msg.hostname };
  }
  if (
    msg.type === "PAGE_SUMMARY" &&
    typeof msg.tabId === "number" &&
    typeof msg.url === "string" &&
    typeof msg.summary === "object"
  ) {
    return {
      type: "PAGE_SUMMARY",
      tabId: msg.tabId,
      url: msg.url,
      summary: msg.summary as Record<string, unknown>,
    };
  }
  if (
    msg.type === "EMAIL_SUMMARY" &&
    typeof msg.tabId === "number" &&
    typeof msg.url === "string" &&
    typeof msg.email === "object"
  ) {
    return {
      type: "EMAIL_SUMMARY",
      tabId: msg.tabId,
      url: msg.url,
      email: msg.email as EmailSummaryPayload,
    };
  }
  if (msg.type === "OPEN_DASHBOARD" && typeof msg.url === "string") {
    return { type: "OPEN_DASHBOARD", url: msg.url };
  }
  if (msg.type === "CLEAR_VISUAL_EVIDENCE") {
    return { type: "CLEAR_VISUAL_EVIDENCE" };
  }
  if (msg.type === "VISUAL_EVIDENCE_STATS") {
    return { type: "VISUAL_EVIDENCE_STATS" };
  }
  if (msg.type === "TEST_ALERT") {
    return { type: "TEST_ALERT" };
  }
  if (msg.type === "LAST_ALERT") {
    return { type: "LAST_ALERT" };
  }
  return null;
}
