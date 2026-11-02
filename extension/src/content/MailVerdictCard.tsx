/**
 * The verdict card PhishBrain shows *inside* the open message.
 *
 * Why a card and not only the red top banner: the banner is a page-level
 * warning, and on a mailbox it covered the message header — the one thing the
 * reader was looking at — while saying nothing about *this* message beyond a
 * colour. A card in the reading pane can state the verdict where the message
 * is, stay compact when the message is clean, and open up with the evidence
 * when it is not.
 *
 * It is rendered inside a Shadow DOM root (see `content-script.ts`), so the
 * provider's stylesheet cannot restyle it and its own Tailwind utilities
 * cannot leak into Gmail.
 */
import { useState } from "react";
import type { AnalysisResult, RiskLevel } from "../types/analysis";
import type { AlertDelivery } from "../background/alerts";

export interface MailVerdictCardProps {
  result: AnalysisResult;
  /** `gmail` / `outlook`, shown as the surface the message was read on. */
  provider: string;
  /** Webhook outcome; null while the alert is still in flight. */
  alert?: AlertDelivery | null;
  /** False when no webhook is configured at all (different from "failed"). */
  alertConfigured?: boolean;
  onOpenReport?: () => void;
  onDismiss?: () => void;
}

interface Tone {
  border: string;
  accent: string;
  chip: string;
  score: string;
  label: string;
  headline: string;
}

const TONES: Record<RiskLevel, Tone> = {
  SAFE: {
    border: "border-slate-200",
    accent: "bg-emerald-500",
    chip: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    score: "text-emerald-600",
    label: "Safe",
    headline: "No phishing indicators found in this message",
  },
  SUSPICIOUS: {
    border: "border-amber-200",
    accent: "bg-amber-500",
    chip: "bg-amber-50 text-amber-800 ring-amber-200",
    score: "text-amber-600",
    label: "Suspicious",
    headline: "Treat this message with caution",
  },
  HIGH_RISK: {
    border: "border-rose-200",
    accent: "bg-rose-500",
    chip: "bg-rose-50 text-rose-700 ring-rose-200",
    score: "text-rose-600",
    label: "High risk",
    headline: "This message shows strong phishing indicators",
  },
};

function ShieldIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className={className} fill="none">
      <path
        d="M12 3.2 5 6v5.4c0 4.1 2.8 7.6 7 9.4 4.2-1.8 7-5.3 7-9.4V6l-7-2.8Z"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path d="m8.7 11.9 2.3 2.3 4.3-4.6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function fact(label: string, value: string) {
  return (
    <div className="flex min-w-0 flex-col">
      <span className="text-[10px] font-medium uppercase tracking-wider text-slate-500">{label}</span>
      <span className="truncate text-xs font-semibold text-slate-800" title={value}>
        {value}
      </span>
    </div>
  );
}

function alertLine(alert: AlertDelivery | null | undefined, configured: boolean) {
  if (!configured) {
    return { tone: "text-slate-500", text: "SOC alert: no webhook configured (Settings → SOC/SIEM alerting)" };
  }
  if (!alert) return { tone: "text-slate-500", text: "SOC alert: sending to the configured webhook…" };
  if (alert.delivered) {
    return {
      tone: "text-emerald-700",
      text: `SOC alert delivered${alert.status ? ` · HTTP ${alert.status}` : ""}${
        alert.attempts > 1 ? ` after ${alert.attempts} attempts` : ""
      }`,
    };
  }
  return {
    tone: "text-rose-700",
    text: `SOC alert not delivered${alert.status ? ` · HTTP ${alert.status}` : ""}${
      alert.error ? ` — ${alert.error}` : ""
    }`,
  };
}

/**
 * Presentational on purpose: the shadow-DOM host and the "show me the report"
 * wiring live in the content script, so this can be rendered to static markup
 * in tests without a browser host.
 */
export default function MailVerdictCard({
  result,
  provider,
  alert,
  alertConfigured = false,
  onOpenReport,
  onDismiss,
}: MailVerdictCardProps) {
  // A clean message stays a one-line reassurance; anything else opens with its
  // evidence, because that is the case the reader needs to act on.
  const [expanded, setExpanded] = useState(result.risk_level !== "SAFE");
  const tone = TONES[result.risk_level] ?? TONES.SAFE;
  const score = Math.round(result.threat_score);
  const indicators = result.indicators.slice(0, 5);
  const alertInfo = alertLine(alert, alertConfigured);
  const sender = result.domain || result.url || "unknown sender";
  const surface = provider === "gmail" ? "Gmail" : provider === "outlook" ? "Outlook" : "Webmail";

  return (
    <div
      role="status"
      aria-label={`PhishBrain verdict for this ${surface} message: ${tone.label}, score ${score} out of 100`}
      className={`pointer-events-auto mb-3 overflow-hidden rounded-lg border ${tone.border} bg-white font-sans shadow-sm`}
      style={{ fontFamily: "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif" }}
    >
      <div className={`h-1 w-full ${tone.accent}`} />
      <div className="flex flex-wrap items-center gap-3 px-4 py-3">
        <span className={`flex size-9 shrink-0 items-center justify-center rounded-full bg-slate-900 text-white`}>
          <ShieldIcon className="size-5" />
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-bold uppercase tracking-widest text-slate-500">PhishBrain</span>
            <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ring-1 ${tone.chip}`}>
              {tone.label}
            </span>
            <span className="text-[10px] font-medium uppercase tracking-wide text-slate-400">{surface} message</span>
          </div>
          <p className="mt-0.5 truncate text-sm font-semibold text-slate-900">{tone.headline}</p>
          <p className="truncate text-[11px] text-slate-500" title={sender}>
            {sender}
          </p>
        </div>

        <div className="flex items-center gap-1">
          <span className={`text-2xl font-bold tabular-nums ${tone.score}`}>{score}</span>
          <span className="mt-2 text-[10px] font-medium text-slate-400">/100</span>
        </div>

        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-semibold text-slate-700 hover:bg-slate-100"
        >
          {expanded ? "Hide details" : "Details"}
        </button>
      </div>

      {expanded ? (
        <div className="border-t border-slate-100 px-4 pb-3 pt-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {fact("Confidence", `${Math.round((result.confidence ?? 0) * 100)}%`)}
            {fact("Indicators", String(result.indicators.length))}
            {fact("Links inspected", String(countLinks(result)))}
            {fact("Analysis", result.analysis_id.slice(0, 8))}
          </div>

          {indicators.length ? (
            <ul className="mt-3 space-y-1">
              {indicators.map((indicator) => (
                <li key={indicator} className="flex items-start gap-2 text-xs leading-snug text-slate-700">
                  <span className={`mt-1.5 size-1.5 shrink-0 rounded-full ${tone.accent}`} />
                  <span>{indicator}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-xs text-slate-600">
              No rule, model or message-level indicator fired for this message.
            </p>
          )}

          <p className={`mt-3 text-[11px] font-medium ${alertInfo.tone}`}>{alertInfo.text}</p>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            {onOpenReport ? (
              <button
                type="button"
                onClick={onOpenReport}
                className="rounded-md bg-slate-900 px-3 py-1.5 text-[11px] font-semibold text-white hover:bg-slate-800"
              >
                Open full report
              </button>
            ) : null}
            <span className="text-[10px] text-slate-400">
              Analysed locally — message text is scored on your own backend, never sent to a proprietary API.
            </span>
            {onDismiss ? (
              <button
                type="button"
                onClick={onDismiss}
                className="ml-auto rounded-md px-2 py-1 text-[11px] font-medium text-slate-500 hover:text-slate-800"
              >
                Dismiss
              </button>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** Links the email layer actually inspected, when the result carries them. */
function countLinks(result: AnalysisResult): number {
  const evidence = result.layers?.email?.evidence as Record<string, unknown> | undefined;
  const value = evidence?.link_count ?? evidence?.links_analyzed ?? evidence?.links;
  if (typeof value === "number") return value;
  if (Array.isArray(value)) return value.length;
  return 0;
}
