import type { AnalysisResult } from "../types/analysis";
import RiskBadge from "../components/RiskBadge";
import ThreatScore from "../components/ThreatScore";
import LayerBreakdown from "../components/LayerBreakdown";
import { LlmCard, PrefilterCard, VisualCard } from "../components/SignalCards";

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col rounded-md border border-slate-800/80 bg-slate-950/40 px-2 py-1.5">
      <span className="text-[9px] uppercase tracking-wide text-slate-500">{label}</span>
      <span className="truncate text-[11px] font-medium text-slate-200" title={value}>
        {value}
      </span>
    </div>
  );
}

/** Accent per verdict, so the popup's first glance is a colour, not a word. */
const VERDICT_ACCENT: Record<AnalysisResult["risk_level"], string> = {
  SAFE: "bg-emerald-500",
  SUSPICIOUS: "bg-amber-500",
  HIGH_RISK: "bg-rose-500",
};

const VERDICT_HEADLINE: Record<AnalysisResult["risk_level"], string> = {
  SAFE: "No phishing indicators found",
  SUSPICIOUS: "Treat this target with caution",
  HIGH_RISK: "Strong phishing indicators detected",
};

/**
 * The full, explainable report shown in the popup. Kept presentational and
 * side-effect free so it can be rendered to markup in tests — the popup shell
 * owns the browser API calls, this owns the explanation.
 */
export default function PopupReport({ result }: { result: AnalysisResult }) {
  return (
    <div className="flex flex-col gap-3">
      {result.provisional && (
        <div className="rounded-md border border-sky-800 bg-sky-950/40 p-2 text-[11px] text-sky-200">
          <span className="font-semibold uppercase">Quick verdict</span> — URL, domain and ML
          layers only. The page fetch, screenshot comparison and local model are still running; this
          report updates when they finish.
        </div>
      )}

      {result.demo && (
        <div className="rounded-md border border-sky-800 bg-sky-950/40 p-2 text-[11px] text-sky-200">
          <span className="font-semibold uppercase">Demo data</span> — this verdict was produced
          offline from a synthetic sample. No live request was made.
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/60">
        <div className={`h-1 w-full ${VERDICT_ACCENT[result.risk_level]}`} />
        <div className="p-3">
          <div className="mb-1 flex items-center justify-between gap-2">
            <RiskBadge level={result.risk_level} />
            <span className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
              Verdict
            </span>
          </div>
          <p className="mb-1 text-[12px] font-semibold text-slate-100">
            {VERDICT_HEADLINE[result.risk_level]}
          </p>
          <p className="mb-2 truncate font-mono text-[10px] text-slate-500" title={result.url}>
            {result.url}
          </p>
          <ThreatScore score={result.threat_score} />
          <dl className="mt-3 grid grid-cols-3 gap-2 border-t border-slate-800 pt-2">
            <Metric label="Confidence" value={`${Math.round((result.confidence ?? 0) * 100)}%`} />
            <Metric label="Latency" value={`${Math.round(result.latency_ms)} ms`} />
            <Metric label="Analysis ID" value={result.analysis_id} />
          </dl>
        </div>
      </div>

      {result.indicators.length > 0 && (
        <section
          aria-label="Top indicators"
          className="rounded-md border border-slate-800 bg-slate-900/60 p-2.5"
        >
          <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
            Why this verdict
          </h3>
          <ul className="list-disc space-y-0.5 pl-4 text-[11px] text-slate-300">
            {result.indicators.map((ind, i) => (
              <li key={i}>{ind}</li>
            ))}
          </ul>
        </section>
      )}

      {result.explanation && (
        <details className="rounded-md border border-slate-800 bg-slate-900/60 p-2.5">
          <summary className="cursor-pointer text-[11px] font-semibold uppercase tracking-wide text-slate-400">
            Full assessment text
          </summary>
          <p className="mt-1 whitespace-pre-wrap text-[11px] leading-snug text-slate-300">
            {result.explanation}
          </p>
        </details>
      )}

      <LayerBreakdown layers={result.layers} />

      <PrefilterCard prefilter={result.prefilter} />
      {/* A provisional result has not asked the model yet and has not rendered
          the page, so those two cards must not claim the layers are missing. */}
      <LlmCard assessment={result.llm_assessment} pending={result.provisional} />
      <VisualCard visual={result.visual} pending={result.provisional} />

      <section className="rounded-md border border-slate-800 bg-slate-900/60 p-2.5">
        <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
          Recommended action
        </h3>
        <p className="text-[11px] text-slate-200">{result.recommended_action}</p>
      </section>

      {result.degraded && result.degraded.length > 0 && (
        <section className="rounded-md border border-slate-800 bg-slate-900/40 p-2.5">
          <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
            Degraded / unavailable layers
          </h3>
          <ul className="list-disc space-y-0.5 pl-4 text-[10px] text-slate-400">
            {result.degraded.map((d, i) => (
              <li key={i}>{d}</li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
