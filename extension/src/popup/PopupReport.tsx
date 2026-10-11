import type { AnalysisResult } from "../types/analysis";
import RiskBadge from "../components/RiskBadge";
import ThreatScore from "../components/ThreatScore";
import LayerBreakdown from "../components/LayerBreakdown";
import { LlmCard, PrefilterCard, VisualCard } from "../components/SignalCards";

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-[9px] uppercase tracking-wide text-slate-500">{label}</span>
      <span className="truncate text-[11px] font-medium text-slate-200" title={value}>
        {value}
      </span>
    </div>
  );
}

/**
 * The full, explainable report shown in the popup. Kept presentational and
 * side-effect free so it can be rendered to markup in tests — the popup shell
 * owns the browser API calls, this owns the explanation.
 */
export default function PopupReport({ result }: { result: AnalysisResult }) {
  return (
    <div className="flex flex-col gap-3">
      {result.demo && (
        <div className="rounded-md border border-sky-800 bg-sky-950/40 p-2 text-[11px] text-sky-200">
          <span className="font-semibold uppercase">Demo data</span> — this verdict was produced
          offline from a synthetic sample. No live request was made.
        </div>
      )}

      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
        <div className="mb-2 flex items-center justify-between gap-2">
          <RiskBadge level={result.risk_level} />
          <span className="max-w-[180px] truncate text-[10px] text-slate-500" title={result.url}>
            {result.url}
          </span>
        </div>
        <ThreatScore score={result.threat_score} />
        <dl className="mt-3 grid grid-cols-3 gap-2 border-t border-slate-800 pt-2">
          <Metric label="Confidence" value={`${Math.round((result.confidence ?? 0) * 100)}%`} />
          <Metric label="Latency" value={`${Math.round(result.latency_ms)} ms`} />
          <Metric label="Analysis ID" value={result.analysis_id} />
        </dl>
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
      <LlmCard assessment={result.llm_assessment} />
      <VisualCard visual={result.visual} />

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
