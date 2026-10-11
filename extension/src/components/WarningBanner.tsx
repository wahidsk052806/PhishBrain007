import { useEffect, useRef } from "react";
import type { AnalysisResult } from "../types/analysis";
import RiskBadge from "./RiskBadge";
import ThreatScore from "./ThreatScore";

export interface WarningBannerProps {
  result: AnalysisResult;
  dashboardUrl: string;
  onDismiss: () => void;
  onGoBack: () => void;
  onProceedAnyway: () => void;
  onViewDetails: () => void;
}

export default function WarningBanner({
  result,
  onDismiss,
  onGoBack,
  onProceedAnyway,
  onViewDetails,
}: WarningBannerProps) {
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const topIndicators = result.indicators.slice(0, 4);
  const label = result.risk_level === "HIGH_RISK" ? "High Risk" : "Suspicious";

  return (
    <div
      role="alert"
      aria-live="assertive"
      className="pointer-events-auto flex w-full flex-col gap-3 border-b border-slate-700 bg-slate-950 p-4 font-sans text-slate-100 shadow-lg sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex flex-1 flex-col gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <h2
            ref={headingRef}
            tabIndex={-1}
            className="text-sm font-bold outline-none"
            aria-label={`PhishBrain warning: ${label} page detected`}
          >
            PhishBrain: {label} page detected
          </h2>
          <RiskBadge level={result.risk_level} />
        </div>
        <div className="max-w-xs">
          <ThreatScore score={result.threat_score} />
        </div>
        {topIndicators.length > 0 && (
          <ul
            className="list-disc space-y-0.5 pl-4 text-xs text-slate-300"
            aria-label="Top indicators"
          >
            {topIndicators.map((ind, i) => (
              <li key={i}>{ind}</li>
            ))}
          </ul>
        )}
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onViewDetails}
          aria-label="View detailed analysis"
          className="rounded-md border border-sky-600 bg-sky-900/40 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-900/70 focus:outline focus:outline-2 focus:outline-sky-400"
        >
          View Detailed Analysis
        </button>
        <button
          type="button"
          onClick={onGoBack}
          aria-label="Go back to previous page"
          className="rounded-md border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 focus:outline focus:outline-2 focus:outline-slate-400"
        >
          Go Back
        </button>
        <button
          type="button"
          onClick={onProceedAnyway}
          aria-label="Proceed anyway, dismiss this warning for this session"
          className="rounded-md border border-red-700 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-300 hover:bg-red-950/70 focus:outline focus:outline-2 focus:outline-red-400"
        >
          Proceed Anyway
        </button>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss this warning"
          className="rounded-md px-2 py-1.5 text-xs text-slate-400 hover:text-slate-200 focus:outline focus:outline-2 focus:outline-slate-400"
        >
          ✕
        </button>
      </div>
    </div>
  );
}
