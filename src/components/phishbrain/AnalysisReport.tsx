import { Download, FlaskConical, Info, Loader2, TriangleAlert } from "lucide-react";
import type { AnalysisResult } from "@/lib/phishbrain/types";
import { api } from "@/lib/phishbrain/api";
import { describeDegraded } from "@/lib/phishbrain/normalize";
import { EvidenceCard } from "./EvidenceCard";
import { RiskBadge } from "./RiskBadge";
import { ThreatScoreDial } from "./ThreatScoreDial";

function download(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function toCsv(r: AnalysisResult) {
  const rows = [
    [
      "analysis_id",
      "timestamp",
      "url",
      "domain",
      "threat_score",
      "risk_level",
      "confidence",
      "indicators",
    ],
    [
      r.analysis_id,
      r.created_at,
      r.target,
      r.domain,
      String(r.threat_score),
      r.risk_level,
      r.confidence.toFixed(2),
      r.indicators.join(" | "),
    ],
  ];
  return rows
    .map((row) => row.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(","))
    .join("\n");
}

export function AnalysisReport({ result }: { result: AnalysisResult }) {
  const { prefilter } = result;
  // A host with no DNS address is a *result*, not a missing layer: there is no
  // page to read, and an unregistered name cannot be serving a credential form.
  // The pipeline records that on the webpage layer so the report can say it in
  // words instead of showing a silent "Not applicable" beside a score.
  const pageDetails = result.layers.webpage.evidence as Record<string, unknown>;
  const unresolvedHost =
    pageDetails["dns_unresolved"] === true ||
    pageDetails["page_fetch_outcome"] === "unresolved";
  const unresolvedReason =
    typeof pageDetails["page_fetch_failed"] === "string"
      ? (pageDetails["page_fetch_failed"] as string)
      : "";
  const registration = (result.layers.domain.evidence as Record<string, unknown>)[
    "registration_status"
  ];
  const domainNotRegistered = registration === "not_registered";
  // `null` means no pre-filter ran for this result (the in-browser engines),
  // which is not the same statement as "no trained model exists".
  const prefilterStatus =
    prefilter.model_trained === null
      ? "Not consulted"
      : prefilter.model_trained
        ? prefilter.blended
          ? "Blended into score"
          : "Available, not blended"
        : "No trained model";
  const blendedClass = prefilter.blended
    ? "border-suspicious/40 bg-suspicious-soft text-suspicious"
    : "border-border bg-muted/50 text-muted-foreground";

  return (
    <div className="space-y-4">
      {result.demo ? (
        <p className="flex items-center gap-2 rounded-md border border-suspicious/40 bg-suspicious-soft px-3 py-2 text-sm text-suspicious">
          <FlaskConical aria-hidden="true" className="size-4 shrink-0" />
          <span>
            <strong className="font-mono">DEMO DATA</strong> — produced offline by the deterministic
            demo engine. This is not a live detection.
          </span>
        </p>
      ) : null}

      {result.provisional ? (
        <p className="flex items-center gap-2 rounded-md border border-primary/40 bg-primary/10 px-3 py-2 text-sm text-primary">
          <Loader2 aria-hidden="true" className="size-4 shrink-0 animate-spin" />
          <span>
            <strong className="font-mono">PROVISIONAL</strong> — the capture, multi-layer and ML
            pre-filter stages have finished, so this score is real; the on-device LLM reasoning step
            is still running and can adjust it. This report updates in place when the verdict lands.
          </span>
        </p>
      ) : null}

      {unresolvedHost ? (
        <section className="flex items-start gap-3 rounded-md border border-primary/40 bg-primary/10 px-4 py-3 text-sm">
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-primary" />
          <div className="space-y-1">
            <p className="font-semibold">
              No live page — {domainNotRegistered ? "this domain is not registered" : "this domain does not resolve"}.
            </p>
            {unresolvedReason ? (
              <p className="text-muted-foreground">{unresolvedReason}</p>
            ) : null}
            <p className="text-muted-foreground">
              The page and visual layers were skipped rather than failed, because a name with no
              DNS address has nothing to serve. The score below is built from the URL string, the
              registration lookup and the local model. A low score here means “there is no live
              site to visit”, not “the site was inspected and found clean” — the name can still be
              a lookalike of a real brand.
            </p>
          </div>
        </section>
      ) : null}

      {result.degraded.length ? (
        <ul className="space-y-1 rounded-md border border-border bg-muted/50 px-3 py-2 text-sm text-muted-foreground">
          {result.degraded.map((d) => (
            <li key={d} className="flex items-start gap-2">
              <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              {/* The code is kept in the tooltip so the sentence stays readable
                  without losing traceability back to the raw pipeline signal. */}
              <span title={d}>{describeDegraded(d)}</span>
            </li>
          ))}
        </ul>
      ) : null}

      {/* 1. Target, 2. Score, 3. Classification, 4. Confidence */}
      <section className="panel p-5">
        <div className="flex flex-wrap items-center gap-6">
          <ThreatScoreDial score={result.threat_score} risk={result.risk_level} />
          <div className="min-w-0 flex-1 space-y-3">
            <div>
              <p className="text-xs uppercase tracking-wider text-muted-foreground">Target</p>
              <p className="break-all font-mono text-sm">{result.target}</p>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              <RiskBadge risk={result.risk_level} />
              <span className="text-sm text-muted-foreground">
                Confidence{" "}
                <strong className="font-mono text-foreground">
                  {Math.round(result.confidence * 100)}%
                </strong>
              </span>
              <span className="text-sm text-muted-foreground">
                Latency{" "}
                <strong className="font-mono text-foreground">{result.latency_ms} ms</strong>
              </span>
              <span className="text-sm text-muted-foreground">
                ID <strong className="font-mono text-foreground">{result.analysis_id}</strong>
              </span>
            </div>
            <div className="flex flex-wrap gap-2 pt-1">
              <button
                type="button"
                onClick={() =>
                  download(
                    `${result.analysis_id}.json`,
                    JSON.stringify(result, null, 2),
                    "application/json",
                  )
                }
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium transition-colors hover:bg-accent"
              >
                <Download aria-hidden="true" className="size-3.5" /> Export JSON
              </button>
              <button
                type="button"
                onClick={() => download(`${result.analysis_id}.csv`, toCsv(result), "text/csv")}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium transition-colors hover:bg-accent"
              >
                <Download aria-hidden="true" className="size-3.5" /> Export CSV
              </button>
              {!result.demo ? (
                <a
                  href={api.exportUrl(result.analysis_id, "json")}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-accent"
                >
                  Backend export endpoint
                </a>
              ) : null}
            </div>
          </div>
        </div>
      </section>

      {/* Explanation */}
      <section className="panel p-5">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Why was this flagged?
        </h2>
        <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">
          {result.explanation}
        </pre>
        <div className="mt-4 rounded-md border border-primary/30 bg-primary/10 p-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-primary">
            Recommended action
          </p>
          <p className="mt-1 text-sm">{result.recommended_action}</p>
        </div>
      </section>

      {/* 5-8. Layer evidence */}
      <div className="grid gap-3 lg:grid-cols-2">
        <EvidenceCard title="URL evidence" layer={result.layers.url} defaultOpen />
        <EvidenceCard title="Domain evidence" layer={result.layers.domain} defaultOpen />
        <EvidenceCard title="Webpage evidence" layer={result.layers.webpage} />
        <EvidenceCard title="Email evidence" layer={result.layers.email} />
      </div>

      {/* 9. Visual */}
      <section className="panel p-5">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Visual analysis
        </h2>
        {result.visual.screenshot_thumbnail && (
          <figure className="mb-3">
            <img
              src={result.visual.screenshot_thumbnail}
              alt={
                result.visual.possible_brand
                  ? `Captured page screenshot, compared against ${result.visual.possible_brand}`
                  : "Captured page screenshot used for the visual comparison"
              }
              className="max-h-64 w-auto rounded-md border border-border object-contain"
            />
            <figcaption className="mt-1 text-xs text-muted-foreground">
              The captured screenshot this comparison was scored on.
            </figcaption>
          </figure>
        )}
        {result.visual.status === "ok" ? (
          <div className="space-y-1 text-sm">
            <p>
              Perceptual similarity:{" "}
              <strong className="font-mono">
                {result.visual.visual_similarity_score?.toFixed(2) ?? "unavailable"}
              </strong>
            </p>
            <p>
              Possible brand:{" "}
              <strong className="font-mono">
                {result.visual.possible_brand ?? "not established"}
              </strong>
            </p>
            <ul className="mt-2 list-disc pl-5 text-muted-foreground">
              {result.visual.visual_indicators.map((v) => (
                <li key={v}>{v}</li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Unavailable. {result.visual.visual_indicators.join(" ")}
          </p>
        )}
      </section>

      {/* 10. LLM assessment — structured summary, never raw chain-of-thought */}
      <section className="panel p-5">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Local LLM assessment
        </h2>
        <p className="mb-3 text-xs text-muted-foreground">
          What the on-device model concluded about this target. PhishBrain surfaces only the model's
          structured security summary — raw chain-of-thought is never shown.
        </p>
        {result.llm_assessment.status === "skipped" && (
          <p className="text-sm text-muted-foreground">
            Not consulted. The rule-based layers already fixed this verdict, and the model's
            adjustment is bounded, so it could not have changed it — the scan skipped the model's
            CPU time instead of paying ~20 s to restate the same answer. Every layer above is real
            evidence from this scan.
          </p>
        )}
        {result.llm_assessment.status !== "unavailable" &&
          result.llm_assessment.status !== "skipped" && (
          <>
            <dl className="grid gap-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">Status</dt>
                <dd className="font-mono">{result.llm_assessment.status}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Model</dt>
                <dd className="font-mono">{result.llm_assessment.model ?? "unavailable"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Classification</dt>
                <dd className="font-mono">
                  {result.llm_assessment.classification ?? "unavailable"}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Model confidence</dt>
                <dd className="font-mono">
                  {result.llm_assessment.confidence === null
                    ? "unavailable"
                    : `${Math.round(result.llm_assessment.confidence * 100)}%`}
                </dd>
              </div>
            </dl>
            {result.llm_assessment.reasoning_summary ? (
              <div className="mt-3 rounded-md border border-border bg-muted/40 p-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Model reasoning
                </p>
                <p className="mt-1 whitespace-pre-wrap text-sm">
                  {result.llm_assessment.reasoning_summary}
                </p>
              </div>
            ) : null}
            {result.llm_assessment.key_indicators?.length ? (
              <div className="mt-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Key indicators the model weighed
                </p>
                <ul className="mt-1 list-disc pl-5 text-sm">
                  {result.llm_assessment.key_indicators.map((k) => (
                    <li key={k}>{k}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            <p className="mt-3 text-sm">{result.llm_assessment.explanation}</p>
          </>
        )}
        {result.llm_assessment.status === "unavailable" && (
          <div className="rounded-md border border-border bg-muted/40 p-3 text-sm">
            <p className="font-medium">LLM reasoning was not available for this result.</p>
            <p className="mt-1 text-muted-foreground">{result.llm_assessment.explanation}</p>
          </div>
        )}
        {result.llm_assessment.uncertainties.length ? (
          <ul className="mt-2 list-disc pl-5 text-sm text-muted-foreground">
            {result.llm_assessment.uncertainties.map((u) => (
              <li key={u}>{u}</li>
            ))}
          </ul>
        ) : null}
      </section>

      {/* ML pre-filter contribution */}
      <section className="panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            ML pre-filter (CatBoost)
          </h2>
          <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${blendedClass}`}>
            {prefilterStatus}
          </span>
        </div>
        <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <dt className="text-xs uppercase tracking-wider text-muted-foreground">
              Pre-filter score
            </dt>
            <dd className="font-mono">
              {result.prefilter.score === null ? "—" : `${result.prefilter.score} / 100`}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-muted-foreground">
              Weight in base score
            </dt>
            <dd className="font-mono">
              {result.prefilter.blended ? `${Math.round(result.prefilter.weight * 100)}%` : "0%"}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-muted-foreground">
              Layer score before blend
            </dt>
            <dd className="font-mono">
              {result.prefilter.layer_score === null
                ? "—"
                : `${result.prefilter.layer_score} / 100`}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-muted-foreground">Method</dt>
            <dd className="font-mono">{result.prefilter.method || "—"}</dd>
          </div>
        </dl>
        <p className="mt-3 text-xs text-muted-foreground">{result.prefilter.note}</p>
        <p className="mt-1 text-xs text-muted-foreground">
          {result.prefilter.blended
            ? `The final score is weighted: ${Math.round((1 - result.prefilter.weight) * 100)}% deterministic layer evidence and ${Math.round(result.prefilter.weight * 100)}% model output.`
            : result.prefilter.model_trained === null
              ? "No pre-filter ran for this result, so the score stands on the layer evidence alone."
              : "The pre-filter did not change the score for this input, so the score stands on the layer evidence alone."}
        </p>
      </section>

      {/* 12-13. Technical JSON + SOC event */}
      <div className="grid gap-3 lg:grid-cols-2">
        <section className="panel p-5">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            SOC / SIEM event
          </h2>
          <pre className="max-h-80 overflow-auto rounded-md bg-background/70 p-3 font-mono text-xs">
            {JSON.stringify(result.soc_event, null, 2)}
          </pre>
        </section>
        <section className="panel p-5">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Technical JSON
          </h2>
          <pre className="max-h-80 overflow-auto rounded-md bg-background/70 p-3 font-mono text-xs">
            {JSON.stringify(result, null, 2)}
          </pre>
        </section>
      </div>
    </div>
  );
}
