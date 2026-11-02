import type { ReactNode } from "react";
import type { PrefilterEvidenceWire } from "../types/analysis";
import VisualComparison from "./VisualComparison";

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-2">
      <dt className="text-[10px] uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="max-w-[62%] text-right text-[11px] text-slate-200">{value}</dd>
    </div>
  );
}

function Section({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
}) {
  return (
    <section
      className="rounded-md border border-slate-800 bg-slate-900/60 p-2.5"
      aria-label={title}
    >
      <h3 className="text-xs font-semibold text-slate-200">{title}</h3>
      <p className="mb-2 text-[10px] text-slate-500">{subtitle}</p>
      {children}
    </section>
  );
}

export function PrefilterCard({ prefilter }: { prefilter?: PrefilterEvidenceWire | null }) {
  if (!prefilter) {
    return (
      <Section
        title="ML pre-filter (CatBoost)"
        subtitle="Fast machine-learning triage before the deep layers"
      >
        <p className="text-[11px] text-slate-400">
          Not consulted for this result — it was produced without the backend pipeline.
        </p>
      </Section>
    );
  }

  const consulted = prefilter.model_trained === true;
  const score = prefilter.score;
  const weightPct = Math.round((prefilter.weight ?? 0) * 100);
  const tier = asString(prefilter.gate_tier);
  const method = asString(prefilter.method) ?? "unknown";
  const above = prefilter.score_above_threshold;

  return (
    <Section
      title="ML pre-filter (CatBoost)"
      subtitle="Fast machine-learning triage before the deep layers"
    >
      <dl className="flex flex-col gap-1">
        <Row
          label="Model"
          value={
            consulted ? "Trained CatBoost consulted" : "No trained model — deterministic fallback"
          }
        />
        <Row
          label="Score"
          value={score === null || score === undefined ? "—" : `${Math.round(score)}/100`}
        />
        <Row label="Weight in score" value={`${weightPct}%`} />
        <Row
          label="Layer score before blend"
          value={
            prefilter.layer_score === null || prefilter.layer_score === undefined
              ? "—"
              : `${Math.round(prefilter.layer_score)}/100`
          }
        />
        <Row label="Method" value={method} />
        {tier && (
          <Row
            label="Deployment tier"
            value={`${tier}${prefilter.gate_passed ? " (passed)" : ""}`}
          />
        )}
        {prefilter.decision_threshold !== null && prefilter.decision_threshold !== undefined && (
          <Row
            label="Decision threshold"
            value={`${prefilter.decision_threshold} → ${above ? "above threshold" : "below threshold"}`}
          />
        )}
        {prefilter.split && <Row label="Validated on" value={prefilter.split} />}
      </dl>
      {prefilter.note && (
        <p className="mt-2 text-[10px] leading-snug text-slate-400">{prefilter.note}</p>
      )}
    </Section>
  );
}

export function LlmCard({
  assessment,
  pending = false,
}: {
  assessment?: Record<string, unknown> | null;
  /** The quick verdict is still being replaced by the full pass. */
  pending?: boolean;
}) {
  if (!assessment) {
    return (
      <Section
        title="Local LLM assessment"
        subtitle="On-device reasoning (Ollama) — no data leaves the machine"
      >
        <p className="text-[11px] text-slate-400">
          {pending
            ? "Still running — this is the quick verdict. The on-device model's assessment arrives with the full pass and replaces this report in place."
            : "No LLM reasoning layer was applied to this result."}
        </p>
      </Section>
    );
  }

  const status = asString(assessment.status) ?? "unknown";
  const model = asString(assessment.model);
  const classification = asString(assessment.classification);
  const confidence = asNumber(assessment.confidence);
  const explanation = asString(assessment.explanation);
  const reasoning = asString(assessment.reasoning_summary);
  const keyIndicators = asList(assessment.key_indicators ?? assessment.indicators);
  const uncertainties = asList(assessment.uncertainties);

  return (
    <Section
      title="Local LLM assessment"
      subtitle="On-device reasoning (Ollama) — the model's structured summary, never its raw chain-of-thought"
    >
      <dl className="flex flex-col gap-1">
        <Row label="Status" value={status} />
        {model && <Row label="Model" value={model} />}
        {classification && <Row label="Classification" value={classification} />}
        {confidence !== null && (
          <Row label="Model confidence" value={`${Math.round(confidence * 100)}%`} />
        )}
      </dl>
      {reasoning && <p className="mt-2 text-[11px] leading-snug text-slate-300">{reasoning}</p>}
      {!reasoning && explanation && (
        <p className="mt-2 text-[11px] leading-snug text-slate-300">{explanation}</p>
      )}
      {keyIndicators.length > 0 && (
        <ul className="mt-2 list-disc space-y-0.5 pl-4 text-[11px] text-slate-300">
          {keyIndicators.slice(0, 6).map((ind, i) => (
            <li key={i}>{ind}</li>
          ))}
        </ul>
      )}
      {uncertainties.length > 0 && (
        <p className="mt-1.5 text-[10px] text-slate-500">
          Caveats: {uncertainties.slice(0, 3).join("; ")}
        </p>
      )}
    </Section>
  );
}

export function VisualCard({
  visual,
  pending = false,
}: {
  visual?: Record<string, unknown> | null;
  /** The quick verdict is still being replaced by the full pass. */
  pending?: boolean;
}) {
  const status = asString(visual?.status) ?? "unavailable";
  const available = status === "ok" || status === "available";
  const similarity = asNumber(visual?.visual_similarity_score);
  const brand = asString(visual?.possible_brand);
  const indicators = asList(visual?.visual_indicators);
  const thumbnail = asString(visual?.screenshot_thumbnail);
  const isImage = thumbnail?.startsWith("data:image/") ?? false;
  const reference = asString(visual?.reference_thumbnail);
  const hasReference = reference?.startsWith("data:image/") ?? false;

  return (
    <Section
      title="Visual / brand-clone analysis"
      subtitle="Perceptual-hash and structural (edge-map) comparison against known brands"
    >
      {isImage && (
        <div className={hasReference ? "mb-2 grid grid-cols-2 gap-2" : "mb-2"}>
          <figure>
            <img
              src={thumbnail as string}
              alt={
                brand
                  ? `Captured page screenshot, visually similar to ${brand}`
                  : "Captured page screenshot"
              }
              className="w-full rounded-md border border-slate-700 object-cover"
              style={{ maxHeight: 150 }}
            />
            <figcaption className="mt-1 text-[10px] text-slate-500">
              {hasReference ? "This page" : "The captured screenshot this verdict was scored on"}
            </figcaption>
          </figure>
          {hasReference && (
            <figure>
              <img
                src={reference as string}
                alt={brand ? `Reference layout for ${brand}` : "Reference brand layout"}
                className="w-full rounded-md border border-slate-700 object-cover"
                style={{ maxHeight: 150 }}
              />
              <figcaption className="mt-1 text-[10px] text-slate-500">
                Reference: {brand ?? "brand"}
              </figcaption>
            </figure>
          )}
        </div>
      )}
      {isImage && hasReference && (
        <VisualComparison
          captured={thumbnail as string}
          reference={reference as string}
          brand={brand}
        />
      )}
      <dl className="flex flex-col gap-1">
        <Row
          label="Status"
          value={
            available ? "Available" : pending ? "Still running" : "Unavailable for this result"
          }
        />
        {similarity !== null && (
          <Row label="Visual similarity" value={`${Math.round(similarity * 100)}%`} />
        )}
        <Row label="Brand matched" value={brand ?? "None"} />
      </dl>
      {indicators.length > 0 && (
        <ul className="mt-2 list-disc space-y-0.5 pl-4 text-[10px] text-slate-400">
          {indicators.slice(0, 4).map((ind, i) => (
            <li key={i}>{ind}</li>
          ))}
        </ul>
      )}
    </Section>
  );
}
