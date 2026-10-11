import type { LayerResult, LayersBreakdown } from "../types/analysis";

const LAYERS: { key: keyof LayersBreakdown; label: string; blurb: string }[] = [
  { key: "url", label: "URL structure", blurb: "Lexical patterns, brand tokens, homograph tricks" },
  { key: "domain", label: "Domain & DNS", blurb: "Registration age, registrar, TLD reputation" },
  { key: "webpage", label: "Page content", blurb: "Credential fields, brand impersonation" },
  { key: "email", label: "Email context", blurb: "Sender authenticity and header signals" },
];

function riskTone(risk: number): { text: string; bar: string; label: string } {
  if (risk >= 60) return { text: "text-red-300", bar: "bg-red-500", label: "high" };
  if (risk >= 30) return { text: "text-amber-300", bar: "bg-amber-500", label: "moderate" };
  if (risk > 0) return { text: "text-sky-300", bar: "bg-sky-500", label: "low" };
  return { text: "text-emerald-300", bar: "bg-emerald-500", label: "clean" };
}

/** Render the handful of primitive evidence values that matter most. */
function evidenceEntries(evidence: Record<string, unknown>): [string, string][] {
  const out: [string, string][] = [];
  for (const [key, value] of Object.entries(evidence)) {
    if (value === null || value === undefined) continue;
    if (typeof value === "object") continue;
    const text = typeof value === "string" ? value : String(value);
    if (text.length === 0 || text === "unavailable") continue;
    out.push([key.replace(/_/g, " "), text.length > 60 ? `${text.slice(0, 57)}…` : text]);
    if (out.length >= 6) break;
  }
  return out;
}

function LayerCard({ label, blurb, layer }: { label: string; blurb: string; layer: LayerResult }) {
  const tone = riskTone(layer.risk);
  const status = layer.unavailable
    ? "Not applicable to this target"
    : layer.risk === 0
      ? "No indicators found"
      : `${layer.risk}/100 risk`;
  const evidence = evidenceEntries(layer.evidence);

  return (
    <div className="rounded-md border border-slate-800 bg-slate-900/60 p-2.5">
      <div className="flex items-center justify-between gap-2">
        <div>
          <p className="text-xs font-semibold text-slate-200">{label}</p>
          <p className="text-[10px] text-slate-500">{blurb}</p>
        </div>
        <span className={`shrink-0 text-[11px] font-semibold ${tone.text}`}>{status}</span>
      </div>

      {!layer.unavailable && (
        <div
          className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-800"
          aria-hidden="true"
        >
          <div
            className={`h-full rounded-full ${tone.bar}`}
            style={{ width: `${Math.max(2, Math.min(100, layer.risk))}%` }}
          />
        </div>
      )}

      {layer.indicators.length > 0 ? (
        <ul className="mt-2 list-disc space-y-0.5 pl-4 text-[11px] text-slate-300">
          {layer.indicators.map((ind, i) => (
            <li key={i}>{ind}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-[11px] text-slate-500">
          {layer.unavailable
            ? "This layer was skipped for the target type."
            : "This layer raised nothing."}
        </p>
      )}

      {evidence.length > 0 && (
        <dl className="mt-2 grid grid-cols-2 gap-x-2 gap-y-0.5">
          {evidence.map(([key, value]) => (
            <div key={key} className="flex flex-col">
              <dt className="text-[9px] uppercase tracking-wide text-slate-500">{key}</dt>
              <dd className="truncate text-[10px] text-slate-300" title={value}>
                {value}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

export default function LayerBreakdown({ layers }: { layers: LayersBreakdown }) {
  return (
    <section aria-label="Layer-by-layer evidence">
      <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
        What PhishBrain checked
      </h3>
      <div className="flex flex-col gap-1.5">
        {LAYERS.map(({ key, label, blurb }) => (
          <LayerCard key={key} label={label} blurb={blurb} layer={layers[key]} />
        ))}
      </div>
    </section>
  );
}
