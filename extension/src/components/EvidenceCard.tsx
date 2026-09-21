export interface EvidenceCardProps {
  title: string;
  indicators: string[];
  risk: number;
}

export default function EvidenceCard({ title, indicators, risk }: EvidenceCardProps) {
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900 p-3">
      <div className="mb-1 flex items-center justify-between">
        <h4 className="text-sm font-semibold text-slate-200">{title}</h4>
        <span className="text-xs text-slate-400">risk {Math.round(risk)}</span>
      </div>
      {indicators.length === 0 ? (
        <p className="text-xs text-slate-500">No indicators found in this layer.</p>
      ) : (
        <ul className="list-disc space-y-0.5 pl-4 text-xs text-slate-300">
          {indicators.map((ind, i) => (
            <li key={i}>{ind}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
