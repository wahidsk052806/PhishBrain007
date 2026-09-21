export default function ThreatScore({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  return (
    <div className="flex flex-col gap-1" role="meter" aria-valuenow={clamped} aria-valuemin={0} aria-valuemax={100} aria-label="Threat score">
      <div className="flex items-baseline justify-between">
        <span className="text-2xl font-bold text-slate-100">{clamped}</span>
        <span className="text-xs text-slate-400">/ 100 threat score</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500"
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  );
}
