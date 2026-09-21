export default function ExplanationPanel({ explanation, recommendedAction }: { explanation: string; recommendedAction: string }) {
  return (
    <div className="space-y-2 rounded-lg border border-slate-700 bg-slate-900 p-3">
      <div>
        <h4 className="text-sm font-semibold text-slate-200">Why this verdict?</h4>
        <p className="text-xs text-slate-300">{explanation}</p>
      </div>
      <div>
        <h4 className="text-sm font-semibold text-slate-200">Recommended action</h4>
        <p className="text-xs text-slate-300">{recommendedAction}</p>
      </div>
    </div>
  );
}
