import type { RiskLevel } from "../types/analysis";

const CONFIG: Record<RiskLevel, { label: string; icon: string; classes: string }> = {
  SAFE: { label: "Safe", icon: "✓", classes: "bg-emerald-950 text-emerald-300 border-emerald-700" },
  SUSPICIOUS: { label: "Suspicious", icon: "⚠", classes: "bg-amber-950 text-amber-300 border-amber-700" },
  HIGH_RISK: { label: "High Risk", icon: "✕", classes: "bg-red-950 text-red-300 border-red-700" },
};

export default function RiskBadge({ level }: { level: RiskLevel }) {
  const cfg = CONFIG[level];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide ${cfg.classes}`}
      role="status"
      aria-label={`Risk level: ${cfg.label}`}
    >
      <span aria-hidden="true">{cfg.icon}</span>
      {cfg.label}
    </span>
  );
}
