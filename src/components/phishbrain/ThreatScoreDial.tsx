import type { RiskLevel } from "@/lib/phishbrain/types";
import { cn } from "@/lib/utils";
import { riskTextClass } from "./RiskBadge";

export function ThreatScoreDial({
  score,
  risk,
  size = 160,
  label = "Threat score",
}: {
  score: number;
  risk: RiskLevel;
  size?: number;
  label?: string;
}) {
  const radius = size / 2 - 10;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const stroke =
    risk === "SAFE" ? "var(--safe)" : risk === "SUSPICIOUS" ? "var(--suspicious)" : "var(--danger)";

  return (
    <div
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`${label}: ${score} out of 100, ${risk.replace("_", " ").toLowerCase()}`}
    >
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={8}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={stroke}
          strokeWidth={8}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - pct)}
          className="transition-[stroke-dashoffset] duration-700 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("font-mono text-4xl font-bold tabular-nums", riskTextClass(risk))}>
          {score}
        </span>
        <span className="text-xs text-muted-foreground">/ 100</span>
      </div>
    </div>
  );
}
