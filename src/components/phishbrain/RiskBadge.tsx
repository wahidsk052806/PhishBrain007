import { AlertTriangle, ShieldAlert, ShieldCheck } from "lucide-react";
import type { RiskLevel } from "@/lib/phishbrain/types";
import { cn } from "@/lib/utils";

const CONFIG: Record<RiskLevel, { label: string; icon: typeof ShieldCheck; className: string }> = {
  SAFE: {
    label: "SAFE",
    icon: ShieldCheck,
    className: "bg-safe-soft text-safe border-safe/40",
  },
  SUSPICIOUS: {
    label: "SUSPICIOUS",
    icon: AlertTriangle,
    className: "bg-suspicious-soft text-suspicious border-suspicious/40",
  },
  HIGH_RISK: {
    label: "HIGH RISK",
    icon: ShieldAlert,
    className: "bg-danger-soft text-danger border-danger/40",
  },
};

export function RiskBadge({
  risk,
  size = "md",
  className,
}: {
  risk: RiskLevel;
  size?: "sm" | "md";
  className?: string;
}) {
  const { label, icon: Icon, className: tone } = CONFIG[risk];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border font-mono font-semibold uppercase tracking-wider",
        size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs",
        tone,
        className,
      )}
    >
      <Icon aria-hidden="true" className={size === "sm" ? "size-3" : "size-3.5"} />
      {label}
    </span>
  );
}

export function riskTextClass(risk: RiskLevel) {
  return risk === "SAFE" ? "text-safe" : risk === "SUSPICIOUS" ? "text-suspicious" : "text-danger";
}
