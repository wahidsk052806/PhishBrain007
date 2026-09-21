import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = "default",
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon: LucideIcon;
  tone?: "default" | "safe" | "suspicious" | "danger";
}) {
  const toneClass =
    tone === "safe"
      ? "text-safe"
      : tone === "suspicious"
        ? "text-suspicious"
        : tone === "danger"
          ? "text-danger"
          : "text-primary";
  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p className={cn("mt-2 font-mono text-3xl font-bold tabular-nums", toneClass)}>{value}</p>
          {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
        </div>
        <Icon aria-hidden="true" className={cn("size-5 shrink-0", toneClass)} />
      </div>
    </div>
  );
}
