import { useState } from "react";
import { ChevronDown, CircleSlash } from "lucide-react";
import type { LayerEvidence } from "@/lib/phishbrain/types";
import { cn } from "@/lib/utils";

function riskTone(risk: number) {
  if (risk >= 60) return "text-danger";
  if (risk >= 25) return "text-suspicious";
  return "text-safe";
}

export function EvidenceCard({
  title,
  layer,
  defaultOpen = false,
}: {
  title: string;
  layer: LayerEvidence;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const unavailable = layer.status !== "ok";
  // Shown next to the header, so an unavailable layer explains *itself* instead
  // of making the reader expand the card to discover why it is empty.
  const unavailableReason = unavailable ? layer.indicators[0] : undefined;

  return (
    <section className="panel overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-accent/50"
      >
        <span className="flex items-center gap-2">
          <span className="text-sm font-semibold">{title}</span>
          {unavailable ? (
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              <CircleSlash aria-hidden="true" className="size-3" />
              {layer.status === "unavailable" ? "Unavailable" : "Not applicable"}
            </span>
          ) : (
            <span className={cn("font-mono text-xs font-semibold", riskTone(layer.risk))}>
              risk {layer.risk}/100
            </span>
          )}
        </span>
        <ChevronDown
          aria-hidden="true"
          className={cn("size-4 shrink-0 transition-transform", open && "rotate-180")}
        />
      </button>
      {unavailable && unavailableReason ? (
        <p className="border-t border-border px-4 py-2 text-xs text-muted-foreground">
          {unavailableReason}
        </p>
      ) : null}
      {open ? (
        <div className="border-t border-border px-4 py-3">
          <ul className="space-y-1.5">
            {layer.indicators
              // The reason line is already visible above the divider; listing
              // it twice reads like two separate findings.
              .filter((ind) => !(unavailable && ind === unavailableReason))
              .map((ind) => (
                <li key={ind} className="flex gap-2 text-sm text-foreground/90">
                  <span
                    aria-hidden="true"
                    className="mt-1.5 size-1.5 shrink-0 rounded-full bg-primary"
                  />
                  <span>{ind}</span>
                </li>
              ))}
          </ul>
          {Object.keys(layer.evidence).length ? (
            <details className="mt-3">
              <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
                Structured evidence
              </summary>
              <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-background/70 p-3 font-mono text-xs leading-relaxed">
                {JSON.stringify(layer.evidence, null, 2)}
              </pre>
            </details>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
