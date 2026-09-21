import { createFileRoute, Link } from "@tanstack/react-router";
import { AppShell } from "@/components/phishbrain/AppShell";
import { RiskBadge } from "@/components/phishbrain/RiskBadge";
import { useAnalyses } from "@/lib/phishbrain/useAnalyses";

export const Route = createFileRoute("/alerts")({
  head: () => ({
    meta: [
      { title: "Alerts — PhishBrain" },
      {
        name: "description",
        content:
          "Suspicious and high-risk PhishBrain detections with indicators, recommended actions and exportable SOC events.",
      },
      { property: "og:title", content: "Alerts — PhishBrain" },
      {
        property: "og:description",
        content: "Suspicious and high-risk detections with recommended actions and SOC events.",
      },
    ],
  }),
  component: AlertsPage,
});

function AlertsPage() {
  const { items, loading, error } = useAnalyses();
  const alerts = items.filter((i) => i.risk_level !== "SAFE");

  return (
    <AppShell title="Alerts" description="Suspicious and high-risk detections">
      {error ? (
        <p className="mb-4 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}

      {loading ? <p className="text-sm text-muted-foreground">Loading alerts…</p> : null}

      {!loading && !alerts.length ? (
        <p className="panel p-6 text-center text-sm text-muted-foreground">
          No suspicious or high-risk detections recorded.
        </p>
      ) : null}

      <ul className="space-y-3">
        {alerts.map((a) => (
          <li key={a.analysis_id} className="panel p-4">
            <div className="flex flex-wrap items-center gap-3">
              <RiskBadge risk={a.risk_level} />
              <span className="font-mono text-sm font-bold">{a.threat_score}/100</span>
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">
                {a.target}
              </span>
              {a.demo ? (
                <span className="rounded border border-suspicious/40 bg-suspicious-soft px-1.5 py-0.5 font-mono text-[10px] text-suspicious">
                  DEMO DATA
                </span>
              ) : null}
              <Link
                to="/analysis/$analysisId"
                params={{ analysisId: a.analysis_id }}
                className="text-xs text-primary hover:underline"
              >
                View detailed analysis
              </Link>
            </div>
            <ul className="mt-2 space-y-1 text-sm text-foreground/90">
              {a.indicators.slice(0, 3).map((ind) => (
                <li key={ind} className="flex gap-2">
                  <span
                    aria-hidden="true"
                    className="mt-1.5 size-1.5 shrink-0 rounded-full bg-danger"
                  />
                  {ind}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-muted-foreground">{a.recommended_action}</p>
          </li>
        ))}
      </ul>
    </AppShell>
  );
}
