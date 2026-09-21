import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { AppShell } from "@/components/phishbrain/AppShell";
import { AnalysisReport } from "@/components/phishbrain/AnalysisReport";
import { api, BackendUnavailableError } from "@/lib/phishbrain/api";
import { loadDemoHistory } from "@/lib/phishbrain/demo";
import type { AnalysisResult } from "@/lib/phishbrain/types";

export const Route = createFileRoute("/analysis/$analysisId")({
  head: () => ({
    meta: [
      { title: "Analysis report — PhishBrain" },
      {
        name: "description",
        content:
          "Full PhishBrain analysis report: threat score, layer-by-layer evidence, LLM assessment, recommended action and SOC event.",
      },
      { property: "og:title", content: "Analysis report — PhishBrain" },
      {
        property: "og:description",
        content:
          "Layer-by-layer phishing evidence, explainable threat score and exportable SOC event.",
      },
    ],
  }),
  component: AnalysisDetailPage,
});

function AnalysisDetailPage() {
  const { analysisId } = Route.useParams();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    const local = loadDemoHistory().find((r) => r.analysis_id === analysisId);
    if (local) {
      setResult(local);
      setLoading(false);
      return;
    }

    api
      .analysis(analysisId)
      .then((r) => {
        if (!cancelled) setResult(r);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const detail = err instanceof BackendUnavailableError ? err.detail : String(err);
        setError(
          `This report could not be loaded (${detail}). It may live only in the backend database, which is currently unreachable.`,
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  return (
    <AppShell
      title="Analysis report"
      description={analysisId}
      actions={
        <Link
          to="/history"
          className="rounded-md border border-border bg-secondary px-3 py-1.5 text-sm hover:bg-accent"
        >
          Back to history
        </Link>
      }
    >
      {loading ? <p className="text-sm text-muted-foreground">Loading report…</p> : null}
      {error ? (
        <p className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
      {result ? <AnalysisReport result={result} /> : null}
    </AppShell>
  );
}
