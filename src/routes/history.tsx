import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Trash2 } from "lucide-react";
import { AppShell } from "@/components/phishbrain/AppShell";
import { RiskBadge } from "@/components/phishbrain/RiskBadge";
import { api } from "@/lib/phishbrain/api";
import { clearDemoHistory } from "@/lib/phishbrain/demo";
import { useAnalyses } from "@/lib/phishbrain/useAnalyses";
import type { RiskLevel } from "@/lib/phishbrain/types";

export const Route = createFileRoute("/history")({
  head: () => ({
    meta: [
      { title: "Analysis history — PhishBrain" },
      {
        name: "description",
        content:
          "Searchable history of PhishBrain analyses with threat score, risk level, confidence and retention controls.",
      },
      { property: "og:title", content: "Analysis history — PhishBrain" },
      {
        property: "og:description",
        content:
          "Every stored analysis with score, risk level and privacy-aware retention controls.",
      },
    ],
  }),
  component: HistoryPage,
});

const FILTERS: Array<RiskLevel | "ALL"> = ["ALL", "SAFE", "SUSPICIOUS", "HIGH_RISK"];

function HistoryPage() {
  const { items, loading, error, source, reload } = useAnalyses();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<RiskLevel | "ALL">("ALL");
  const [notice, setNotice] = useState<string | null>(null);

  const filtered = useMemo(
    () =>
      items.filter(
        (i) =>
          (filter === "ALL" || i.risk_level === filter) &&
          (!query || i.target.toLowerCase().includes(query.toLowerCase())),
      ),
    [items, filter, query],
  );

  async function clearAll() {
    if (source === "demo") {
      clearDemoHistory();
      setNotice("Local demo history cleared.");
      reload();
      return;
    }
    try {
      const res = await api.clearHistory();
      setNotice(`Backend history cleared (${res.deleted} records removed).`);
      reload();
    } catch {
      setNotice("Could not clear backend history — the backend is unreachable.");
    }
  }

  return (
    <AppShell
      title="History"
      description={
        source === "demo"
          ? "DEMO DATA stored in this browser only"
          : "Records retained by the backend according to the configured retention policy"
      }
      actions={
        <button
          type="button"
          onClick={() => void clearAll()}
          className="inline-flex items-center gap-1.5 rounded-md border border-danger/40 bg-danger-soft px-3 py-1.5 text-sm text-danger transition-colors hover:bg-danger/20"
        >
          <Trash2 aria-hidden="true" className="size-4" /> Clear history
        </button>
      }
    >
      {error ? (
        <p className="mb-4 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="mb-4 rounded-md border border-border bg-muted px-3 py-2 text-sm">{notice}</p>
      ) : null}

      <div className="panel mb-4 flex flex-wrap items-center gap-2 p-3">
        <label htmlFor="history-search" className="sr-only">
          Search history
        </label>
        <input
          id="history-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter by URL or domain…"
          className="min-w-0 flex-1 rounded-md border border-input bg-background px-3 py-1.5 font-mono text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        <div className="flex gap-1">
          {FILTERS.map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              aria-pressed={filter === f}
              className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors ${
                filter === f ? "bg-primary text-primary-foreground" : "bg-secondary hover:bg-accent"
              }`}
            >
              {f.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      <section className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-2 font-medium">URL</th>
                <th className="px-4 py-2 font-medium">Score</th>
                <th className="px-4 py-2 font-medium">Risk</th>
                <th className="px-4 py-2 font-medium">Confidence</th>
                <th className="px-4 py-2 font-medium">Top indicator</th>
                <th className="px-4 py-2 font-medium">Date</th>
                <th className="px-4 py-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-muted-foreground">
                    Loading…
                  </td>
                </tr>
              ) : filtered.length ? (
                filtered.map((i) => (
                  <tr key={i.analysis_id} className="border-b border-border/60 last:border-0">
                    <td className="max-w-[20rem] truncate px-4 py-2 font-mono text-xs">
                      {i.target}
                    </td>
                    <td className="px-4 py-2 font-mono">{i.threat_score}</td>
                    <td className="px-4 py-2">
                      <RiskBadge risk={i.risk_level} size="sm" />
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">
                      {Math.round(i.confidence * 100)}%
                    </td>
                    <td className="max-w-[18rem] truncate px-4 py-2 text-xs text-muted-foreground">
                      {i.indicators[0] ?? "—"}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {new Date(i.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2">
                      <Link
                        to="/analysis/$analysisId"
                        params={{ analysisId: i.analysis_id }}
                        className="text-xs text-primary hover:underline"
                      >
                        Open
                      </Link>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-muted-foreground">
                    No analyses match this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <p className="mt-3 text-xs text-muted-foreground">
        Privacy: raw email bodies are not persisted by default (STORE_RAW_EMAIL=false) and email
        addresses / personal identifiers are masked before storage.
      </p>
    </AppShell>
  );
}
