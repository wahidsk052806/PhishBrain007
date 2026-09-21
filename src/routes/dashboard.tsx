import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AlertOctagon, AlertTriangle, Gauge, ScanSearch, ShieldCheck, Timer } from "lucide-react";
import { AppShell } from "@/components/phishbrain/AppShell";
import { RiskBadge } from "@/components/phishbrain/RiskBadge";
import { StatCard } from "@/components/phishbrain/StatCard";
import { useAnalyses } from "@/lib/phishbrain/useAnalyses";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "PhishBrain SOC Dashboard — Zero-Day Phishing Detection" },
      {
        name: "description",
        content:
          "Operational overview of PhishBrain analyses: threat scores, risk distribution, alerts and detection latency from the local detection pipeline.",
      },
      { property: "og:title", content: "PhishBrain SOC Dashboard" },
      {
        property: "og:description",
        content:
          "Threat scores, risk distribution and alerts from the local PhishBrain phishing detection pipeline.",
      },
    ],
  }),
  component: DashboardPage,
});

function DashboardPage() {
  const { items, loading, error, source } = useAnalyses();

  const stats = useMemo(() => {
    const total = items.length;
    const safe = items.filter((i) => i.risk_level === "SAFE").length;
    const suspicious = items.filter((i) => i.risk_level === "SUSPICIOUS").length;
    const high = items.filter((i) => i.risk_level === "HIGH_RISK").length;
    const avg = total ? Math.round(items.reduce((s, i) => s + i.threat_score, 0) / total) : 0;
    const latency = total ? Math.round(items.reduce((s, i) => s + i.latency_ms, 0) / total) : 0;
    return { total, safe, suspicious, high, avg, latency };
  }, [items]);

  const overTime = useMemo(() => {
    const buckets = new Map<string, { date: string; detections: number; scans: number }>();
    for (const i of items) {
      const date = i.created_at.slice(0, 10);
      const b = buckets.get(date) ?? { date, detections: 0, scans: 0 };
      b.scans += 1;
      if (i.risk_level !== "SAFE") b.detections += 1;
      buckets.set(date, b);
    }
    return [...buckets.values()].sort((a, b) => a.date.localeCompare(b.date));
  }, [items]);

  const distribution = [
    { name: "Safe", value: stats.safe, fill: "var(--safe)" },
    { name: "Suspicious", value: stats.suspicious, fill: "var(--suspicious)" },
    { name: "High risk", value: stats.high, fill: "var(--danger)" },
  ];

  const topDomains = useMemo(() => {
    const map = new Map<string, number>();
    for (const i of items) {
      if (i.risk_level === "SAFE") continue;
      map.set(i.domain, Math.max(map.get(i.domain) ?? 0, i.threat_score));
    }
    return [...map.entries()]
      .map(([domain, score]) => ({ domain, score }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 6);
  }, [items]);

  const categories = useMemo(() => {
    const buckets: Record<string, number> = {
      Typosquatting: 0,
      "New domain": 0,
      "Credential form": 0,
      Homograph: 0,
      "Sender spoofing": 0,
    };
    const bump = (key: string) => {
      buckets[key] = (buckets[key] ?? 0) + 1;
    };
    for (const i of items) {
      const joined = i.indicators.join(" ").toLowerCase();
      if (joined.includes("typosquat")) bump("Typosquatting");
      if (joined.includes("newly registered")) bump("New domain");
      if (joined.includes("password input") || joined.includes("credential"))
        bump("Credential form");
      if (joined.includes("homograph") || joined.includes("punycode")) bump("Homograph");
      if (joined.includes("reply-to") || joined.includes("display name")) bump("Sender spoofing");
    }
    return Object.entries(buckets).map(([category, count]) => ({ category, count }));
  }, [items]);

  const recentAlerts = items.filter((i) => i.risk_level !== "SAFE").slice(0, 5);

  return (
    <AppShell
      title="Security overview"
      description={
        source === "demo"
          ? "DEMO DATA — locally computed synthetic analyses"
          : "Live results from the local PhishBrain backend"
      }
      actions={
        <Link
          to="/analysis"
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
        >
          New analysis
        </Link>
      }
    >
      {error ? (
        <p className="mb-4 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
          {error}
        </p>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <StatCard label="Total scans" value={stats.total} icon={ScanSearch} />
        <StatCard label="Safe" value={stats.safe} icon={ShieldCheck} tone="safe" />
        <StatCard
          label="Suspicious"
          value={stats.suspicious}
          icon={AlertTriangle}
          tone="suspicious"
        />
        <StatCard label="High risk" value={stats.high} icon={AlertOctagon} tone="danger" />
        <StatCard label="Avg threat score" value={stats.avg} icon={Gauge} />
        <StatCard label="Avg latency" value={`${stats.latency} ms`} icon={Timer} />
      </div>

      <div className="mt-4 grid gap-3 lg:grid-cols-3">
        <section className="panel p-4 lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Detections over time
          </h2>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={overTime}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                <XAxis dataKey="date" stroke="var(--muted-foreground)" fontSize={11} />
                <YAxis stroke="var(--muted-foreground)" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="scans"
                  stroke="var(--primary)"
                  fill="var(--primary)"
                  fillOpacity={0.15}
                />
                <Area
                  type="monotone"
                  dataKey="detections"
                  stroke="var(--danger)"
                  fill="var(--danger)"
                  fillOpacity={0.2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Risk distribution
          </h2>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distribution}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={75}
                >
                  {distribution.map((d) => (
                    <Cell key={d.name} fill={d.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <ul className="mt-2 space-y-1 text-xs">
            {distribution.map((d) => (
              <li key={d.name} className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span
                    aria-hidden="true"
                    className="size-2 rounded-full"
                    style={{ background: d.fill }}
                  />
                  {d.name}
                </span>
                <span className="font-mono">{d.value}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Top suspicious domains
          </h2>
          {topDomains.length ? (
            <ul className="space-y-2">
              {topDomains.map((d) => (
                <li key={d.domain} className="flex items-center justify-between gap-2 text-sm">
                  <span className="truncate font-mono text-xs">{d.domain}</span>
                  <span className="font-mono text-xs text-danger">{d.score}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">No non-safe results recorded yet.</p>
          )}
        </section>

        <section className="panel p-4 lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Detection categories
          </h2>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categories}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                <XAxis dataKey="category" stroke="var(--muted-foreground)" fontSize={11} />
                <YAxis stroke="var(--muted-foreground)" fontSize={11} allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: "var(--accent)" }}
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" fill="var(--chart-4)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      <section className="panel mt-4 overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Recent analyses
          </h2>
          <Link to="/history" className="text-xs text-primary hover:underline">
            View all
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-2 font-medium">URL</th>
                <th className="px-4 py-2 font-medium">Score</th>
                <th className="px-4 py-2 font-medium">Risk</th>
                <th className="px-4 py-2 font-medium">Confidence</th>
                <th className="px-4 py-2 font-medium">Date</th>
                <th className="px-4 py-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-muted-foreground">
                    Loading analyses…
                  </td>
                </tr>
              ) : items.length ? (
                items.slice(0, 8).map((i) => (
                  <tr key={i.analysis_id} className="border-b border-border/60 last:border-0">
                    <td className="max-w-[24rem] truncate px-4 py-2 font-mono text-xs">
                      {i.target}
                    </td>
                    <td className="px-4 py-2 font-mono">{i.threat_score}</td>
                    <td className="px-4 py-2">
                      <RiskBadge risk={i.risk_level} size="sm" />
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">
                      {Math.round(i.confidence * 100)}%
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
                        Open report
                      </Link>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-muted-foreground">
                    No analyses yet. Run one from the Analyze page.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {recentAlerts.length ? (
        <section className="panel mt-4 p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Recent alerts
          </h2>
          <ul className="space-y-2">
            {recentAlerts.map((a) => (
              <li key={a.analysis_id} className="flex flex-wrap items-center gap-3 text-sm">
                <RiskBadge risk={a.risk_level} size="sm" />
                <span className="min-w-0 flex-1 truncate font-mono text-xs">{a.target}</span>
                <span className="font-mono text-xs">{a.threat_score}/100</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </AppShell>
  );
}
