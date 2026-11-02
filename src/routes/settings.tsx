import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { AppShell } from "@/components/phishbrain/AppShell";
import { api } from "@/lib/phishbrain/api";
import { clearDemoHistory } from "@/lib/phishbrain/demo";
import { useBackendEndpoint } from "@/lib/phishbrain/useBackendEndpoint";
import { usePhishbrainSettings } from "@/lib/phishbrain/usePhishbrainSettings";
import { DEFAULT_SETTINGS } from "@/lib/phishbrain/settings";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — PhishBrain" },
      {
        name: "description",
        content:
          "Configure the PhishBrain backend endpoint, demo mode, risk thresholds, theme and local data retention.",
      },
      { property: "og:title", content: "Settings — PhishBrain" },
      {
        property: "og:description",
        content: "Backend endpoint, demo mode, risk thresholds and local data retention controls.",
      },
    ],
  }),
  component: SettingsPage,
});

function SettingsPage() {
  const { settings, update } = usePhishbrainSettings();
  const { resolution, refresh } = useBackendEndpoint();
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [visualPolicy, setVisualPolicy] = useState<{
    retention_days: number;
    auto_purge_enabled: boolean;
  } | null>(null);
  const [clearingVisual, setClearingVisual] = useState(false);
  const [visualNotice, setVisualNotice] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void api
      .visualEvidencePolicy()
      .then((policy) => {
        if (!cancelled) setVisualPolicy(policy);
      })
      .catch(() => {
        if (!cancelled) setVisualPolicy(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function clearVisualEvidence() {
    setClearingVisual(true);
    setVisualNotice(null);
    try {
      const result = await api.clearVisualEvidence();
      setVisualNotice(
        result.cleared > 0
          ? `Removed stored screenshots from ${result.cleared} ${result.cleared === 1 ? "analysis" : "analyses"}. The analyses themselves were kept.`
          : "No stored screenshots to remove — nothing was being kept.",
      );
    } catch (err) {
      setVisualNotice(
        `Could not clear visual evidence: ${err instanceof Error ? err.message : "unknown error"}`,
      );
    } finally {
      setClearingVisual(false);
    }
  }

  async function testConnection() {
    setTesting(true);
    setTestResult(null);
    try {
      const health = await api.health();
      // The API reports each dependency by name; the old `components` map it
      // was read from never existed, so this line used to say "undefined".
      const components = [
        `database ${health.database}${health.database_backend ? ` (${health.database_backend})` : ""}`,
        `cache ${health.cache}${health.cache_backend ? ` (${health.cache_backend})` : ""}`,
        `LLM ${health.ollama}`,
      ].join(", ");
      setTestResult({
        ok: true,
        message: `Backend ${health.status}. ${components}`,
      });
      // A backend that has just been started should be picked up without a
      // reload: re-probe so the header badge and the engine line agree.
      await refresh();
    } catch (err) {
      const tried = resolution?.tried.map((t) => t.url).join(", ") ?? settings.backendUrl;
      setTestResult({
        ok: false,
        message: `Could not reach a backend (tried ${tried}). ${err instanceof Error ? err.message : ""}`,
      });
      await refresh();
    } finally {
      setTesting(false);
    }
  }

  // The engine is resolved by probing, and the probe list is shown so an
  // operator on a phone or second laptop can see exactly which addresses were
  // tried and add whichever one is missing.
  const engine = resolution?.engine;
  const serverSide = engine !== undefined && engine !== "backend";

  return (
    <AppShell title="Settings" description="Dashboard configuration (no secrets are stored here)">
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Backend
          </h2>
          <label htmlFor="backend-url" className="mt-3 block text-sm font-medium">
            PhishBrain API base URL
          </label>
          <input
            id="backend-url"
            value={settings.backendUrl}
            onChange={(e) => update({ backendUrl: e.target.value })}
            className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
          <p className="mt-1 text-xs text-muted-foreground">
            {/* Naming the value this build actually ships, not a hardcoded
                localhost: a production build defaults to the deployed API and a
                development build to the local docker compose service. */}
            Default <span className="font-mono">{DEFAULT_SETTINGS.backendUrl}</span> (the API for
            this build — the docker compose service
            <span className="font-mono"> backend</span> locally).
            {serverSide ? (
              <>
                {" "}
                Scans currently run without it: no API answered, so this site uses its own server
                engine instead (fetch, DNS-over-HTTPS, RDAP, DOM analysis). Point this at a
                reachable API base to add the CatBoost pre-filter, the local LLM verdict and
                screenshots.
              </>
            ) : null}
          </p>
          <div className="mt-2 rounded-md border border-border bg-muted/40 p-2.5 text-xs">
            <p className="font-medium">
              Engine in use:{" "}
              <span className="font-mono">
                {engine === undefined
                  ? "probing…"
                  : engine === "backend"
                    ? `backend at ${resolution?.url}`
                    : engine === "hosted"
                      ? "hosted server engine"
                      : "built-in browser scanner"}
              </span>
            </p>
            {resolution?.tried.length ? (
              <ul className="mt-1 space-y-0.5 text-muted-foreground">
                {resolution.tried.map((t) => (
                  <li key={t.url}>
                    <span className="font-mono">{t.url}</span>
                    {" — "}
                    {t.reachable ? "answered" : "no answer"}
                  </li>
                ))}
              </ul>
            ) : null}
            <p className="mt-1 text-muted-foreground">
              Opening this dashboard from another device on your network? The page's own host is
              probed on the backend port as well, so a backend started with{" "}
              <span className="font-mono">--host 0.0.0.0</span> and allowed through the firewall is
              found automatically — see “Use it from another device” in the README.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void testConnection()}
            disabled={testing}
            className="mt-3 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {testing ? "Testing…" : "Test connection"}
          </button>
          {testResult ? (
            <p
              className={`mt-3 flex items-start gap-2 rounded-md border px-3 py-2 text-xs ${
                testResult.ok
                  ? "border-safe/40 bg-safe-soft text-safe"
                  : "border-danger/40 bg-danger-soft text-danger"
              }`}
            >
              {testResult.ok ? (
                <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              ) : (
                <XCircle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              )}
              <span className="break-words">{testResult.message}</span>
            </p>
          ) : null}
        </section>

        <section className="panel p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Analysis
          </h2>
          <label className="mt-3 flex items-start gap-3 text-sm">
            <input
              type="checkbox"
              checked={settings.demoMode}
              onChange={(e) => update({ demoMode: e.target.checked })}
              className="mt-1 size-4 accent-[var(--primary)]"
            />
            <span>
              <strong>Demo Mode</strong>
              <span className="block text-xs text-muted-foreground">
                When the backend is unreachable, compute deterministic results locally from
                synthetic samples. Everything produced this way is labelled DEMO DATA. Disable this
                to make backend failures surface as explicit errors.
              </span>
            </span>
          </label>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="safe-threshold" className="block text-sm font-medium">
                Safe threshold ({settings.safeThreshold})
              </label>
              <input
                id="safe-threshold"
                type="range"
                min={0}
                max={100}
                value={settings.safeThreshold}
                onChange={(e) => update({ safeThreshold: Number(e.target.value) })}
                className="mt-2 w-full accent-[var(--safe)]"
              />
            </div>
            <div>
              <label htmlFor="susp-threshold" className="block text-sm font-medium">
                Suspicious threshold ({settings.suspiciousThreshold})
              </label>
              <input
                id="susp-threshold"
                type="range"
                min={0}
                max={100}
                value={settings.suspiciousThreshold}
                onChange={(e) => update({ suspiciousThreshold: Number(e.target.value) })}
                className="mt-2 w-full accent-[var(--suspicious)]"
              />
            </div>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            These thresholds affect dashboard demo scoring only. The authoritative thresholds are
            the backend&apos;s <span className="font-mono">SAFE_THRESHOLD</span> /{" "}
            <span className="font-mono">SUSPICIOUS_THRESHOLD</span> environment variables.
          </p>
        </section>

        <section className="panel p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Appearance
          </h2>
          <div className="mt-3 flex gap-2">
            {(["dark", "light"] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => update({ theme: t })}
                aria-pressed={settings.theme === t}
                className={`rounded-md px-3 py-1.5 text-sm capitalize ${
                  settings.theme === t
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary hover:bg-accent"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </section>

        <section className="panel p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Privacy &amp; data
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            PhishBrain analyses data in memory by default. Raw email bodies are not stored unless
            <span className="font-mono"> STORE_RAW_EMAIL=true</span>; email addresses and personal
            identifiers are masked before persistence. Retention is controlled by{" "}
            <span className="font-mono">RETENTION_DAYS</span> on the backend. Nothing is sent to any
            third-party or proprietary AI service — all reasoning runs on a local Ollama model.
          </p>
          <p className="mt-3 text-sm text-muted-foreground">
            Screenshot evidence is purged on its own, shorter clock: the backend keeps a captured
            page image for{" "}
            <span className="font-mono">
              {visualPolicy
                ? `${visualPolicy.retention_days} day${visualPolicy.retention_days === 1 ? "" : "s"}`
                : "the configured window"}
            </span>{" "}
            (<span className="font-mono">VISUAL_RETENTION_DAYS</span>
            {visualPolicy && !visualPolicy.auto_purge_enabled
              ? ", automatic sweep disabled"
              : ", swept automatically"}
            ), then drops the image while keeping the analysis record.
          </p>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void clearVisualEvidence()}
              disabled={clearingVisual}
              className="rounded-md border border-danger/40 bg-danger-soft px-3 py-1.5 text-sm text-danger hover:bg-danger/20 disabled:opacity-50"
            >
              {clearingVisual ? "Clearing screenshots…" : "Clear all visual evidence"}
            </button>
            <button
              type="button"
              onClick={() => {
                clearDemoHistory();
                setNotice("Locally stored demo analyses were removed from this browser.");
              }}
              className="rounded-md border border-border bg-secondary px-3 py-1.5 text-sm hover:bg-accent"
            >
              Clear local demo data
            </button>
          </div>
          {visualNotice ? (
            <p className="mt-2 text-xs text-muted-foreground">{visualNotice}</p>
          ) : null}
          {notice ? <p className="mt-2 text-xs text-muted-foreground">{notice}</p> : null}
        </section>
      </div>
    </AppShell>
  );
}
