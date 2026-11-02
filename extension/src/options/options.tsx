import { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "../styles.css";
import {
  getSettings,
  setSettings,
  DEFAULT_SETTINGS,
  type BannerMode,
  type ScreenshotPrivacy,
  type Settings,
} from "../lib/settings";
import {
  DEFAULT_BACKEND_URL,
  DEFAULT_DASHBOARD_URL,
  backendCandidates,
  findReachableBackend,
  getHealth,
} from "../services/api";
import { describeSource, resolveHostedEmail, resolveHostedScan } from "../lib/hosted";
import { runtimeApi } from "../lib/browser";

type ConnectionStatus = "idle" | "checking" | "ok" | "error";

type HostedStatus = "idle" | "checking" | "ok" | "error";

interface VisualEvidenceStats {
  screenshots: number;
  learned: number;
  retentionDays: number;
}

/** What the background reports after attempting a webhook delivery. */
interface AlertDeliveryResult {
  delivered: boolean;
  status: number | null;
  attempts: number;
  error: string | null;
  at: number;
}

/** The stored outcome of the most recent alert, for the status line below. */
interface LastAlertRecord extends AlertDeliveryResult {
  url: string;
  analysis_id: string;
  threshold: number;
  test: boolean;
}

function formatWhen(at: number): string {
  const secs = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return new Date(at).toLocaleString();
}

/**
 * One sentence that says whether the webhook actually accepted the event.
 * "Enabled" on its own is not evidence — this is.
 */
function describeDelivery(record: LastAlertRecord): string {
  const label = record.test ? "Test alert" : "Latest alert";
  const when = formatWhen(record.at);
  if (record.delivered) {
    return `${label} delivered (HTTP ${record.status}) ${when}.`;
  }
  const status = record.status !== null ? ` (HTTP ${record.status})` : "";
  return `${label} FAILED ${when}${status} — ${record.error ?? "unknown error"}`;
}

function Options() {
  const [settings, setLocalSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [loaded, setLoaded] = useState(false);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>("idle");
  const [connectionMessage, setConnectionMessage] = useState("");
  const [hostedStatus, setHostedStatus] = useState<HostedStatus>("idle");
  const [hostedMessage, setHostedMessage] = useState("");
  const [newAllowlistEntry, setNewAllowlistEntry] = useState("");
  const [visualStats, setVisualStats] = useState<VisualEvidenceStats | null>(null);
  const [clearingVisual, setClearingVisual] = useState(false);
  const [visualNotice, setVisualNotice] = useState<string | null>(null);
  const [lastAlert, setLastAlert] = useState<LastAlertRecord | null>(null);
  const [testingAlert, setTestingAlert] = useState(false);

  const refreshVisualStats = useCallback(async () => {
    try {
      const stats = await runtimeApi.sendMessage<{ type: string }, VisualEvidenceStats>({
        type: "VISUAL_EVIDENCE_STATS",
      });
      setVisualStats(stats);
    } catch {
      setVisualStats(null);
    }
  }, []);

  const refreshLastAlert = useCallback(async () => {
    try {
      const stored = await runtimeApi.sendMessage<{ type: string }, LastAlertRecord | null>({
        type: "LAST_ALERT",
      });
      setLastAlert(stored ?? null);
    } catch {
      setLastAlert(null);
    }
  }, []);

  useEffect(() => {
    void (async () => {
      const stored = await getSettings();
      setLocalSettings(stored);
      setLoaded(true);
      void refreshVisualStats();
      void refreshLastAlert();
    })();
  }, [refreshVisualStats, refreshLastAlert]);

  const handleTestAlert = useCallback(async () => {
    setTestingAlert(true);
    try {
      const result = await runtimeApi.sendMessage<{ type: string }, AlertDeliveryResult>({
        type: "TEST_ALERT",
      });
      setLastAlert({ ...result, url: "", analysis_id: "test-alert", threshold: 0, test: true });
      await refreshLastAlert();
    } catch {
      setLastAlert({
        delivered: false,
        status: null,
        attempts: 0,
        error: "The extension background did not answer.",
        at: Date.now(),
        url: "",
        analysis_id: "test-alert",
        threshold: 0,
        test: true,
      });
    } finally {
      setTestingAlert(false);
    }
  }, [refreshLastAlert]);

  const handleClearVisualEvidence = useCallback(async () => {
    setClearingVisual(true);
    setVisualNotice(null);
    try {
      const res = await runtimeApi.sendMessage<{ type: string }, { cleared: number }>({
        type: "CLEAR_VISUAL_EVIDENCE",
      });
      setVisualNotice(
        res.cleared > 0
          ? `Removed stored screenshots from ${res.cleared} ${res.cleared === 1 ? "result" : "results"} and forgot the learned brand fingerprints.`
          : "No stored screenshots to remove — nothing was being kept.",
      );
      await refreshVisualStats();
    } catch {
      setVisualNotice("Could not clear stored visual evidence.");
    } finally {
      setClearingVisual(false);
    }
  }, [refreshVisualStats]);

  const persist = useCallback(async (partial: Partial<Settings>) => {
    setLocalSettings((prev) => ({ ...prev, ...partial }));
    await setSettings(partial);
    setSavedAt(Date.now());
  }, []);

  const handleTestConnection = useCallback(async () => {
    setConnectionStatus("checking");
    setConnectionMessage("");
    // Probe the same candidate list the worker uses, so a healthy backend on
    // this computer is not reported as unreachable just because the Backend URL
    // field still holds a deployed address.
    const reachable = await findReachableBackend(settings.backendUrl);
    if (!reachable) {
      setConnectionStatus("error");
      setConnectionMessage(
        `No backend answered. Tried ${backendCandidates(settings.backendUrl).join(" and ")}.`,
      );
      return;
    }
    try {
      const health = await getHealth(reachable);
      setConnectionStatus("ok");
      const suffix =
        reachable === settings.backendUrl.trim().replace(/\/+$/, "")
          ? ""
          : ` (on this computer — the Backend URL field points elsewhere)`;
      setConnectionMessage(`Connected to ${reachable}. Status: ${health.status ?? "ok"}${suffix}`);
    } catch (err) {
      setConnectionStatus("error");
      setConnectionMessage(err instanceof Error ? err.message : "Backend unavailable.");
    }
  }, [settings.backendUrl]);

  const handleTestHosted = useCallback(async () => {
    setHostedStatus("checking");
    setHostedMessage("");
    // Probe the URL that would actually be used, not the raw field: the
    // endpoint is derived from the dashboard URL on most installations.
    const endpoint = resolveHostedScan(settings).url;
    if (!endpoint) {
      // Nothing to probe: an empty URL would fetch the extension's own origin
      // and report a bogus "HTTP 200".
      setHostedStatus("error");
      setHostedMessage(
        "No hosted endpoint yet — deploy the dashboard and set its URL above (or run the local backend).",
      );
      return;
    }
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      let res: Response;
      try {
        res = await fetch(endpoint, { method: "OPTIONS", signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
      if (res.ok || res.status === 204) {
        setHostedStatus("ok");
        setHostedMessage(`Hosted live-scan endpoint is answering at ${endpoint}.`);
        return;
      }
      setHostedStatus("error");
      setHostedMessage(
        `${endpoint} answered with HTTP ${res.status}. The domain resolves but the public scan routes are not deployed there.`,
      );
    } catch {
      setHostedStatus("error");
      setHostedMessage(
        `${endpoint} is unreachable (the domain does not resolve, or the deployment is down).`,
      );
    }
  }, [settings]);

  const hostedScan = useMemo(() => resolveHostedScan(settings), [settings]);
  const hostedEmail = useMemo(() => resolveHostedEmail(settings), [settings]);

  const addAllowlistEntry = useCallback(async () => {
    const value = newAllowlistEntry.trim().toLowerCase();
    if (!value) return;
    if (settings.allowlist.includes(value)) {
      setNewAllowlistEntry("");
      return;
    }
    await persist({ allowlist: [...settings.allowlist, value] });
    setNewAllowlistEntry("");
  }, [newAllowlistEntry, settings.allowlist, persist]);

  const removeAllowlistEntry = useCallback(
    async (entry: string) => {
      await persist({ allowlist: settings.allowlist.filter((e) => e !== entry) });
    },
    [settings.allowlist, persist],
  );

  const savedLabel = useMemo(() => {
    if (!savedAt) return "";
    return "Saved";
  }, [savedAt]);

  if (!loaded) {
    return <div className="p-6 text-sm text-slate-400">Loading settings…</div>;
  }

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 p-6 font-sans text-slate-100">
      <header>
        <h1 className="text-xl font-bold">PhishBrain007 Settings</h1>
        <p className="text-xs text-slate-400">
          Configure backend connectivity, scanning behavior and allowlisted domains.
        </p>
      </header>

      <section className="flex flex-col gap-3 rounded-lg border border-slate-700 bg-slate-900 p-4">
        <h2 className="text-sm font-semibold">Backend</h2>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Backend URL
          <input
            type="url"
            value={settings.backendUrl}
            onChange={(e) => setLocalSettings((prev) => ({ ...prev, backendUrl: e.target.value }))}
            onBlur={(e) => void persist({ backendUrl: e.target.value })}
            placeholder={DEFAULT_BACKEND_URL}
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Dashboard URL
          <input
            type="url"
            value={settings.dashboardUrl}
            onChange={(e) =>
              setLocalSettings((prev) => ({ ...prev, dashboardUrl: e.target.value }))
            }
            onBlur={(e) => void persist({ dashboardUrl: e.target.value })}
            placeholder={DEFAULT_DASHBOARD_URL}
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Live scan URL (used when the local backend is offline)
          <input
            type="url"
            value={settings.cloudScanUrl}
            onChange={(e) =>
              setLocalSettings((prev) => ({ ...prev, cloudScanUrl: e.target.value }))
            }
            onBlur={(e) => void persist({ cloudScanUrl: e.target.value })}
            placeholder={hostedScan.url}
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
          <span className="text-[10px] text-slate-500">
            Leave this empty to follow your dashboard: currently {describeSource(hostedScan.source)}{" "}
            → <code className="font-mono">{hostedScan.url}</code>
          </span>
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Email live-scan URL (used when the local backend is offline)
          <input
            type="url"
            value={settings.cloudEmailScanUrl}
            onChange={(e) =>
              setLocalSettings((prev) => ({ ...prev, cloudEmailScanUrl: e.target.value }))
            }
            onBlur={(e) => void persist({ cloudEmailScanUrl: e.target.value })}
            placeholder={hostedEmail.url}
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
          <span className="text-[10px] text-slate-500">
            Currently {describeSource(hostedEmail.source)} →{" "}
            <code className="font-mono">{hostedEmail.url}</code>
          </span>
        </label>

        <label className="flex items-center gap-2 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={settings.useCloudFallback}
            onChange={(e) => {
              setLocalSettings((prev) => ({ ...prev, useCloudFallback: e.target.checked }));
              void persist({ useCloudFallback: e.target.checked });
            }}
          />
          Fall back to hosted live scans when the local backend is unavailable
        </label>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleTestConnection}
            disabled={connectionStatus === "checking"}
            className="rounded-md border border-sky-600 bg-sky-900/40 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-900/70 disabled:opacity-50"
          >
            {connectionStatus === "checking" ? "Testing…" : "Test local backend"}
          </button>
          {connectionStatus === "ok" && (
            <span className="text-xs text-emerald-400">{connectionMessage}</span>
          )}
          {connectionStatus === "error" && (
            <span role="alert" className="text-xs text-red-400">
              Local backend unreachable: {connectionMessage}
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleTestHosted}
            disabled={hostedStatus === "checking"}
            className="rounded-md border border-amber-600 bg-amber-900/40 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-900/70 disabled:opacity-50"
          >
            {hostedStatus === "checking" ? "Testing…" : "Test hosted fallback"}
          </button>
          {hostedStatus === "ok" && (
            <span className="text-xs text-emerald-400">{hostedMessage}</span>
          )}
          {hostedStatus === "error" && (
            <span role="alert" className="text-xs text-red-400">
              {hostedMessage}
            </span>
          )}
        </div>
      </section>

      <section className="flex flex-col gap-3 rounded-lg border border-slate-700 bg-slate-900 p-4">
        <h2 className="text-sm font-semibold">Scanning</h2>

        <label className="flex items-center justify-between text-xs text-slate-300">
          Automatically scan visited pages
          <input
            type="checkbox"
            checked={settings.autoScan}
            onChange={(e) => void persist({ autoScan: e.target.checked })}
            className="h-4 w-4"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Warning banner mode
          <select
            value={settings.bannerMode}
            onChange={(e) => void persist({ bannerMode: e.target.value as BannerMode })}
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          >
            <option value="banner">Show warning banner</option>
            <option value="silent">Silent (badge only)</option>
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Banner threshold (threat score {settings.riskThreshold})
          <input
            type="range"
            min={0}
            max={100}
            value={settings.riskThreshold}
            onChange={(e) =>
              setLocalSettings((prev) => ({ ...prev, riskThreshold: Number(e.target.value) }))
            }
            onMouseUp={(e) =>
              void persist({ riskThreshold: Number((e.target as HTMLInputElement).value) })
            }
            onTouchEnd={(e) =>
              void persist({ riskThreshold: Number((e.target as HTMLInputElement).value) })
            }
          />
        </label>
      </section>

      <section className="flex flex-col gap-3 rounded-lg border border-slate-700 bg-slate-900 p-4">
        <h2 className="text-sm font-semibold">Real-time alerts (opt-in)</h2>
        <p className="text-xs text-slate-400">
          When enabled, every detection at or above your banner threshold is POSTed to this webhook
          as the same SOC event the dashboard emits — <code className="font-mono">event_id</code>,
          severity, score, indicators, <code className="font-mono">degraded</code> and the ML
          pre-filter's contribution. Use it with an email relay, a Slack workflow, or your own SIEM.
          Nothing leaves the browser while this is off.
        </p>
        <p className="text-xs text-slate-400">
          A webhook that is unreachable or returns an error cannot alert you, so use the button
          below to send a marked test event and see the exact HTTP answer.
        </p>
        <label className="flex items-center gap-2 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={settings.alertsEnabled}
            onChange={(e) => void persist({ alertsEnabled: e.target.checked })}
          />
          Send high-risk detections to my webhook
        </label>
        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Alert webhook URL
          <input
            type="url"
            value={settings.alertWebhookUrl}
            onChange={(e) =>
              setLocalSettings((prev) => ({ ...prev, alertWebhookUrl: e.target.value }))
            }
            onBlur={(e) => void persist({ alertWebhookUrl: e.target.value })}
            placeholder="https://hooks.slack.com/services/..."
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
        </label>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void handleTestAlert()}
            disabled={testingAlert || !settings.alertWebhookUrl.trim()}
            className="rounded-md border border-sky-600 bg-sky-900/40 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-900/70 disabled:opacity-50"
          >
            {testingAlert ? "Sending…" : "Send test alert"}
          </button>
          {!settings.alertWebhookUrl.trim() ? (
            <span className="text-[11px] text-slate-500">
              Set a webhook URL first — there is nothing to send to.
            </span>
          ) : null}
        </div>
        {lastAlert ? (
          <p
            aria-live="polite"
            className={`rounded-md border px-3 py-2 text-xs ${
              lastAlert.delivered
                ? "border-emerald-700/60 bg-emerald-950/30 text-emerald-300"
                : "border-red-700/60 bg-red-950/30 text-red-300"
            }`}
          >
            {describeDelivery(lastAlert)}
            {lastAlert.delivered && lastAlert.attempts > 1
              ? ` Delivered on attempt ${lastAlert.attempts}.`
              : ""}
          </p>
        ) : (
          <p className="text-[11px] text-slate-500">No alert has been sent yet.</p>
        )}
        <p className="text-[11px] text-slate-500">
          Alerts use the banner threshold ({settings.riskThreshold}) so what warns you and what
          pages your SOC cannot drift apart. A failing webhook never interrupts scanning, and each
          detection retries once before it is reported as failed here.
        </p>
      </section>

      <section className="flex flex-col gap-3 rounded-lg border border-slate-700 bg-slate-900 p-4">
        <h2 className="text-sm font-semibold">Screenshot &amp; visual clone analysis (opt-in)</h2>
        <p className="text-xs text-slate-400">
          When enabled, PhishBrain captures the visible tab after a scan and compares its layout
          fingerprint against known brand login pages — entirely on this device, no server needed. A
          page that mimics a genuine brand login (PayPal, Microsoft, Google…) is flagged as a
          possible visual clone. Visiting the genuine brand login once teaches the detector your
          browser's own rendering for sharper matches. Screenshots never leave your machine.
        </p>
        <label className="flex items-center gap-2 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={settings.captureScreenshots}
            onChange={(e) => void persist({ captureScreenshots: e.target.checked })}
          />
          Capture and visually analyse pages I visit
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Stored screenshot style
          <select
            value={settings.screenshotPrivacy}
            onChange={(e) =>
              void persist({ screenshotPrivacy: e.target.value as ScreenshotPrivacy })
            }
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          >
            <option value="pixels">Pixel thumbnail (shows the page as it looks)</option>
            <option value="wireframe">Wireframe only (layout edges, no colour or text)</option>
          </select>
          <span className="text-[11px] text-slate-500">
            The thumbnail is shown in the toolbar popup with the verdict. Wireframe keeps the page's
            layout as black-and-white edges so you can show what was compared without storing a
            readable copy of the page.
          </span>
        </label>

        <label className="flex flex-col gap-1 text-xs text-slate-300">
          Keep stored screenshots for (days)
          <input
            type="number"
            min={0}
            max={365}
            value={settings.visualRetentionDays}
            onChange={(e) =>
              setLocalSettings((prev) => ({
                ...prev,
                visualRetentionDays: Math.max(0, Math.min(365, Number(e.target.value) || 0)),
              }))
            }
            onBlur={(e) =>
              void persist({
                visualRetentionDays: Math.max(0, Math.min(365, Number(e.target.value) || 0)),
              })
            }
            className="w-24 rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
          <span className="text-[11px] text-slate-500">
            After this many days the stored screenshot is removed automatically, keeping the
            verdict. 0 keeps no screenshots at all — the popup then shows the text evidence only.
          </span>
        </label>

        <div className="flex flex-col gap-2 border-t border-slate-800 pt-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs text-slate-400">
              {visualStats
                ? `${visualStats.screenshots} stored screenshot${visualStats.screenshots === 1 ? "" : "s"} · ${visualStats.learned} learned brand fingerprint${visualStats.learned === 1 ? "" : "s"}`
                : "Visual evidence store unavailable."}
            </span>
            <button
              type="button"
              onClick={() => void handleClearVisualEvidence()}
              disabled={clearingVisual}
              className="rounded-md border border-red-700 bg-red-950/40 px-3 py-1.5 text-xs font-semibold text-red-200 hover:bg-red-950/70 disabled:opacity-50"
            >
              {clearingVisual ? "Clearing…" : "Clear all visual evidence"}
            </button>
          </div>
          {visualNotice ? (
            <p className="text-[11px] text-slate-400" aria-live="polite">
              {visualNotice}
            </p>
          ) : null}
        </div>
      </section>

      <section className="flex flex-col gap-3 rounded-lg border border-slate-700 bg-slate-900 p-4">
        <h2 className="text-sm font-semibold">Allowlisted domains</h2>
        <p className="text-xs text-slate-400">
          Pages on these domains (and subdomains) are never scanned or warned about.
        </p>
        <div className="flex gap-2">
          <input
            type="text"
            value={newAllowlistEntry}
            onChange={(e) => setNewAllowlistEntry(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void addAllowlistEntry();
            }}
            placeholder="example.com"
            className="flex-1 rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
          <button
            type="button"
            onClick={addAllowlistEntry}
            className="rounded-md border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700"
          >
            Add
          </button>
        </div>
        {settings.allowlist.length === 0 ? (
          <p className="text-xs text-slate-500">No allowlisted domains.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {settings.allowlist.map((entry) => (
              <li
                key={entry}
                className="flex items-center justify-between rounded-md bg-slate-950 px-2 py-1 text-xs text-slate-200"
              >
                {entry}
                <button
                  type="button"
                  onClick={() => void removeAllowlistEntry(entry)}
                  aria-label={`Remove ${entry} from allowlist`}
                  className="text-slate-500 hover:text-red-400"
                >
                  ✕
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <footer className="text-xs text-slate-500" aria-live="polite">
        {savedLabel}
      </footer>
    </div>
  );
}

const container = document.getElementById("root");
if (container) {
  createRoot(container).render(<Options />);
}
