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
import { DEFAULT_BACKEND_URL, DEFAULT_DASHBOARD_URL, getHealth } from "../services/api";
import { runtimeApi } from "../lib/browser";

type ConnectionStatus = "idle" | "checking" | "ok" | "error";

type HostedStatus = "idle" | "checking" | "ok" | "error";

interface VisualEvidenceStats {
  screenshots: number;
  learned: number;
  retentionDays: number;
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

  useEffect(() => {
    void (async () => {
      const stored = await getSettings();
      setLocalSettings(stored);
      setLoaded(true);
      void refreshVisualStats();
    })();
  }, [refreshVisualStats]);

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
    try {
      const health = await getHealth(settings.backendUrl);
      setConnectionStatus("ok");
      setConnectionMessage(`Connected. Status: ${health.status ?? "ok"}`);
    } catch (err) {
      setConnectionStatus("error");
      setConnectionMessage(err instanceof Error ? err.message : "Backend unavailable.");
    }
  }, [settings.backendUrl]);

  const handleTestHosted = useCallback(async () => {
    setHostedStatus("checking");
    setHostedMessage("");
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      let res: Response;
      try {
        res = await fetch(settings.cloudScanUrl, { method: "OPTIONS", signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
      if (res.ok || res.status === 204) {
        setHostedStatus("ok");
        setHostedMessage("Hosted live-scan endpoint is answering.");
      } else {
        setHostedStatus("error");
        setHostedMessage(
          `Hosted endpoint answered with HTTP ${res.status}. The dashboard may not be deployed with the public scan routes.`,
        );
      }
    } catch {
      setHostedStatus("error");
      setHostedMessage(
        "Hosted fallback is unreachable (domain does not resolve or the deployment is down).",
      );
    }
  }, [settings.cloudScanUrl]);

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
            placeholder="https://www.phishbrain07.app/api/public/scan"
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
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
            placeholder="https://www.phishbrain07.app/api/public/email-scan"
            className="rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-100"
          />
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
          When enabled, every detection at or above your banner threshold is sent to this webhook as
          a JSON SOC event (URL, domain, score, indicators). Use it with an email relay, Slack
          workflow, or your own SIEM. Nothing leaves the browser while this is off.
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
