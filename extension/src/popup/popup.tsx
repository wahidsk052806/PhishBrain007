import { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "../styles.css";
import { tabsApi, runtimeApi } from "../lib/browser";
import { getSettings } from "../lib/settings";
import {
  analysisDeepLink,
  dashboardOpenTarget,
  isLocalOrigin,
  isStaleDashboardUrl,
  probeHosted,
  resolveHostedScan,
} from "../lib/hosted";
import { findReachableBackend } from "../services/api";
import type { AnalysisResult } from "../types/analysis";
import PopupReport from "./PopupReport";

type BackendStatus = "checking" | "online" | "fallback" | "offline";

const STATUS_META: Record<BackendStatus, { label: string; classes: string }> = {
  checking: { label: "Checking…", classes: "bg-slate-800 text-slate-400" },
  online: { label: "Backend online", classes: "bg-emerald-950 text-emerald-300" },
  fallback: { label: "Hosted fallback", classes: "bg-amber-950 text-amber-300" },
  offline: { label: "Backend unavailable", classes: "bg-red-950 text-red-300" },
};

function Popup() {
  const [tabId, setTabId] = useState<number | null>(null);
  const [tabUrl, setTabUrl] = useState<string>("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [rescanning, setRescanning] = useState(false);
  const [backendStatus, setBackendStatus] = useState<BackendStatus>("checking");
  const [dashboardUrl, setDashboardUrl] = useState("");
  const [hostedUrl, setHostedUrl] = useState("");
  /** Dashboard URL is still the old `www.phishbrain07.app` placeholder. */
  const [staleDashboard, setStaleDashboard] = useState(false);
  /**
   * The engine answered on loopback even though a different Backend URL is
   * stored — a release build ships a public API origin, so this is the normal
   * state when the FastAPI stack is running locally. Worth saying out loud:
   * the scan used this computer's backend, not the configured one.
   */
  const [localEngine, setLocalEngine] = useState(false);

  const checkBackend = useCallback(async () => {
    setBackendStatus("checking");
    const settings = await getSettings();
    // The hosted live-scan endpoint is normally derived from the dashboard
    // URL, so "View details" and the fallback always agree on one origin.
    const hosted = resolveHostedScan(settings);
    setHostedUrl(hosted.url);
    // Never offer to open an undeployed default: `publicOrigin` happily parses
    // `https://www.phishbrain07.app`, which turned the button into a dead link.
    // Includes the local dashboard origin: it is the only dashboard a
    // development build has, and the previous public-only lookup left this
    // empty, so "Open Dashboard" fell through to the Options page — the same
    // destination as the Settings button next to it.
    setDashboardUrl(dashboardOpenTarget(hosted.url, settings.dashboardUrl) ?? "");
    setStaleDashboard(isStaleDashboardUrl(settings.dashboardUrl));
    // Try every candidate, not just the stored URL: a release build stores the
    // public API origin, so probing only that reported “Backend unavailable”
    // while the FastAPI stack on this very machine was answering on 8000.
    let reachable: string | null = null;
    try {
      reachable = await findReachableBackend(settings.backendUrl);
    } catch {
      /* treated as unreachable below */
    }
    if (reachable) {
      setBackendStatus("online");
      setLocalEngine(reachable.trim() !== settings.backendUrl.trim().replace(/\/+$/, ""));
      return;
    }
    try {
      if (settings.useCloudFallback && hosted.url) {
        const probe = await probeHosted(hosted.url);
        if (probe.reachable && (probe.status === 200 || probe.status === 204)) {
          setBackendStatus("fallback");
          return;
        }
      }
    } catch {
      /* fall through to offline */
    }
    setBackendStatus("offline");
  }, []);

  const loadCurrentTab = useCallback(async () => {
    setLoading(true);
    try {
      const [tab] = await tabsApi.query({ active: true, currentWindow: true });
      if (!tab || typeof tab.id !== "number") {
        setTabId(null);
        setResult(null);
        return;
      }
      setTabId(tab.id);
      setTabUrl(tab.url ?? "");
      const response = await runtimeApi.sendMessage<
        { type: string; tabId: number },
        AnalysisResult | null
      >({
        type: "GET_RESULT",
        tabId: tab.id,
      });
      setResult(response ?? null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void checkBackend();
    void loadCurrentTab();
  }, [checkBackend, loadCurrentTab]);

  // While a scan is in flight — or only its provisional result is in hand — ask
  // the worker for the finished verdict. The deterministic pass lands in about
  // a second and the full one (page fetch + screenshot + local model) replaces
  // it when it is ready, so the popup never waits ~a minute on a blank panel.
  useEffect(() => {
    if (tabId === null) return;
    if (!rescanning && !result?.provisional) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void (async () => {
        try {
          const current = await runtimeApi.sendMessage<
            { type: string; tabId: number },
            AnalysisResult | null
          >({ type: "GET_RESULT", tabId });
          if (!cancelled && current) setResult(current);
        } catch {
          /* the worker may restart mid-poll; the next tick retries */
        }
      })();
    }, 1500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [tabId, rescanning, result?.provisional]);

  const handleRescan = useCallback(async () => {
    if (tabId === null || !tabUrl) return;
    setRescanning(true);
    try {
      const response = await runtimeApi.sendMessage<
        { type: string; tabId: number; url: string },
        AnalysisResult | null
      >({
        type: "RESCAN",
        tabId,
        url: tabUrl,
      });
      setResult(response ?? null);
      await checkBackend();
    } finally {
      setRescanning(false);
    }
  }, [tabId, tabUrl, checkBackend]);

  // A tab that was already open when the extension loaded has no cached result,
  // so the popup used to answer “No scan result yet for this tab” and wait for
  // the user to press Rescan. Start the scan as soon as the popup knows what
  // the tab is; the button stays for a deliberate re-run.
  const autoScanTried = useRef(false);
  useEffect(() => {
    if (loading || autoScanTried.current) return;
    if (tabId === null || !/^https?:/i.test(tabUrl)) return;
    if (result) return;
    autoScanTried.current = true;
    void handleRescan();
  }, [loading, tabId, tabUrl, result, handleRescan]);

  const openOptions = useCallback(() => {
    const url = runtimeApi.getURL("options.html");
    void runtimeApi.sendMessage({ type: "OPEN_DASHBOARD", url });
  }, []);

  const openDashboard = useCallback(() => {
    // Only send the user to Settings when nothing at all is configured. A local
    // dashboard (127.0.0.1:8080) is a real destination, so it opens as-is.
    if (!dashboardUrl) {
      openOptions();
      return;
    }
    // Carry the page that was just scanned, so the dashboard opens on its
    // report — re-scanned by the backend, with the screenshot, pre-filter and
    // model layers the popup could not run — instead of the home page. The
    // result is preferred over the tab URL because it is the address that was
    // actually scored (e.g. after a redirect).
    const target = result?.url || tabUrl;
    void runtimeApi.sendMessage({ type: "OPEN_DASHBOARD", url: analysisDeepLink(dashboardUrl, target) });
  }, [dashboardUrl, openOptions, result?.url, tabUrl]);

  const statusMeta = STATUS_META[backendStatus];

  return (
    <div className="flex max-h-[600px] w-[400px] flex-col gap-3 overflow-y-auto bg-slate-950 p-4 font-sans text-slate-100">
      <header className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-sky-950 text-sky-300 ring-1 ring-sky-800">
            <svg viewBox="0 0 24 24" aria-hidden="true" className="size-4" fill="none">
              <path
                d="M12 3.2 5 6v5.4c0 4.1 2.8 7.6 7 9.4 4.2-1.8 7-5.3 7-9.4V6l-7-2.8Z"
                stroke="currentColor"
                strokeWidth="1.7"
                strokeLinejoin="round"
              />
              <path
                d="m8.7 11.9 2.3 2.3 4.3-4.6"
                stroke="currentColor"
                strokeWidth="1.7"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <div className="leading-tight">
            <h1 className="text-sm font-bold tracking-wide">PhishBrain</h1>
            <span className="text-[10px] text-slate-500">zero-day defence</span>
          </div>
        </div>
        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${statusMeta.classes}`}
        >
          <span className="size-1.5 rounded-full bg-current" />
          {statusMeta.label}
        </span>
      </header>

      {(backendStatus === "online" || backendStatus === "fallback") && localEngine && (
        <div
          role="status"
          className="rounded-md border border-slate-700 bg-slate-900 p-2 text-[11px] text-slate-300"
        >
          Using the backend on this computer (<code className="font-mono">127.0.0.1:8000</code>).
          The Backend URL in{" "}
          <button type="button" onClick={openOptions} className="underline">
            settings
          </button>{" "}
          points elsewhere and was not reachable.
        </div>
      )}

      {backendStatus === "offline" && (
        <div
          role="alert"
          className="rounded-md border border-red-800 bg-red-950/40 p-2 text-[11px] text-red-200"
        >
          <span className="font-semibold">No scan engine is reachable.</span>{" "}
          {staleDashboard ? (
            <>
              Your Dashboard URL is still the old placeholder, which was never deployed. Start the
              local backend, or deploy the dashboard and paste its URL in{" "}
              <button type="button" onClick={openOptions} className="underline">
                settings
              </button>
              .
            </>
          ) : hostedUrl ? (
            <>
              Neither the local backend nor the hosted live-scan endpoint answered. Tried{" "}
              <code className="break-all font-mono text-red-100">{hostedUrl}</code> — that endpoint
              only exists once your dashboard is deployed, and its address follows the Dashboard URL
              in{" "}
              <button type="button" onClick={openOptions} className="underline">
                settings
              </button>
              .
            </>
          ) : (
            <>
              No local backend is running and no hosted endpoint is configured. Start the backend (
              <code className="font-mono">uvicorn app.main:app --port 8000</code>) or deploy the
              dashboard and paste its URL in{" "}
              <button type="button" onClick={openOptions} className="underline">
                settings
              </button>
              .
            </>
          )}
        </div>
      )}

      {backendStatus === "fallback" && (
        <div
          role="status"
          className="rounded-md border border-amber-800 bg-amber-950/40 p-2 text-[11px] text-amber-200"
        >
          Local backend is offline; scans are running through the hosted live-scan endpoint{" "}
          {hostedUrl ? <code className="font-mono">{hostedUrl}</code> : null}.
        </div>
      )}

      {loading ? (
        <p className="py-6 text-center text-xs text-slate-400">Loading current tab…</p>
      ) : !result ? (
        <div className="rounded-md border border-slate-700 bg-slate-900 p-3 text-[11px] text-slate-400">
          <p className="mb-1 font-semibold text-slate-300">No scan result yet for this tab</p>
          <p>
            This page may not have been scanned yet, or it was skipped because it is an internal
            browser page, was added to your allowlist, or had not finished loading.
          </p>
          <p className="mt-1">Use “Rescan this page” below to analyse the current URL now.</p>
        </div>
      ) : (
        <PopupReport result={result} />
      )}

      {dashboardUrl && isLocalOrigin(dashboardUrl) && (
        <p className="text-[10px] text-slate-500">
          Dashboard: <code className="font-mono text-slate-400">{dashboardUrl}</code>
          {" "}— the local dashboard, served by <code className="font-mono">npm run dev</code>. Set a
          Dashboard URL in Settings to use a deployed one.
        </p>
      )}

      <div className="mt-1 flex flex-wrap items-center gap-2 border-t border-slate-800 pt-3">
        <button
          type="button"
          onClick={handleRescan}
          disabled={rescanning || tabId === null}
          className="rounded-md border border-sky-600 bg-sky-900/40 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-900/70 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {rescanning ? "Rescanning…" : "Rescan this page"}
        </button>
        <button
          type="button"
          onClick={openDashboard}
          className="rounded-md border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700"
        >
          {dashboardUrl ? "Open Dashboard" : "Set up dashboard"}
        </button>
        <button
          type="button"
          onClick={openOptions}
          className="ml-auto rounded-md px-2 py-1.5 text-xs text-slate-400 hover:text-slate-200"
        >
          Settings
        </button>
      </div>
    </div>
  );
}

const container = document.getElementById("root");
if (container) {
  createRoot(container).render(<Popup />);
}
