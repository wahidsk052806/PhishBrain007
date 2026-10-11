import { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "../styles.css";
import { tabsApi, runtimeApi } from "../lib/browser";
import { getSettings } from "../lib/settings";
import { DEFAULT_DASHBOARD_URL, getHealth } from "../services/api";
import type { AnalysisResult } from "../types/analysis";
import PopupReport from "./PopupReport";

type BackendStatus = "checking" | "online" | "fallback" | "offline";

/**
 * Lightweight reachability probe for the hosted fallback. Any HTTP response
 * (even 404) means the deployment answers; a network error means the domain
 * is unreachable (DNS/deploy issue).
 */
async function probeHosted(url: string): Promise<{ reachable: boolean; status: number | null }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(url, { method: "OPTIONS", signal: controller.signal });
      return { reachable: true, status: res.status };
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return { reachable: false, status: null };
  }
}

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

  const checkBackend = useCallback(async () => {
    setBackendStatus("checking");
    try {
      const settings = await getSettings();
      setDashboardUrl(settings.dashboardUrl);
      await getHealth(settings.backendUrl);
      setBackendStatus("online");
    } catch {
      // Local backend unreachable — is the hosted fallback answering instead?
      try {
        const settings = await getSettings();
        if (settings.useCloudFallback && settings.cloudScanUrl) {
          const probe = await probeHosted(settings.cloudScanUrl);
          if (probe.reachable && (probe.status === 200 || probe.status === 204)) {
            setBackendStatus("fallback");
            return;
          }
        }
      } catch {
        /* fall through to offline */
      }
      setBackendStatus("offline");
    }
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

  const openDashboard = useCallback(() => {
    void runtimeApi.sendMessage({
      type: "OPEN_DASHBOARD",
      // Fall back to the *dashboard* port, never the API port: 8000 serves the
      // FastAPI JSON root, which is not a page a user can navigate to.
      url: dashboardUrl || DEFAULT_DASHBOARD_URL,
    });
  }, [dashboardUrl]);

  const openOptions = useCallback(() => {
    const url = runtimeApi.getURL("options.html");
    void runtimeApi.sendMessage({ type: "OPEN_DASHBOARD", url });
  }, []);

  const statusMeta = STATUS_META[backendStatus];

  return (
    <div className="flex max-h-[600px] w-[400px] flex-col gap-3 overflow-y-auto bg-slate-950 p-4 font-sans text-slate-100">
      <header className="flex items-center justify-between">
        <div className="flex items-baseline gap-2">
          <h1 className="text-sm font-bold tracking-wide">PhishBrain</h1>
          <span className="text-[10px] text-slate-500">zero-day defence</span>
        </div>
        <span
          className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${statusMeta.classes}`}
        >
          {statusMeta.label}
        </span>
      </header>

      {backendStatus === "offline" && (
        <div
          role="alert"
          className="rounded-md border border-red-800 bg-red-950/40 p-2 text-[11px] text-red-200"
        >
          Neither the local backend nor the hosted live-scan fallback answered. Open{" "}
          <button type="button" onClick={openOptions} className="underline">
            settings
          </button>{" "}
          to check both URLs — the hosted fallback only works when your dashboard is deployed at the
          configured Live scan URL.
        </div>
      )}

      {backendStatus === "fallback" && (
        <div
          role="status"
          className="rounded-md border border-amber-800 bg-amber-950/40 p-2 text-[11px] text-amber-200"
        >
          Local backend is offline; scans are running through the hosted live-scan fallback.
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
          Open Dashboard
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
