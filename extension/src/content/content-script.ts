/**
 * Main content script entry point.
 *
 * - Summarizes the current page and reports it to the background service
 *   worker for webpage-layer analysis.
 * - Parses email metadata on Gmail/Outlook Web and reports it for
 *   email-layer analysis. Gmail and Outlook are single-page apps, so parsing
 *   runs at page load AND re-runs whenever a message is opened (URL/hash
 *   change or DOM change) — deduplicated by message fingerprint.
 * - Listens for SHOW_BANNER messages from the background script and injects
 *   an isolated (Shadow DOM) warning banner with "Proceed anyway" and
 *   "View details" actions.
 */

import { createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { runtimeApi } from "../lib/browser";
import { DEFAULT_DASHBOARD_URL } from "../services/api";
import { summarizePage } from "./page-analyzer";
import { parseEmail, type ParsedEmail } from "./email-parser";
import type { AnalysisResult } from "../types/analysis";
import WarningBanner from "../components/WarningBanner";
// Raw CSS text (built by @tailwindcss/vite) injected into the shadow root so
// banner styles are isolated from the host page.
// eslint-disable-next-line import/no-unresolved
import bannerCss from "../styles.css?inline";

const BANNER_HOST_ID = "phishbrain-banner-root";

let bannerRoot: Root | null = null;
let bannerHost: HTMLElement | null = null;

function removeBanner(): void {
  if (bannerRoot) {
    bannerRoot.unmount();
    bannerRoot = null;
  }
  if (bannerHost) {
    bannerHost.remove();
    bannerHost = null;
  }
}

function renderBanner(result: AnalysisResult, dashboardUrl: string): void {
  removeBanner();

  bannerHost = document.createElement("div");
  bannerHost.id = BANNER_HOST_ID;
  bannerHost.style.all = "initial";
  bannerHost.style.position = "fixed";
  bannerHost.style.top = "0";
  bannerHost.style.left = "0";
  bannerHost.style.right = "0";
  bannerHost.style.zIndex = "2147483647";
  document.documentElement.appendChild(bannerHost);

  const shadow = bannerHost.attachShadow({ mode: "open" });
  const style = document.createElement("style");
  style.textContent = bannerCss;
  shadow.appendChild(style);

  const mountPoint = document.createElement("div");
  shadow.appendChild(mountPoint);

  bannerRoot = createRoot(mountPoint);
  bannerRoot.render(
    createElement(WarningBanner, {
      result,
      dashboardUrl,
      onDismiss: () => removeBanner(),
      onGoBack: () => {
        removeBanner();
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.close();
        }
      },
      onProceedAnyway: () => {
        void runtimeApi.sendMessage({ type: "PROCEED_ANYWAY", hostname: window.location.hostname });
        removeBanner();
      },
      onViewDetails: () => {
        const url = `${dashboardUrl.replace(/\/$/, "")}/?analysis_id=${encodeURIComponent(result.analysis_id)}`;
        void runtimeApi.sendMessage({ type: "OPEN_DASHBOARD", url });
      },
    })
  );
}

function reportPageSummary(): void {
  try {
    const summary = summarizePage(document, window.location);
    void runtimeApi.sendMessage({
      type: "PAGE_SUMMARY",
      tabId: -1,
      url: window.location.href,
      summary: summary as unknown as Record<string, unknown>,
    });
  } catch {
    // Fail silently: page analysis is best-effort and must never break the host page.
  }
}

function isMailProvider(hostname: string): boolean {
  return hostname.includes("mail.google.com") || hostname.includes("outlook.");
}

function parsedEmailPayload(parsed: ParsedEmail): Record<string, unknown> {
  return {
    sender: parsed.sender ?? undefined,
    reply_to: parsed.replyTo ?? undefined,
    display_name: parsed.displayName ?? undefined,
    subject: parsed.subject ?? undefined,
    body_text: parsed.bodyText ?? undefined,
    links: parsed.links,
    spf: parsed.spf,
    dkim: parsed.dkim,
    dmarc: parsed.dmarc,
  };
}

/** Cheap identity of the currently open message so unchanged views are not
 * re-sent (Gmail/OWA re-render DOM constantly). */
function emailFingerprint(parsed: ParsedEmail): string {
  const body = parsed.bodyText ?? "";
  return [
    parsed.provider,
    parsed.sender ?? "",
    parsed.subject ?? "",
    body.length,
    body.slice(0, 120).replace(/\s+/g, " "),
  ].join("|");
}

let lastEmailFingerprint = "";

/**
 * Parses the currently open message (if any) and reports it to the background
 * worker. Safe to call repeatedly: it only sends when the open message
 * actually changed (opening a new conversation, switching tabs/views, or the
 * body finishing lazy-loading).
 */
function reportEmailSummary(force = false): void {
  const hostname = window.location.hostname;
  if (!isMailProvider(hostname)) return;

  try {
    const parsed = parseEmail(document, window.location);
    if (!parsed || (!parsed.sender && !parsed.bodyText)) return;
    const fingerprint = emailFingerprint(parsed);
    if (!force && fingerprint === lastEmailFingerprint) return;
    lastEmailFingerprint = fingerprint;
    void runtimeApi.sendMessage({
      type: "EMAIL_SUMMARY",
      tabId: -1,
      url: window.location.href,
      email: parsedEmailPayload(parsed),
    });
  } catch {
    // Best-effort only.
  }
}

/** Re-check the open message on SPA navigation and on a light interval while
 * the tab is visible. Both Gmail (hash-based) and Outlook Web (history API)
 * swap message content without a full page load. */
function watchEmailProvider(): void {
  const hostname = window.location.hostname;
  if (!isMailProvider(hostname)) return;

  const check = (force = false): void => {
    if (document.hidden) return;
    reportEmailSummary(force);
  };

  window.addEventListener("hashchange", () => check(), { passive: true });
  window.addEventListener("popstate", () => check(), { passive: true });
  window.addEventListener("focus", () => check(true), { passive: true });

  // Gmail occasionally lazy-loads the body after the URL settles; polling
  // cheaply re-reads only once per fingerprint change.
  const intervalMs = 2500;
  window.setInterval(() => check(), intervalMs);
}

runtimeApi.onMessage.addListener((raw: unknown) => {
  const message = raw as { type?: string; result?: AnalysisResult; dashboardUrl?: string };
  if (message?.type === "SHOW_BANNER" && message.result) {
    // The dashboard lives on its own port; :8000 is the API and would show raw
    // JSON instead of the report.
    renderBanner(message.result, message.dashboardUrl || DEFAULT_DASHBOARD_URL);
    return true;
  }
  if (message?.type === "HIDE_BANNER") {
    removeBanner();
    return true;
  }
  return false;
});

function init(): void {
  reportPageSummary();
  reportEmailSummary(true);
  watchEmailProvider();
}

if (document.readyState === "complete" || document.readyState === "interactive") {
  init();
} else {
  window.addEventListener("DOMContentLoaded", init, { once: true });
}
