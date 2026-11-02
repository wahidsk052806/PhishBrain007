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
import { analysisDeepLink } from "../lib/hosted";
import { summarizePage } from "./page-analyzer";
import { parseEmail, type ParsedEmail } from "./email-parser";
import { isMailProviderHost } from "../lib/mail-hosts";
import type { AnalysisResult } from "../types/analysis";
import WarningBanner from "../components/WarningBanner";
import MailVerdictCard from "./MailVerdictCard";
import type { AlertDelivery } from "../background/alerts";
// Raw CSS text (built by @tailwindcss/vite) injected into the shadow root so
// banner styles are isolated from the host page.
// eslint-disable-next-line import/no-unresolved
import bannerCss from "../styles.css?inline";

const BANNER_HOST_ID = "phishbrain-banner-root";
const VERDICT_HOST_ID = "phishbrain-mail-verdict";

let bannerRoot: Root | null = null;
let bannerHost: HTMLElement | null = null;

/** Everything needed to re-render the in-message verdict card, including a
 * later alert-delivery update for the same scan. */
interface MailVerdictMessage {
  result: AnalysisResult;
  provider?: string;
  alert?: AlertDelivery | null;
  alertConfigured?: boolean;
  dashboardUrl?: string;
}

let verdictRoot: Root | null = null;
let verdictHost: HTMLElement | null = null;
let lastVerdict: MailVerdictMessage | null = null;

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
        // `/analysis?url=…`, not `/?analysis_id=…`: the dashboard re-runs the
        // pipeline for the scanned address, so the report is there whether the
        // result came from a backend or from the hosted fallback (whose ids the
        // backend's history has never seen).
        void runtimeApi.sendMessage({
          type: "OPEN_DASHBOARD",
          url: analysisDeepLink(dashboardUrl, result.url),
        });
      },
    }),
  );
}

/**
 * Where the verdict card goes: the reading pane, above the message header.
 * Kept next to the parser's own idea of the pane so the card cannot land in a
 * hidden list column or inside the message body it describes.
 */
function readingPaneElement(): HTMLElement | null {
  return (
    (document.querySelector('div[role="main"]') as HTMLElement | null) ??
    (document.querySelector("div.nH.bkK") as HTMLElement | null) ??
    (document.querySelector("div.aeN") as HTMLElement | null)
  );
}

/** Remove the card and forget the verdict it showed. */
function removeVerdictCard(): void {
  lastVerdict = null;
  if (verdictRoot) {
    verdictRoot.unmount();
    verdictRoot = null;
  }
  verdictHost?.remove();
  verdictHost = null;
}

/** Detach the host without losing the verdict (the provider re-rendered the pane). */
function detachVerdictHost(): void {
  if (verdictRoot) {
    verdictRoot.unmount();
    verdictRoot = null;
  }
  verdictHost?.remove();
  verdictHost = null;
}

function ensureVerdictHost(): { root: Root } | null {
  const pane = readingPaneElement();
  if (!pane) return null;
  if (verdictHost && verdictRoot && verdictHost.parentElement === pane) return { root: verdictRoot };

  // The pane was replaced (Gmail does this on every thread switch), so the old
  // shadow root is orphaned: rebuild it in the new pane.
  detachVerdictHost();

  const host = document.createElement("div");
  host.id = VERDICT_HOST_ID;
  host.style.all = "initial";
  host.style.display = "block";
  pane.prepend(host);

  const shadow = host.attachShadow({ mode: "open" });
  const style = document.createElement("style");
  style.textContent = bannerCss;
  shadow.appendChild(style);
  const mountPoint = document.createElement("div");
  shadow.appendChild(mountPoint);

  verdictHost = host;
  verdictRoot = createRoot(mountPoint);
  return { root: verdictRoot };
}

function renderMailVerdict(message: MailVerdictMessage): void {
  const target = ensureVerdictHost();
  if (!target) return;
  lastVerdict = message;
  const dashboardUrl = (message.dashboardUrl || DEFAULT_DASHBOARD_URL).replace(/\/$/, "");
  target.root.render(
    createElement(MailVerdictCard, {
      result: message.result,
      provider: message.provider ?? "gmail",
      alert: message.alert ?? null,
      alertConfigured: message.alertConfigured ?? false,
      onOpenReport: () => {
        // A message verdict has no single page to re-scan, so this opens the
        // analysis page (the first link is used when the result carries one).
        void runtimeApi.sendMessage({
          type: "OPEN_DASHBOARD",
          url: analysisDeepLink(dashboardUrl, message.result.url),
        });
      },
      onDismiss: () => removeVerdictCard(),
    }),
  );
}

/** Re-mount after the provider re-rendered the reading pane; keeps the verdict
 * so a clean message does not lose its card on Gmail's next repaint. */
function ensureVerdictAttached(): void {
  if (!lastVerdict) return;
  if (verdictHost && verdictHost.isConnected && verdictRoot) return;
  renderMailVerdict(lastVerdict);
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

const isMailProvider = isMailProviderHost;

function parsedEmailPayload(parsed: ParsedEmail): Record<string, unknown> {
  return {
    sender: parsed.sender ?? undefined,
    reply_to: parsed.replyTo ?? undefined,
    display_name: parsed.displayName ?? undefined,
    subject: parsed.subject ?? undefined,
    body_text: parsed.bodyText ?? undefined,
    // `text|href` pairs: the backend compares a link's visible text against its
    // real destination in this form, and the hrefs are already unwrapped from
    // the provider's redirector.
    links: parsed.links,
    has_attachments: parsed.hasAttachments,
    // Tells the report that quoted material was deliberately left out, rather
    // than silently scoring less of the message than the reader can see.
    has_quoted_content: parsed.quotedContentExcluded,
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
    parsed.quotedContentExcluded ? "quoted-excluded" : "independent",
    parsed.sender ?? "",
    parsed.replyTo ?? "",
    parsed.subject ?? "",
    body.length,
    body.slice(0, 120).replace(/\s+/g, " "),
    // A changed link set is a different message even when the prose is reused.
    parsed.links.length,
    parsed.links[0] ?? "",
  ].join("|");
}

let lastEmailFingerprint = "";
/** When the open message was last sent for analysis (ms since epoch). */
let lastEmailReportAt = 0;
/**
 * A message left open is re-analysed after this long even though nothing in it
 * changed: the first verdict may have been produced before the backend was
 * ready, and "keep scanning" is the behaviour users expect. Five minutes
 * matches the background worker's result cache, so the two do not fight.
 */
const EMAIL_REFRESH_MS = 5 * 60 * 1000;
/**
 * Focus/visibility re-checks ask for a fresh verdict, but switching windows is
 * not a reason to pay for a full email analysis: a forced re-report is skipped
 * when the same message was reported this recently. The Rescan button does not
 * use this gap — a deliberate click always re-scans.
 */
const FORCED_RECHECK_GAP_MS = 30 * 1000;

/**
 * Parses the currently open message (if any) and reports it to the background
 * worker. Safe to call repeatedly: it only sends when the open message
 * actually changed (opening a new conversation, switching tabs/views, or the
 * body finishing lazy-loading).
 */
function reportEmailSummary(force = false, minGapMs = 0): boolean {
  const hostname = window.location.hostname;
  if (!isMailProvider(hostname)) return false;

  try {
    const parsed = parseEmail(document, window.location);
    // `hasBody` is what tells an open message apart from the inbox list: the
    // list carries sender avatars but never a rendered body, and reporting it
    // produced a verdict for a message the user had not opened.
    if (!parsed || !parsed.hasBody) return false;
    const fingerprint = emailFingerprint(parsed);
    const changed = fingerprint !== lastEmailFingerprint;
    const stale = Date.now() - lastEmailReportAt >= EMAIL_REFRESH_MS;
    if (!changed) {
      if (Date.now() - lastEmailReportAt < minGapMs) return true;
      if (!force && !stale) return true;
    }
    if (changed) {
      // A different message is open: the previous verdict must never stay on
      // screen labelled as this one. The new result re-mounts the card.
      removeVerdictCard();
    }
    lastEmailFingerprint = fingerprint;
    lastEmailReportAt = Date.now();
    void runtimeApi.sendMessage({
      type: "EMAIL_SUMMARY",
      tabId: -1,
      url: window.location.href,
      email: parsedEmailPayload(parsed),
    });
    return true;
  } catch {
    // Best-effort only.
    return false;
  }
}

/** Re-check the open message on SPA navigation and on a light interval while
 * the tab is visible. Both Gmail (hash-based) and Outlook Web (history API)
 * swap message content without a full page load. */
function watchEmailProvider(): void {
  const hostname = window.location.hostname;
  if (!isMailProvider(hostname)) return;

  const check = (force = false, minGapMs = 0): void => {
    if (document.hidden) return;
    reportEmailSummary(force, minGapMs);
    ensureVerdictAttached();
  };

  window.addEventListener("hashchange", () => check(), { passive: true });
  window.addEventListener("popstate", () => check(), { passive: true });
  window.addEventListener("focus", () => check(true, FORCED_RECHECK_GAP_MS), { passive: true });
  // Coming back to a tab that sat in the background is the same event as
  // focusing it, and Gmail can have replaced the open message while hidden.
  document.addEventListener("visibilitychange", () => check(true, FORCED_RECHECK_GAP_MS));

  // Gmail occasionally lazy-loads the body after the URL settles, and the
  // SPA rewrites the URL through the history API without always firing
  // popstate. Polling cheaply re-reads only once per fingerprint change.
  const intervalMs = 2500;
  window.setInterval(() => check(), intervalMs);
}

runtimeApi.onMessage.addListener((raw: unknown, _sender, sendResponse) => {
  const message = raw as {
    type?: string;
    result?: AnalysisResult;
    dashboardUrl?: string;
    provider?: string;
    alert?: AlertDelivery | null;
    alertConfigured?: boolean;
  };
  if (message?.type === "PING") {
    // Answers the background worker's "is there a content script in this tab?"
    // probe, which decides whether the script must be injected first.
    sendResponse({ ok: true });
    return true;
  }
  if (message?.type === "REPARSE_EMAIL") {
    // "Rescan this page" on a mailbox means "re-read the open message": the
    // background worker deliberately does not scan the mail UI as a website.
    // `ok: false` (inbox list open, no message yet) lets it answer at once
    // instead of waiting for a verdict that is not coming.
    const ok = reportEmailSummary(true);
    sendResponse({ ok });
    return true;
  }
  if (message?.type === "SHOW_MAIL_VERDICT" && message.result) {
    // The inbox verdict card. Rendered per message, not per tab: it is the
    // result for the message currently open in the reading pane.
    renderMailVerdict({
      result: message.result,
      provider: message.provider,
      alert: message.alert ?? null,
      alertConfigured: message.alertConfigured ?? false,
      dashboardUrl: message.dashboardUrl,
    });
    return true;
  }
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
  // On a mailbox the message is the subject of the analysis, not the mail UI.
  // Scanning the Gmail page as well raced the email scan for the same tab (the
  // badge and banner showed whichever finished last), spent a full page fetch
  // plus LLM reasoning on “Google Mail”, and could flag the provider's own
  // page. The email verdict is the meaningful one there, so it is the only one.
  if (!isMailProvider(window.location.hostname)) reportPageSummary();
  reportEmailSummary(true);
  watchEmailProvider();
}

if (document.readyState === "complete" || document.readyState === "interactive") {
  init();
} else {
  window.addEventListener("DOMContentLoaded", init, { once: true });
}
