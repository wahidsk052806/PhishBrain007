import {
  storage,
  tabsApi,
  runtimeApi,
  actionApi,
  notificationsApi,
  scriptingApi,
} from "../lib/browser";
import {
  analyzeUrl,
  analyzePage,
  analyzeEmail,
  analyzeUrlCloud,
  analyzeEmailCloud,
  backendCandidates,
  ApiError,
} from "../services/api";
import type { Settings } from "../lib/settings";
import { getSettings, setSettings, DEFAULT_SETTINGS } from "../lib/settings";
import { configuredDashboardOrigin, resolveHostedEmail, resolveHostedScan } from "../lib/hosted";
import { isMailProviderUrl, mailProviderFor } from "../lib/mail-hosts";
import type { AnalysisResult } from "../types/analysis";
import {
  shouldScanUrl,
  badgeForResult,
  badgeForUnavailable,
  shouldShowBanner,
  isCacheFresh,
  parseIncomingMessage,
  type CacheEntry,
} from "./logic";
import {
  buildSocAlert,
  buildTestAlert,
  sendSocAlert,
  shouldSendAlert,
  type AlertDelivery,
} from "./alerts";
import { runVisualScan, applyVisualToResult, persistLearnedRef } from "./visual";
import {
  DAY_MS,
  clearAllVisualEvidence,
  shouldStoreImages,
  stripVisualEvidence,
  sweepStoredVisualEvidence,
  visualEvidenceStats,
} from "./visual-retention";

const CACHE_TTL_MS = 5 * 60 * 1000;
const VISUAL_COOLDOWN_MS = 90 * 1000; // don't re-screenshot the same tab too often
const tabCache = new Map<number, CacheEntry>();
/** tabId:url pairs already alerted, so a rescan/visual pass never re-notifies. */
const notifiedKeys = new Set<string>();

type ServerResult = AnalysisResult & { target?: string };

/**
 * Server results carry `target` (see src/lib/phishbrain/demo.ts), while the
 * extension expects `url`. Normalise on ingest so cache freshness checks,
 * the popup and banners all see a consistent shape.
 */
function normalizeResult(result: AnalysisResult): AnalysisResult {
  const server = result as ServerResult;
  const next: ServerResult = { ...server };
  if (!next.url && next.target) {
    next.url = next.target;
  } else if (!next.target && next.url) {
    next.target = next.url;
  }
  if (typeof next.threat_score !== "number") next.threat_score = 0;
  if (!next.risk_level) next.risk_level = "SAFE";
  return next as AnalysisResult;
}

async function setBadge(tabId: number, badge: { text: string; color: string; title: string }) {
  await actionApi.setBadgeText({ tabId, text: badge.text });
  await actionApi.setBadgeBackgroundColor({ tabId, color: badge.color });
  await actionApi.setTitle({ tabId, title: badge.title });
}

/**
 * Persist a result for a tab (in memory and in storage).
 *
 * `storeImages: false` is the retention-0 case ("store none"): the picture is
 * stripped *before* it is written anywhere, so the promise the options page
 * makes holds immediately rather than only after the next hourly sweep. It is
 * applied to the in-memory entry too, so the popup shows exactly what is
 * stored instead of a picture that exists only until the tab closes.
 */
async function persistResult(
  tabId: number,
  result: AnalysisResult,
  options: { storeImages?: boolean; visualAt?: number } = {},
) {
  const { storeImages = true, visualAt } = options;
  const entry: CacheEntry = {
    result: storeImages ? result : stripVisualEvidence(result),
    cachedAt: Date.now(),
    ...(visualAt ? { visualAt } : {}),
  };
  tabCache.set(tabId, entry);
  await storage.set({ [`result_${tabId}`]: entry });
}

/** What the options page shows to prove the webhook is really accepting events. */
interface LastAlertRecord extends AlertDelivery {
  url: string;
  analysis_id: string;
  threshold: number;
  test: boolean;
}

/**
 * Record the outcome of the most recent alert so the options page can answer
 * "is my SOC actually receiving these?" instead of leaving the user to infer
 * it from silence. Kept in storage (not a module variable) because a service
 * worker restart would erase it.
 */
async function persistAlertDelivery(record: LastAlertRecord): Promise<void> {
  try {
    await storage.set({ lastAlert: record });
  } catch {
    // Diagnostics must never break the delivery path that produced them.
  }
}

/**
 * Opt-in SOC/SIEM alert for a finished analysis.
 *
 * The event is the backend's own SOC event where the analysis has one (see
 * background/alerts.ts), delivered with a bounded timeout and one retry, and
 * the outcome is recorded for the options page. Never throws.
 */
async function deliverAlert(
  result: AnalysisResult,
  settings: Settings,
): Promise<AlertDelivery | null> {
  if (!shouldSendAlert(result, settings)) return null;
  const delivery = await sendSocAlert(settings.alertWebhookUrl, buildSocAlert(result));
  await persistAlertDelivery({
    ...delivery,
    url: result.url,
    analysis_id: result.analysis_id,
    threshold: settings.riskThreshold,
    test: false,
  });
  return delivery;
}

async function showBanner(
  tabId: number,
  result: AnalysisResult,
  settings: Settings,
): Promise<void> {
  if (!shouldShowBanner(result, settings)) return;
  try {
    await tabsApi.sendMessage(tabId, {
      type: "SHOW_BANNER",
      result,
      // “View details” must not point at an undeployed placeholder; fall back to
      // the local dashboard origin, which is where `npm run dev` serves it.
      dashboardUrl:
        configuredDashboardOrigin(settings.dashboardUrl) ?? DEFAULT_SETTINGS.dashboardUrl,
    });
  } catch {
    // content script may not be injected yet (e.g. chrome:// pages navigated away); ignore.
  }
}

/**
 * Desktop alert for a HIGH_RISK hit — the one signal that reaches the user even
 * when they are looking at another tab. "Silent" banner mode disables it, and a
 * `tabId:url` key keeps a rescan or the visual pass from alerting twice.
 */
async function notifyHighRisk(
  tabId: number,
  result: AnalysisResult,
  settings: Settings,
  /** "message" on a mailbox, so the alert names the right thing. */
  subject: "page" | "message" = "page",
): Promise<void> {
  if (settings.bannerMode === "silent") return;
  if (result.risk_level !== "HIGH_RISK") return;
  const key = `${tabId}:${result.url}`;
  if (notifiedKeys.has(key)) return;
  notifiedKeys.add(key);
  const host = result.domain || result.url || `this ${subject}`;
  const lead = result.indicators?.[0] ?? "Multiple phishing indicators were detected.";
  try {
    await notificationsApi.create({
      type: "basic",
      iconUrl: runtimeApi.getURL("icons/icon128.png"),
      title: `PhishBrain: high-risk ${subject} (${Math.round(result.threat_score)}/100)`,
      message: `${host} — ${lead}`,
    });
  } catch {
    // Notifications are best-effort; a missing permission must never break a scan.
  }
}

let lastVisualSweepAt = 0;
const VISUAL_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Enforce the screenshot-evidence retention policy over both the persisted
 * results and the in-memory cache.
 *
 * Throttled to once an hour, so a scan storm never turns into a storage walk;
 * `force` is used at browser launch, when the age check is what actually
 * matters. A window of 0 means "store none" and strips every result.
 */
async function applyVisualRetention(force = false): Promise<number> {
  if (!force && Date.now() - lastVisualSweepAt < VISUAL_SWEEP_INTERVAL_MS) return 0;
  lastVisualSweepAt = Date.now();
  const settings = await getSettings();
  const stripped = await sweepStoredVisualEvidence(settings.visualRetentionDays);
  const windowMs = Math.max(0, settings.visualRetentionDays) * DAY_MS;
  const now = Date.now();
  for (const [tabId, entry] of tabCache) {
    if (now - (entry.cachedAt ?? 0) <= windowMs) continue;
    const next = stripVisualEvidence(entry.result);
    if (next !== entry.result) tabCache.set(tabId, { ...entry, result: next });
  }
  return stripped;
}

/**
 * Send the in-message verdict card to a mailbox tab.
 *
 * The alert outcome is a separate argument because it arrives after the scan:
 * the card is shown straight away with "sending…" and is replaced by the same
 * card with the delivery result a moment later, so a slow webhook never delays
 * the verdict.
 */
async function showMailVerdict(
  tabId: number,
  result: AnalysisResult,
  settings: Settings,
  alert: AlertDelivery | null,
  provider: string,
): Promise<void> {
  try {
    await tabsApi.sendMessage(tabId, {
      type: "SHOW_MAIL_VERDICT",
      result,
      provider,
      alert,
      alertConfigured: Boolean(settings.alertWebhookUrl.trim()),
      dashboardUrl: configuredDashboardOrigin(settings.dashboardUrl) ?? DEFAULT_SETTINGS.dashboardUrl,
    });
  } catch {
    // No content script (the tab navigated away from the mailbox) — the badge
    // and the popup still carry the result.
  }
}

interface FinalizeOptions {
  /**
   * Set for a mailbox scan. Enables the in-message verdict card, and replaces
   * the page-level warning banner, which on Gmail covered the message header
   * and offered "Proceed anyway" — an action that would allowlist the mailbox
   * itself. The card is the alert on a mailbox.
   */
  mailCard?: { provider: string };
}

/**
 * Single funnel for every completed scan: persist the cache, update the
 * toolbar badge, fire the opt-in webhook and show the warning banner (or, on a
 * mailbox, the in-message verdict card).
 */
async function finalizeScan(
  tabId: number,
  url: string,
  result: AnalysisResult,
  settings: Settings,
  options: FinalizeOptions = {},
): Promise<AnalysisResult> {
  const normalized = normalizeResult(result);
  await persistResult(tabId, normalized, {
    storeImages: shouldStoreImages(settings.visualRetentionDays),
  });
  await setBadge(tabId, badgeForResult(normalized));

  const isMail = Boolean(options.mailCard);
  void notifyHighRisk(tabId, normalized, settings, isMail ? "message" : "page");
  if (!isMail) await showBanner(tabId, normalized, settings);

  // Alerting runs last and unawaited so a slow webhook never delays the badge,
  // banner or the response the popup is waiting on. It is safe to leave in
  // flight: delivery is bounded to two 4-second attempts, and Chrome only
  // tears a worker down when a fetch response takes longer than 30 seconds.
  // Awaiting it here would instead stall every scan on a misconfigured URL.
  const alertPromise = deliverAlert(normalized, settings);
  if (options.mailCard) {
    const provider = options.mailCard.provider;
    void showMailVerdict(tabId, normalized, settings, null, provider);
    void alertPromise.then((delivery) =>
      showMailVerdict(tabId, normalized, settings, delivery, provider),
    );
  } else {
    void alertPromise;
  }

  // Lazy enforcement of the evidence-retention policy (throttled internally).
  void applyVisualRetention();
  return normalized;
}

/**
 * Opt-in visual brand-clone analysis of the ACTIVE tab. Called after page
 * scans and again when a tab becomes active (a page that finished loading in
 * the background can only be screenshotted once the user switches to it).
 */
async function runVisualIfEnabled(
  tabId: number,
  url: string,
  result: AnalysisResult,
  settings: Settings,
  delayMs = 0,
): Promise<AnalysisResult> {
  if (!settings.captureScreenshots) return result;
  if (!shouldScanUrl(url, settings)) return result;

  const cached = tabCache.get(tabId);
  const lastVisualAt = cached?.visualAt ?? 0;
  if (Date.now() - lastVisualAt < VISUAL_COOLDOWN_MS) return result;

  const attach = async (): Promise<AnalysisResult> => {
    const scan = await runVisualScan(tabId, url, settings.screenshotPrivacy === "wireframe");
    if (!scan) return result;
    if (scan.learnBrand && scan.outcome.phash) {
      // The user is on the genuine brand login: remember its fingerprint from
      // THEIR browser engine so future clone comparisons are engine-accurate.
      await persistLearnedRef(scan.learnBrand, scan.outcome.phash);
    }
    const merged = applyVisualToResult(result, scan.outcome);
    if (merged !== result) {
      await persistResult(tabId, merged, {
        storeImages: shouldStoreImages(settings.visualRetentionDays),
        visualAt: Date.now(),
      });
      await setBadge(tabId, badgeForResult(merged));
      void deliverAlert(merged, settings);
      void notifyHighRisk(tabId, merged, settings);
      await showBanner(tabId, merged, settings);
    }
    return merged;
  };

  if (delayMs > 0) {
    void new Promise((resolve) => setTimeout(resolve, delayMs)).then(attach);
    return result;
  }
  return attach();
}

interface ScanDepth {
  /** Run the local LLM verdict — the slowest layer on CPU hardware. */
  useLlm?: boolean;
  /** Ask the backend to fetch and screenshot the page (the visual layer). */
  fetchPage?: boolean;
}

/**
 * Run `attempt` against the self-hosted engine, trying every candidate base.
 *
 * `backendCandidates` returns the configured address first and loopback second,
 * so a build that ships a public API origin still uses the FastAPI stack when
 * one is running on this computer. A server that *answered* with an error is
 * deliberately not retried elsewhere: it is reachable, and its HTTP status is
 * the real problem — retrying would hide a 500 behind "no local backend".
 */
async function withLocalBackend<T>(
  settings: Settings,
  attempt: (baseUrl: string) => Promise<T>,
): Promise<T> {
  let lastError: unknown;
  for (const baseUrl of backendCandidates(settings.backendUrl)) {
    try {
      return await attempt(baseUrl);
    } catch (err) {
      lastError = err;
      if (err instanceof ApiError && (err.code === "HTTP_ERROR" || err.code === "PARSE_ERROR")) {
        throw err;
      }
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new ApiError("BACKEND_UNAVAILABLE", "No local backend is running.");
}

async function analyzeWithFallback(
  url: string,
  settings: Settings,
  depth: ScanDepth = {},
): Promise<AnalysisResult> {
  try {
    return await withLocalBackend(settings, (baseUrl) =>
      analyzeUrl(
        { url, fetch_page: depth.fetchPage ?? true, use_llm: depth.useLlm ?? true },
        baseUrl,
      ),
    );
  } catch (err) {
    if (!settings.useCloudFallback) throw err;
    return await analyzeUrlCloud({ url }, resolveHostedScan(settings).url);
  }
}

async function analyzePageWithFallback(
  url: string,
  summary: Record<string, unknown>,
  settings: Settings,
): Promise<AnalysisResult> {
  try {
    return await withLocalBackend(settings, (baseUrl) =>
      analyzePage({ url, dom_summary: JSON.stringify(summary) }, baseUrl),
    );
  } catch (err) {
    if (!settings.useCloudFallback) throw err;
    // The hosted scan re-fetches the page itself, so a URL scan is the
    // closest fallback; client-side summary evidence is preserved nowhere but
    // the hosted fetch already covers the same webpage signals.
    return await analyzeUrlCloud({ url }, resolveHostedScan(settings).url);
  }
}

async function analyzeEmailWithFallback(
  url: string,
  email: {
    sender?: string;
    reply_to?: string;
    display_name?: string;
    subject?: string;
    body_text?: string;
    links?: string[];
    has_attachments?: boolean;
    has_quoted_content?: boolean;
    spf?: string;
    dkim?: string;
    dmarc?: string;
  },
  settings: Settings,
  depth: ScanDepth = {},
): Promise<AnalysisResult> {
  try {
    return await withLocalBackend(settings, (baseUrl) =>
      analyzeEmail(
        {
          sender: email.sender,
          reply_to: email.reply_to,
          display_name: email.display_name,
          has_attachments: email.has_attachments,
          has_quoted_content: email.has_quoted_content,
          subject: email.subject,
          body_text: email.body_text,
          links: email.links,
          spf: email.spf,
          dkim: email.dkim,
          dmarc: email.dmarc,
          use_llm: depth.useLlm ?? true,
        },
        baseUrl,
      ),
    );
  } catch (err) {
    if (!settings.useCloudFallback) throw err;
    return await analyzeEmailCloud(
      {
        sender: email.sender,
        reply_to: email.reply_to,
        display_name: email.display_name,
        subject: email.subject,
        body_text: email.body_text,
        links: email.links,
        has_attachments: email.has_attachments,
        has_quoted_content: email.has_quoted_content,
      },
      resolveHostedEmail(settings).url,
    );
  }
}

/**
 * Make sure a tab has a live content script, injecting it when it does not.
 *
 * The ping is the test: a page with the script answers it, a page without one
 * rejects with “Could not establish connection”. Injection is then a no-op for
 * the page's own state — the script reads the DOM, it does not restart the page.
 */
async function ensureContentScript(tabId: number): Promise<boolean> {
  try {
    await tabsApi.sendMessage(tabId, { type: "PING" });
    return true;
  } catch {
    /* no listener in that tab yet */
  }
  try {
    await scriptingApi.executeScript({ target: { tabId }, files: ["content.js"] });
    return true;
  } catch {
    // Restricted page (about:, add-on manager, PDF viewer): nothing to inject.
    return false;
  }
}

/**
 * Per-tab sequence for mailbox scans. The content script deliberately reports
 * the open message again and again (new message, refresh, focus, Rescan), and
 * a full pass can take a minute on CPU hardware: without this token a slow
 * scan of the message the user already left would finish last and replace the
 * newer message's card, badge, alert and stored result with its own.
 */
const emailScanTokens = new Map<number, number>();

/** A scan already running for a tab, so the same navigation cannot start two. */
const scansInFlight = new Map<number, string>();
/** Bumped per scan; a superseded scan must not write over a newer result. */
const scanTokens = new Map<number, number>();

async function scanTab(tabId: number, url: string, force = false) {
  // A mailbox tab belongs to the message, not to the provider's UI: the content
  // script reports the open email, and this URL scan would either duplicate that
  // (racing it for the same badge and banner) or report “Google Mail” as the
  // finding. Nothing is set here — the email path owns the tab.
  if (isMailProviderUrl(url)) {
    // Firefox only injects declared content scripts into pages loaded *after*
    // the add-on is installed or reloaded. A Gmail tab that was already open
    // therefore has no listener: the mailbox reports nothing, "Rescan" sends
    // REPARSE_EMAIL into the void, and the popup answers “No scan result yet
    // for this tab” forever. Make sure the script is there.
    await ensureContentScript(tabId);
    return;
  }

  const settings = await getSettings();
  if (!force && !shouldScanUrl(url, settings)) {
    await setBadge(tabId, badgeForResult(null));
    return;
  }

  const cached = tabCache.get(tabId);
  if (!force && isCacheFresh(cached, url, CACHE_TTL_MS, Date.now())) {
    await setBadge(tabId, badgeForResult(cached.result));
    return;
  }

  // A full navigation reports both a URL change and `status: complete`, so the
  // same scan would otherwise be started twice and race itself for the badge.
  if (!force && scansInFlight.get(tabId) === url) return;
  scansInFlight.set(tabId, url);

  const token = (scanTokens.get(tabId) ?? 0) + 1;
  scanTokens.set(tabId, token);
  const current = () => scanTokens.get(tabId) === token;

  try {
    // Phase 1 — deterministic layers only: no page fetch and no model. On
    // CPU-only hardware the full pipeline needs 40–60 s, nearly all of it
    // inside llama.cpp, and waiting for that made the popup look stuck. This
    // lands in about a second and is labelled provisional; phase 2 replaces it.
    try {
      const quick = await analyzeWithFallback(url, settings, { useLlm: false, fetchPage: false });
      if (!current()) return;
      const provisional: AnalysisResult = { ...quick, provisional: true };
      await persistResult(tabId, provisional, { storeImages: false });
      await setBadge(tabId, badgeForResult(provisional));
    } catch {
      // A failed quick pass is not fatal — phase 2 may still succeed through
      // the hosted fallback, and it owns the unavailable state.
    }

    // Phase 2 — page fetch, screenshot comparison and the local LLM verdict.
    // Only this phase alerts, notifies or shows a banner, so a provisional
    // score can never fire a webhook or a warning the final verdict would not.
    const result = await analyzeWithFallback(url, settings);
    if (!current()) return;
    const finalResult = await finalizeScan(tabId, url, result, settings);
    // Delay the screenshot slightly so the page has visually settled.
    await runVisualIfEnabled(tabId, url, finalResult, settings, 1200);
  } catch {
    if (current()) await setBadge(tabId, badgeForUnavailable());
  } finally {
    if (scansInFlight.get(tabId) === url) scansInFlight.delete(tabId);
  }
}

/**
 * "Rescan" for a tab.
 *
 * On a mailbox this asks the content script to re-read the open message (the
 * background deliberately does not scan the mail UI as a website) and waits for
 * that new verdict, so the button is not a no-op on Gmail. Everywhere else it
 * is the ordinary forced URL scan.
 */
async function rescanTab(tabId: number, url: string): Promise<AnalysisResult | null> {
  if (!isMailProviderUrl(url)) {
    await scanTab(tabId, url, true);
    const entry = tabCache.get(tabId);
    return entry ? entry.result : null;
  }

  const MESSAGE_WAIT_MS = 20 * 1000;
  const POLL_MS = 250;
  const requestedAt = Date.now();
  // Inject first when the tab predates the add-on: without this the REPARSE
  // message had no receiver and the button silently did nothing on Gmail.
  await ensureContentScript(tabId);
  try {
    const reply = await tabsApi.sendMessage<{ type: string }, { ok?: boolean }>(tabId, {
      type: "REPARSE_EMAIL",
    });
    // `ok: false` means no message is open (inbox list, search results): there
    // is no verdict coming, so answer with whatever is cached instead of
    // leaving the popup spinning for twenty seconds.
    if (reply && reply.ok === false) {
      const entry = tabCache.get(tabId);
      return entry ? entry.result : null;
    }
  } catch {
    // No content script in that tab (e.g. it is not a mailbox page any more).
  }

  for (;;) {
    const entry = tabCache.get(tabId);
    if (entry && entry.cachedAt > requestedAt) return entry.result;
    if (Date.now() - requestedAt > MESSAGE_WAIT_MS) break;
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }

  const entry = tabCache.get(tabId);
  return entry ? entry.result : null;
}

/** Visual-only pass for a tab that already has a fresh scan in cache. */
async function attachVisualToCachedTab(tabId: number, url: string | undefined) {
  if (!url) return;
  const cached = tabCache.get(tabId);
  if (!cached || !isCacheFresh(cached, url, CACHE_TTL_MS, Date.now())) return;
  const settings = await getSettings();
  if (!settings.captureScreenshots) return;
  await runVisualIfEnabled(tabId, url, cached.result, settings, 0);
}

tabsApi.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    void scanTab(tabId, tab.url);
    return;
  }
  // Single-page apps swap the URL without ever firing another "complete" —
  // YouTube, X, GitHub and most dashboards do exactly that. Listening only for
  // "complete" left the tab showing the verdict of the page it first loaded,
  // and made "Rescan" the only way to analyse anything after the first view.
  if (changeInfo.url) void scanTab(tabId, changeInfo.url);
});

tabsApi.onActivated.addListener((activeInfo) => {
  void (async () => {
    try {
      const tab = await tabsApi.get(activeInfo.tabId);
      if (tab.url) {
        // A background tab is re-analysed when the user comes back to it: the
        // cache is trusted for five minutes, so a page left open for an hour is
        // refreshed on the next activation instead of showing a stale verdict.
        void scanTab(activeInfo.tabId, tab.url);
        void attachVisualToCachedTab(activeInfo.tabId, tab.url);
      }
    } catch {
      /* ignore */
    }
  })();
});

/**
 * Scan whatever is in front of the user right now.
 *
 * Runs when the browser starts and when the extension is first installed or
 * updated. Without it, every tab that was already open when the add-on loaded
 * had no cached result, and the popup answered “No scan result yet for this
 * tab” until the user pressed Rescan.
 */
async function scanActiveTab(): Promise<void> {
  try {
    const [tab] = await tabsApi.query({ active: true, currentWindow: true });
    if (tab && typeof tab.id === "number" && tab.url) await scanTab(tab.id, tab.url);
  } catch {
    /* best effort: a browser without a focused window is not an error */
  }
}

runtimeApi.onStartup.addListener(() => void scanActiveTab());
runtimeApi.onInstalled.addListener(() => void scanActiveTab());

// Keep the page in front of the user analysed instead of analysing it once and
// trusting that verdict forever. `scanTab` is cache-aware (five-minute TTL), so
// this re-runs the pipeline at most once per TTL and never on every tick.
// Mailboxes are skipped here — their content script re-reads the open message.
const ACTIVE_RESCAN_MS = 5 * 60 * 1000;
setInterval(() => void scanActiveTab(), ACTIVE_RESCAN_MS);

tabsApi.onRemoved.addListener((tabId) => {
  tabCache.delete(tabId);
  emailScanTokens.delete(tabId);
  void storage.remove(`result_${tabId}`);
});

runtimeApi.onMessage.addListener((raw, sender, sendResponse) => {
  const message = parseIncomingMessage(raw);
  if (!message) return false;

  // Content scripts don't know their own tab id; prefer the sender's tab id
  // whenever the message carries the -1 sentinel (or none at all).
  const senderTabId = sender?.tab?.id;

  if (message.type === "GET_RESULT") {
    const entry = tabCache.get(message.tabId);
    sendResponse(entry ? entry.result : null);
    return true;
  }

  if (message.type === "RESCAN") {
    rescanTab(message.tabId, message.url).then((result) => sendResponse(result));
    return true;
  }

  if (message.type === "PROCEED_ANYWAY") {
    getSettings().then(async (settings) => {
      const updated = Array.from(new Set([...settings.allowlist, message.hostname]));
      await setSettings({ allowlist: updated });
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message.type === "PAGE_SUMMARY") {
    const tabId = message.tabId >= 0 ? message.tabId : senderTabId;
    if (typeof tabId !== "number") {
      sendResponse(null);
      return true;
    }
    getSettings().then(async (settings) => {
      try {
        const result = await analyzePageWithFallback(message.url, message.summary, settings);
        const finalResult = await finalizeScan(tabId, message.url, result, settings);
        void runVisualIfEnabled(tabId, message.url, finalResult, settings, 0);
        sendResponse(finalResult);
      } catch {
        await setBadge(tabId, badgeForUnavailable());
        sendResponse(null);
      }
    });
    return true;
  }

  if (message.type === "EMAIL_SUMMARY") {
    const tabId = message.tabId >= 0 ? message.tabId : senderTabId;
    if (typeof tabId !== "number") {
      sendResponse(null);
      return true;
    }
    // A newer report for this tab supersedes every scan already in flight.
    const token = (emailScanTokens.get(tabId) ?? 0) + 1;
    emailScanTokens.set(tabId, token);
    const current = () => emailScanTokens.get(tabId) === token;

    getSettings().then(async (settings) => {
      const provider = (() => {
        try {
          return mailProviderFor(new URL(message.url).hostname);
        } catch {
          return "unknown";
        }
      })();
      try {
        // Quick deterministic pass first: the email layer is sub-second, so the
        // card can appear while the local model is still thinking. Alerts and
        // the final badge belong to the full pass below.
        try {
          const quick = await analyzeEmailWithFallback(message.url, message.email, settings, {
            useLlm: false,
          });
          if (!current()) return;
          const provisional: AnalysisResult = { ...quick, provisional: true };
          await persistResult(tabId, provisional, { storeImages: false });
          await setBadge(tabId, badgeForResult(provisional));
          await showMailVerdict(tabId, provisional, settings, null, provider);
        } catch {
          // A failed quick pass is not fatal; the full pass owns the error state.
        }

        const result = await analyzeEmailWithFallback(message.url, message.email, settings);
        // Superseded while the model was thinking: this verdict belongs to a
        // message that is no longer open, so it must not touch the tab.
        if (!current()) {
          sendResponse(null);
          return;
        }
        // Email results are not screenshotted; the visual pass is only for
        // websites. The verdict is delivered as an in-message card plus the
        // toolbar badge, and the SOC webhook fires from the same funnel.
        const finalResult = await finalizeScan(tabId, message.url, result, settings, {
          mailCard: { provider },
        });
        sendResponse(finalResult);
      } catch {
        if (current()) await setBadge(tabId, badgeForUnavailable());
        sendResponse(null);
      }
    });
    return true;
  }

  if (message.type === "OPEN_DASHBOARD") {
    void tabsApi.create({ url: message.url });
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "CLEAR_VISUAL_EVIDENCE") {
    void (async () => {
      try {
        const cleared = await clearAllVisualEvidence();
        for (const [tabId, entry] of tabCache) {
          const next = stripVisualEvidence(entry.result);
          if (next !== entry.result) tabCache.set(tabId, { ...entry, result: next });
        }
        sendResponse({ cleared });
      } catch {
        sendResponse({ cleared: 0 });
      }
    })();
    return true;
  }

  if (message.type === "LAST_ALERT") {
    void (async () => {
      try {
        const stored = await storage.get<{ lastAlert?: LastAlertRecord }>("lastAlert");
        sendResponse(stored.lastAlert ?? null);
      } catch {
        sendResponse(null);
      }
    })();
    return true;
  }

  if (message.type === "TEST_ALERT") {
    void (async () => {
      const settings = await getSettings();
      const webhook = settings.alertWebhookUrl.trim();
      if (!webhook) {
        sendResponse({
          delivered: false,
          status: null,
          attempts: 0,
          error: "No alert webhook URL is set.",
          at: Date.now(),
        });
        return;
      }
      // Sent even when the alerts toggle is off: this button exists precisely
      // to check a URL before trusting it, and it is the user's own endpoint.
      const delivery = await sendSocAlert(webhook, buildTestAlert());
      await persistAlertDelivery({
        ...delivery,
        url: "https://phishbrain-test.example/login/verify",
        analysis_id: "test-alert",
        threshold: settings.riskThreshold,
        test: true,
      });
      sendResponse(delivery);
    })();
    return true;
  }

  if (message.type === "VISUAL_EVIDENCE_STATS") {
    void (async () => {
      try {
        const settings = await getSettings();
        const stats = await visualEvidenceStats();
        sendResponse({ ...stats, retentionDays: settings.visualRetentionDays });
      } catch {
        sendResponse({ screenshots: 0, learned: 0, retentionDays: 0 });
      }
    })();
    return true;
  }

  return false;
});

runtimeApi.onStartup.addListener(() => void applyVisualRetention(true));
runtimeApi.onInstalled.addListener(() => void applyVisualRetention(true));

void (async () => {
  const settings = await getSettings();
  const patch: Partial<Settings> = {};
  // Hosted-first users (no local FastAPI) should see “View details” land on
  // the same hosted dashboard that serves their scans, not 127.0.0.1.
  if (settings.dashboardUrl === DEFAULT_SETTINGS.dashboardUrl && settings.cloudScanUrl) {
    try {
      const u = new URL(settings.cloudScanUrl);
      if (u.protocol === "https:" && u.hostname !== "127.0.0.1" && u.hostname !== "localhost") {
        patch.dashboardUrl = u.origin;
      }
    } catch {
      /* keep default */
    }
  }
  if (Object.keys(patch).length) await setSettings(patch);
  await setSettings(settings); // ensure defaults are persisted on install
})();
