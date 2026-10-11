import { storage, tabsApi, runtimeApi, actionApi, notificationsApi } from "../lib/browser";
import {
  analyzeUrl,
  analyzePage,
  analyzeEmail,
  analyzeUrlCloud,
  analyzeEmailCloud,
  ApiError,
} from "../services/api";
import type { Settings } from "../lib/settings";
import { getSettings, setSettings, DEFAULT_SETTINGS } from "../lib/settings";
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

async function maybeAlert(result: AnalysisResult, settings: Settings): Promise<void> {
  if (!settings.alertsEnabled || !settings.alertWebhookUrl) return;
  if ((result.threat_score ?? 0) < settings.riskThreshold) return;
  try {
    await fetch(settings.alertWebhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source: "phishbrain-extension",
        detected_at: new Date().toISOString(),
        analysis_id: result.analysis_id,
        url: result.url,
        domain: result.domain,
        threat_score: result.threat_score,
        risk_level: result.risk_level,
        indicators: result.indicators?.slice(0, 12) ?? [],
        recommended_action: result.recommended_action,
      }),
    });
  } catch {
    // Alerting is best-effort and must never break scanning.
  }
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
      dashboardUrl: settings.dashboardUrl,
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
): Promise<void> {
  if (settings.bannerMode === "silent") return;
  if (result.risk_level !== "HIGH_RISK") return;
  const key = `${tabId}:${result.url}`;
  if (notifiedKeys.has(key)) return;
  notifiedKeys.add(key);
  const host = result.domain || result.url || "this page";
  const lead = result.indicators?.[0] ?? "Multiple phishing indicators were detected.";
  try {
    await notificationsApi.create({
      type: "basic",
      iconUrl: runtimeApi.getURL("icons/icon128.png"),
      title: `PhishBrain: high-risk page (${Math.round(result.threat_score)}/100)`,
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
 * Single funnel for every completed scan: persist the cache, update the
 * toolbar badge, fire the opt-in webhook and show the warning banner.
 */
async function finalizeScan(
  tabId: number,
  url: string,
  result: AnalysisResult,
  settings: Settings,
): Promise<AnalysisResult> {
  const normalized = normalizeResult(result);
  await persistResult(tabId, normalized, {
    storeImages: shouldStoreImages(settings.visualRetentionDays),
  });
  await setBadge(tabId, badgeForResult(normalized));
  void maybeAlert(normalized, settings);
  void notifyHighRisk(tabId, normalized, settings);
  await showBanner(tabId, normalized, settings);
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
      void maybeAlert(merged, settings);
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

async function analyzeWithFallback(url: string, settings: Settings): Promise<AnalysisResult> {
  try {
    return await analyzeUrl({ url }, settings.backendUrl);
  } catch (err) {
    if (!settings.useCloudFallback) throw err;
    return await analyzeUrlCloud({ url }, settings.cloudScanUrl);
  }
}

async function analyzePageWithFallback(
  url: string,
  summary: Record<string, unknown>,
  settings: Settings,
): Promise<AnalysisResult> {
  try {
    return await analyzePage({ url, dom_summary: JSON.stringify(summary) }, settings.backendUrl);
  } catch (err) {
    if (!settings.useCloudFallback) throw err;
    // The hosted scan re-fetches the page itself, so a URL scan is the
    // closest fallback; client-side summary evidence is preserved nowhere but
    // the hosted fetch already covers the same webpage signals.
    return await analyzeUrlCloud({ url }, settings.cloudScanUrl);
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
    spf?: string;
    dkim?: string;
    dmarc?: string;
  },
  settings: Settings,
): Promise<AnalysisResult> {
  try {
    return await analyzeEmail(
      {
        sender: email.sender,
        reply_to: email.reply_to,
        display_name: email.display_name,
        subject: email.subject,
        body_text: email.body_text,
        links: email.links,
        spf: email.spf,
        dkim: email.dkim,
        dmarc: email.dmarc,
      },
      settings.backendUrl,
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
      },
      settings.cloudEmailScanUrl,
    );
  }
}

async function scanTab(tabId: number, url: string, force = false) {
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

  try {
    const result = await analyzeWithFallback(url, settings);
    const finalResult = await finalizeScan(tabId, url, result, settings);
    // Delay the screenshot slightly so the page has visually settled.
    await runVisualIfEnabled(tabId, url, finalResult, settings, 1200);
  } catch {
    await setBadge(tabId, badgeForUnavailable());
  }
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
  }
});

tabsApi.onActivated.addListener((activeInfo) => {
  void (async () => {
    try {
      const tab = await tabsApi.get(activeInfo.tabId);
      void attachVisualToCachedTab(activeInfo.tabId, tab.url);
    } catch {
      /* ignore */
    }
  })();
});

tabsApi.onRemoved.addListener((tabId) => {
  tabCache.delete(tabId);
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
    scanTab(message.tabId, message.url, true).then(() => {
      const entry = tabCache.get(message.tabId);
      sendResponse(entry ? entry.result : null);
    });
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
    getSettings().then(async (settings) => {
      try {
        const result = await analyzeEmailWithFallback(message.url, message.email, settings);
        // Email results are not screenshotted; the visual pass is only for
        // websites. Banner + badge still apply (sender impersonation etc.).
        const finalResult = await finalizeScan(tabId, message.url, result, settings);
        sendResponse(finalResult);
      } catch {
        await setBadge(tabId, badgeForUnavailable());
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
