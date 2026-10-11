/**
 * Opt-in screenshot / visual brand-clone analysis that runs ENTIRELY inside
 * the extension — no Playwright, no Docker, no serverless browser needed.
 *
 * Flow (Chrome and Firefox, MV3):
 *   1. After a page scan on the ACTIVE tab, capture the visible tab as PNG
 *      (tabs.captureVisibleTab — requires host permissions for http/https).
 *   2. Compute a 64-bit perceptual hash of the screenshot (pHash, same format
 *      as data/reference_hashes.json).
 *   3. Compare against per-brand reference hashes (bundled seed file +
 *      fingerprints the user's own browser learned while visiting the real
 *      brand login pages — same engine, so the comparison is reliable).
 *   4. When the page is NOT the genuine brand domain but its layout hash is
 *      close, add a "visual clone" indicator to the webpage layer and
 *      re-score the result so banners/alerts behave consistently.
 *
 * Cross-engine caveat: the seeded hashes are captured with Chromium. If the
 * user browses with Firefox the first few comparisons are noisier; visiting
 * the real brand login once (e.g. logging in normally) re-seeds the reference
 * from the user's own engine.
 */

import { storage, tabsApi, runtimeApi, scriptingApi } from "../lib/browser";
import { hammingDistanceHex, phashFromDataUrl, phashFromUrl, thumbnailFromDataUrl } from "./phash";
import { getBrandIconRefs, isOfficialHost } from "./brand-refs";
import type { AnalysisResult, RiskLevel } from "../types/analysis";

export type VisualRefs = Record<string, string>; // brand -> 16-char hex pHash
export type VisualThumbs = Record<string, string>; // brand -> downscaled data URL

/** Official login destinations used to (a) learn references and (b) never
 * flag the genuine brand page as a clone of itself. */
export const BRAND_LOGIN_PAGES: { brand: string; host: string; pathIncludes?: string }[] = [
  { brand: "paypal", host: "paypal.com", pathIncludes: "/signin" },
  { brand: "microsoft", host: "login.microsoftonline.com" },
  { brand: "google", host: "accounts.google.com", pathIncludes: "/signin" },
  { brand: "apple", host: "appleid.apple.com", pathIncludes: "/sign-in" },
  { brand: "amazon", host: "amazon.com", pathIncludes: "ap/signin" },
  { brand: "netflix", host: "netflix.com", pathIncludes: "/login" },
  { brand: "facebook", host: "facebook.com", pathIncludes: "/login" },
  { brand: "instagram", host: "instagram.com", pathIncludes: "accounts/login" },
  { brand: "linkedin", host: "linkedin.com", pathIncludes: "/login" },
  { brand: "dropbox", host: "dropbox.com", pathIncludes: "/login" },
];

const LEARNED_REFS_KEY = "visualLearnedRefs";

export function officialBrandFor(url: string): { brand: string; official: boolean } | null {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    for (const entry of BRAND_LOGIN_PAGES) {
      const hostMatches = host === entry.host || host.endsWith(`.${entry.host}`);
      if (!hostMatches) continue;
      // Brand landing pages that are not the login screen are not references
      // (a clone imitates the login card, not the marketing homepage).
      if (entry.pathIncludes && !path.includes(entry.pathIncludes)) return null;
      return { brand: entry.brand, official: true };
    }
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * The bundled layout-reference bundle. Two schemas exist and both are read:
 *   - legacy flat `{ "brand": "16hex" }` (what this extension's own
 *     scripts/data/generate_reference_hashes.ts writes),
 *   - the backend's structured `{ version, favicons, references }` file, whose
 *     `references` map is a list of `{ url, phash }` captures per brand.
 *
 * Note the backend's hashes come from Python's `imagehash` and are NOT
 * bit-comparable with this engine's, so a structured file only ever
 * contributes layout references on a best-effort basis; brand ICON matching
 * happens in ./brand-refs.ts, which hashes everything with this engine.
 */
export function normalizeRefMap(raw: unknown): VisualRefs {
  if (!raw || typeof raw !== "object") return {};
  const out: VisualRefs = {};
  const record = raw as Record<string, unknown>;

  const take = (value: unknown): string | null => {
    if (typeof value === "string" && /^[0-9a-f]{16}$/i.test(value)) return value.toLowerCase();
    if (Array.isArray(value)) {
      for (const entry of value) {
        const hash = (entry as { phash?: unknown })?.phash;
        if (typeof hash === "string" && /^[0-9a-f]{16}$/i.test(hash)) return hash.toLowerCase();
      }
    }
    return null;
  };

  const structured = record.references;
  const source =
    structured && typeof structured === "object" ? (structured as Record<string, unknown>) : record;
  for (const [brand, value] of Object.entries(source)) {
    if (!/^[a-z0-9][a-z0-9._-]*$/i.test(brand)) continue; // skip metadata keys
    const hash = take(value);
    if (hash) out[brand] = hash;
  }
  return out;
}

async function loadBundledRefs(): Promise<VisualRefs> {
  try {
    const res = await fetch(runtimeApi.getURL("reference_hashes.json"));
    if (!res.ok) return {};
    return normalizeRefMap(await res.json());
  } catch {
    return {};
  }
}

/**
 * Reference preview images, { brand: "data:image/png;base64,..." }.
 *
 * Optional: written by scripts/data/generate_reference_hashes.ts when it
 * captures the brand login pages. When present, the popup can show the captured
 * screenshot next to the brand it was compared against, turning a bare hash
 * distance into a visible side-by-side. Absent -> only the captured image shows.
 */
async function loadBundledThumbs(): Promise<VisualThumbs> {
  try {
    const res = await fetch(runtimeApi.getURL("reference_thumbnails.json"));
    if (!res.ok) return {};
    const raw = (await res.json()) as unknown;
    if (!raw || typeof raw !== "object") return {};
    const out: VisualThumbs = {};
    for (const [brand, value] of Object.entries(raw as Record<string, unknown>)) {
      if (typeof value === "string" && value.startsWith("data:image/")) out[brand] = value;
    }
    return out;
  } catch {
    return {};
  }
}

/** The URL of the icon the scanned page actually displays, when obtainable. */
async function pageIconUrl(tabId: number, pageUrl: string): Promise<string | null> {
  try {
    const results = await scriptingApi.executeScript<string | null>({
      target: { tabId },
      func: () => {
        const wanted =
          /(^|\s)(icon|shortcut icon|apple-touch-icon|apple-touch-icon-precomposed)(\s|$)/i;
        for (const link of Array.from(document.querySelectorAll("link[rel]"))) {
          if (!wanted.test(link.getAttribute("rel") ?? "")) continue;
          const href = (link as HTMLLinkElement).href;
          if (href) return href;
        }
        return null;
      },
    });
    const href = results?.[0]?.result ?? null;
    if (href) return href;
  } catch {
    // No scripting access (browser-internal page, or Firefox without the
    // grant): fall through to the conventional location.
  }
  try {
    return new URL("/favicon.ico", pageUrl).toString();
  } catch {
    return null;
  }
}

async function loadLearnedRefs(): Promise<VisualRefs> {
  try {
    const stored = await storage.get<{ [LEARNED_REFS_KEY]?: VisualRefs }>(LEARNED_REFS_KEY);
    return stored[LEARNED_REFS_KEY] ?? {};
  } catch {
    return {};
  }
}

async function loadRefs(): Promise<VisualRefs> {
  const [bundled, learned] = await Promise.all([loadBundledRefs(), loadLearnedRefs()]);
  return { ...bundled, ...learned };
}

export async function persistLearnedRef(brand: string, phash: string): Promise<void> {
  try {
    const learned = await loadLearnedRefs();
    learned[brand] = phash;
    await storage.set({ [LEARNED_REFS_KEY]: learned });
  } catch {
    /* best-effort */
  }
}

export type VisualSignal = "favicon" | "layout" | "none";

export interface VisualOutcome {
  status: "ok" | "unavailable";
  reason?: string;
  visual_similarity_score: number | null;
  possible_brand: string | null;
  visual_indicators: string[];
  hash_distance: number | null;
  phash: string | null;
  /** Which comparison produced `possible_brand`. */
  visual_signal?: VisualSignal;
  /** Brand-icon comparison result (the stable signal). */
  favicon_status?: "ok" | "unavailable";
  favicon_brand?: string | null;
  favicon_distance?: number | null;
  /**
   * Downscaled JPEG data URL of the exact screenshot this verdict is based on,
   * so the report can SHOW the evidence rather than only score it. Null when
   * thumbnail generation is unsupported or screenshots are disabled.
   */
  screenshot_thumbnail?: string | null;
  /** Bundled preview of the brand this page was compared against, if any. */
  reference_thumbnail?: string | null;
}

/** How close a captured layout must be before we call it a probable clone. */
const MATCH_THRESHOLD = 12;
const STRONG_THRESHOLD = 6;
/** Brand icons are small and stable; identical files hash to distance 0. */
const ICON_MATCH_THRESHOLD = 10;
const ICON_STRONG_THRESHOLD = 2;

/** Closest reference to `phash`, or null when `refs` holds nothing usable. */
function bestMatch(phash: string, refs: VisualRefs): { brand: string; distance: number } | null {
  let best: { brand: string; distance: number } | null = null;
  for (const [brand, refHash] of Object.entries(refs ?? {})) {
    if (!/^[0-9a-f]{16}$/i.test(refHash)) continue;
    const distance = hammingDistanceHex(phash, refHash.toLowerCase());
    if (!best || distance < best.distance) best = { brand, distance };
  }
  return best;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export interface CompareOptions {
  /** pHash of the page's own icon, computed by this engine. */
  iconPhash?: string | null;
  /** Brand icon hashes, computed by this engine (see ./brand-refs). */
  iconRefs?: VisualRefs;
}

export function comparePhash(
  phash: string,
  refs: VisualRefs,
  scannedUrl: string,
  options: CompareOptions = {},
): VisualOutcome {
  const { iconPhash = null, iconRefs = {} } = options;

  const layoutMatch = bestMatch(phash, refs);
  const iconMatch = iconPhash ? bestMatch(iconPhash, iconRefs) : null;

  const host = hostOf(scannedUrl);
  const genuineLogin = officialBrandFor(scannedUrl);

  // ---- Brand icon (stable signal) -------------------------------------
  let iconClone = false;
  let iconIndicator: string | null = null;
  let faviconStatus: "ok" | "unavailable" = "unavailable";
  let iconBrand: string | null = null;
  let iconDistance: number | null = null;

  if (iconPhash && iconMatch) {
    faviconStatus = "ok";
    iconBrand = iconMatch.brand;
    iconDistance = iconMatch.distance;
    const official =
      isOfficialHost(iconMatch.brand, host) || genuineLogin?.brand === iconMatch.brand;
    if (iconMatch.distance <= ICON_MATCH_THRESHOLD && !official) {
      iconClone = true;
      iconIndicator = `Page icon is the genuine "${iconMatch.brand}" brand mark (icon pHash distance ${iconMatch.distance} of 64) while the page is served from ${host || "an unrelated domain"} — brand icon copied onto a non-brand site.`;
    } else if (iconMatch.distance <= ICON_MATCH_THRESHOLD && official) {
      iconIndicator = `Page icon matches ${iconMatch.brand}'s own brand mark and the domain belongs to ${iconMatch.brand} — expected, not a clone.`;
    } else {
      iconIndicator = `Page icon does not match any tracked brand mark (closest: ${iconMatch.brand}, distance ${iconMatch.distance}).`;
    }
  } else if (iconPhash) {
    iconIndicator =
      "Page icon was captured but no brand icon reference is available to compare against yet.";
  } else {
    iconIndicator = "Page icon could not be retrieved for brand-icon comparison.";
  }

  // ---- Layout (secondary signal) --------------------------------------
  const layoutSimilar = layoutMatch !== null && layoutMatch.distance <= MATCH_THRESHOLD;
  const onGenuineLayout = layoutMatch !== null && genuineLogin?.brand === layoutMatch.brand;
  let layoutClone = false;
  let layoutIndicator: string | null = null;
  if (layoutMatch) {
    if (layoutSimilar && onGenuineLayout) {
      layoutIndicator = `Screenshot layout matches the genuine ${layoutMatch.brand} sign-in page (distance ${layoutMatch.distance}); this IS the official domain — no clone indicator added.`;
    } else if (layoutSimilar) {
      layoutClone = true;
      layoutIndicator = `Screenshot layout resembles the genuine "${layoutMatch.brand}" sign-in page (distance ${layoutMatch.distance} of 64) while the page is NOT served from ${layoutMatch.brand}'s official domain — possible visual clone.`;
    } else {
      layoutIndicator = `Screenshot does not match any known brand login layout (closest: ${layoutMatch.brand}, distance ${layoutMatch.distance}).`;
    }
  }

  if (!layoutMatch && !iconMatch) {
    return {
      status: "unavailable",
      reason: "no reference hashes bundled or learned yet",
      visual_similarity_score: null,
      possible_brand: null,
      visual_indicators: [
        "Screenshot taken, but no reference fingerprints are available to compare against. Visit a genuine brand login page once (with screenshot analysis on) to teach the detector.",
      ],
      hash_distance: null,
      phash,
      visual_signal: "none",
      favicon_status: faviconStatus,
      favicon_brand: iconBrand,
      favicon_distance: iconDistance,
    };
  }

  const clone = iconClone || layoutClone;
  const signal: VisualSignal = iconClone ? "favicon" : layoutClone ? "layout" : "none";
  const brand = iconClone ? iconBrand : layoutClone ? (layoutMatch?.brand ?? null) : null;
  const distance = iconClone ? iconDistance : (layoutMatch?.distance ?? null);

  // The decisive line first — the popup and the banner render `[0]`.
  const cloneIndicator = iconClone ? iconIndicator : layoutClone ? layoutIndicator : null;
  const indicators = [cloneIndicator, iconIndicator, layoutIndicator].filter(
    (i, idx, all): i is string => typeof i === "string" && all.indexOf(i) === idx,
  );

  return {
    status: "ok",
    visual_similarity_score: clone && distance !== null ? Math.max(0, 1 - distance / 20) : null,
    possible_brand: brand,
    visual_indicators: indicators,
    hash_distance: clone ? distance : (layoutMatch?.distance ?? null),
    phash,
    visual_signal: signal,
    favicon_status: faviconStatus,
    favicon_brand: iconBrand,
    favicon_distance: iconDistance,
  };
}

export interface VisualScanResult {
  outcome: VisualOutcome;
  /** Set when the captured page was a genuine brand login: learner should store it. */
  learnBrand?: string;
}

/**
 * Captures the visible tab (must be the ACTIVE tab; captureVisibleTab only
 * sees the active tab) and runs the brand-clone comparison.
 */
export async function runVisualScan(
  tabId: number,
  url: string,
  wireframe = false,
): Promise<VisualScanResult | null> {
  try {
    // captureVisibleTab only ever captures the ACTIVE tab of a window, so if
    // this tab is in the background skip silently — it will be re-scanned the
    // moment it becomes active (tabs.onActivated handler).
    const tab = await tabsApi.get(tabId);
    if (!tab.active || typeof tab.windowId !== "number") return null;
    const dataUrl = await tabsApi.captureVisibleTab(tab.windowId, { format: "png" });
    const phash = await phashFromDataUrl(dataUrl);
    if (!phash) {
      return {
        outcome: {
          status: "unavailable",
          reason: "screenshot decode failed",
          visual_similarity_score: null,
          possible_brand: null,
          visual_indicators: ["Screenshot could not be decoded for visual analysis."],
          hash_distance: null,
          phash: null,
        },
      };
    }
    const [refs, iconRefs, thumbs] = await Promise.all([
      loadRefs(),
      getBrandIconRefs().catch(() => ({}) as VisualRefs),
      loadBundledThumbs(),
    ]);
    const iconUrl = await pageIconUrl(tabId, url);
    const [iconPhash, thumbnail] = await Promise.all([
      iconUrl ? phashFromUrl(iconUrl) : Promise.resolve(null),
      thumbnailFromDataUrl(dataUrl, 360, 0.6, wireframe),
    ]);
    const outcome = comparePhash(phash, refs, url, { iconPhash, iconRefs });
    outcome.screenshot_thumbnail = thumbnail;
    if (outcome.possible_brand && thumbs[outcome.possible_brand]) {
      outcome.reference_thumbnail = thumbs[outcome.possible_brand];
    }
    const official = officialBrandFor(url);
    const onGenuineLogin = official?.brand !== undefined && outcome.status === "ok";
    return { outcome, learnBrand: onGenuineLogin ? official.brand : undefined };
  } catch {
    return null;
  }
}

/** Risk contribution of a visual clone match (mirrors the live-only page
 * signals in live-analyze.server.ts).
 *
 * A copied brand ICON is a much stronger statement than a similar-looking
 * layout (icons are byte-identical when cloned, layouts are not), so it
 * carries the larger weight. The two signals are combined with `max`, never
 * summed, so one clone is never counted twice. */
export function visualRiskContribution(outcome: VisualOutcome): number {
  if (outcome.status !== "ok" || !outcome.possible_brand) return 0;
  const distance = outcome.hash_distance ?? MATCH_THRESHOLD;
  if (outcome.visual_signal === "favicon") {
    return distance <= ICON_STRONG_THRESHOLD ? 30 : 22;
  }
  return distance <= STRONG_THRESHOLD ? 26 : 18;
}

type AnyLayer = {
  risk: number;
  indicators: string[];
  evidence: Record<string, unknown>;
  status?: "ok" | "unavailable" | "not_applicable";
};
type AnyLayers = Record<string, AnyLayer>;

/** SAFE/SUSPICIOUS split used by every hosted result (mirrors riskFromScore). */
export function riskLevelFromScore(score: number): RiskLevel {
  if (score <= 30) return "SAFE";
  if (score <= 70) return "SUSPICIOUS";
  return "HIGH_RISK";
}

const RECOMMENDED: Record<RiskLevel, string> = {
  SAFE: "No action required. Continue to apply normal caution before entering credentials.",
  SUSPICIOUS:
    "Review the evidence below before continuing. Do not submit credentials unless you can independently verify the domain.",
  HIGH_RISK:
    "Do not enter credentials or financial information on this page. Close the tab and reach the service through a known-good bookmark.",
};

/**
 * Attach the visual outcome to a result. When a probable clone match is found
 * the webpage layer gains an indicator + risk and the overall score / risk
 * level / recommendation are recomputed the same way the deterministic engine
 * does (equal layer weights over the "ok" layers), so banners and alerts stay
 * consistent with the added evidence.
 */
export function applyVisualToResult(
  result: AnalysisResult,
  outcome: VisualOutcome,
): AnalysisResult {
  const next: AnalysisResult = {
    ...result,
    visual: {
      status: outcome.status,
      visual_similarity_score: outcome.visual_similarity_score,
      possible_brand: outcome.possible_brand,
      visual_indicators: outcome.visual_indicators,
      hash_distance: outcome.hash_distance,
      phash: outcome.phash,
      visual_signal: outcome.visual_signal ?? "none",
      favicon_status: outcome.favicon_status ?? "unavailable",
      favicon_brand: outcome.favicon_brand ?? null,
      favicon_distance: outcome.favicon_distance ?? null,
      screenshot_thumbnail: outcome.screenshot_thumbnail ?? null,
      reference_thumbnail: outcome.reference_thumbnail ?? null,
    },
  };

  const layers = next.layers as unknown as AnyLayers;
  const webpage = layers.webpage;
  if (!webpage) return next;

  const contribution = visualRiskContribution(outcome);
  if (contribution === 0) {
    // No clone indicator — but surface honest visual status if we have one.
    if (outcome.visual_indicators.length && outcome.status === "ok") {
      webpage.indicators = [
        ...webpage.indicators.filter(
          (i) =>
            !i.startsWith("Visual") && !i.startsWith("Screenshot") && !i.startsWith("Page icon"),
        ),
        ...outcome.visual_indicators,
      ];
    }
    return next;
  }

  const indicator =
    outcome.visual_indicators.find((i) => i.includes("visual clone") || i.includes("brand mark")) ??
    outcome.visual_indicators[0] ??
    `Screenshot visually resembles the genuine "${outcome.possible_brand}" login page.`;
  webpage.risk = Math.min(100, webpage.risk + contribution);
  webpage.indicators = [
    ...webpage.indicators.filter(
      (i) =>
        !i.startsWith("Visual") &&
        !i.startsWith("Screenshot") &&
        !i.startsWith("Page icon") &&
        !i.includes("No credential"),
    ),
    indicator,
  ];
  webpage.evidence = {
    ...webpage.evidence,
    visual_similarity_score: outcome.visual_similarity_score,
    possible_brand: outcome.possible_brand,
    hash_distance: outcome.hash_distance,
    visual_signal: outcome.visual_signal ?? "none",
    favicon_brand: outcome.favicon_brand ?? null,
    favicon_distance: outcome.favicon_distance ?? null,
  };

  // Recompute the deterministic weighted score over active layers.
  const active = Object.values(layers).filter(
    (l) => l && l.risk !== undefined && l.status !== "not_applicable" && l.status !== "unavailable",
  );
  const score = active.length
    ? Math.round(active.reduce((s, l) => s + l.risk, 0) / active.length)
    : next.threat_score;
  const risk = riskLevelFromScore(score);

  next.threat_score = score;
  next.risk_level = risk;
  next.recommended_action = RECOMMENDED[risk];
  next.indicators = Array.from(
    new Set([indicator, ...(next.indicators ?? []).filter((i) => i !== indicator)]),
  ).slice(0, 12);
  if (!next.explanation?.includes("Visual")) {
    next.explanation = `${next.explanation ?? ""}\n- ${indicator}`;
  }
  return next;
}
