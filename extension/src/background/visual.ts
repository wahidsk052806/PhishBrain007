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

import { storage, tabsApi, runtimeApi } from "../lib/browser";
import { hammingDistanceHex, phashFromDataUrl } from "./phash";
import type { AnalysisResult, RiskLevel } from "../types/analysis";

export type VisualRefs = Record<string, string>; // brand -> 16-char hex pHash

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

async function loadBundledRefs(): Promise<VisualRefs> {
  try {
    const res = await fetch(runtimeApi.getURL("reference_hashes.json"));
    if (!res.ok) return {};
    const json = (await res.json()) as VisualRefs;
    return typeof json === "object" && json !== null ? json : {};
  } catch {
    return {};
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

export interface VisualOutcome {
  status: "ok" | "unavailable";
  reason?: string;
  visual_similarity_score: number | null;
  possible_brand: string | null;
  visual_indicators: string[];
  hash_distance: number | null;
  phash: string | null;
}

/** How close a captured layout must be before we call it a probable clone. */
const MATCH_THRESHOLD = 12;
const STRONG_THRESHOLD = 6;

export function comparePhash(
  phash: string,
  refs: VisualRefs,
  scannedUrl: string,
): VisualOutcome {
  if (!refs || !Object.keys(refs).length) {
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
    };
  }

  let bestBrand: string | null = null;
  let bestDistance = Infinity;
  for (const [brand, refHash] of Object.entries(refs)) {
    if (!/^[0-9a-f]{16}$/i.test(refHash)) continue;
    const d = hammingDistanceHex(phash, refHash.toLowerCase());
    if (d < bestDistance) {
      bestDistance = d;
      bestBrand = brand;
    }
  }

  if (bestBrand === null) {
    return {
      status: "unavailable",
      reason: "no comparable reference hashes",
      visual_similarity_score: null,
      possible_brand: null,
      visual_indicators: [],
      hash_distance: null,
      phash,
    };
  }

  const official = officialBrandFor(scannedUrl);
  const onGenuinePage = official?.brand === bestBrand;
  const visuallySimilar = bestDistance <= MATCH_THRESHOLD;

  const indicators: string[] = [];
  if (visuallySimilar && onGenuinePage) {
    indicators.push(
      `Visual layout matches the genuine ${bestBrand} sign-in page (pHash distance ${bestDistance}); this IS the official domain — no clone indicator added.`,
    );
  } else if (visuallySimilar) {
    indicators.push(
      `Screenshot layout closely resembles the genuine "${bestBrand}" sign-in page (pHash distance ${bestDistance} of 64) while the page is NOT served from ${bestBrand}'s official domain — possible visual clone.`,
    );
  } else {
    indicators.push(`Screenshot does not visually match any known brand login layout (closest: ${bestBrand}, distance ${bestDistance}).`);
  }

  return {
    status: "ok",
    visual_similarity_score: visuallySimilar ? Math.max(0, 1 - bestDistance / 20) : null,
    possible_brand: visuallySimilar && !onGenuinePage ? bestBrand : null,
    visual_indicators: indicators,
    hash_distance: bestDistance,
    phash,
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
    const refs = await loadRefs();
    const outcome = comparePhash(phash, refs, url);
    const official = officialBrandFor(url);
    const onGenuineLogin = official?.brand !== undefined && outcome.status === "ok";
    return { outcome, learnBrand: onGenuineLogin ? official.brand : undefined };
  } catch {
    return null;
  }
}

/** Risk contribution of a visual clone match (mirrors the live-only page
 * signals in live-analyze.server.ts). */
export function visualRiskContribution(outcome: VisualOutcome): number {
  if (outcome.status !== "ok" || !outcome.possible_brand) return 0;
  const distance = outcome.hash_distance ?? MATCH_THRESHOLD;
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
          (i) => !i.startsWith("Visual") && !i.startsWith("Screenshot"),
        ),
        ...outcome.visual_indicators,
      ];
    }
    return next;
  }

  const indicator = outcome.visual_indicators.find((i) => i.includes("visual clone")) ??
    outcome.visual_indicators[0] ??
    `Screenshot visually resembles the genuine "${outcome.possible_brand}" login page.`;
  webpage.risk = Math.min(100, webpage.risk + contribution);
  webpage.indicators = [
    ...webpage.indicators.filter(
      (i) => !i.startsWith("Visual") && !i.startsWith("Screenshot") && !i.includes("No credential"),
    ),
    indicator,
  ];
  webpage.evidence = {
    ...webpage.evidence,
    visual_similarity_score: outcome.visual_similarity_score,
    possible_brand: outcome.possible_brand,
    hash_distance: outcome.hash_distance,
  };

  // Recompute the deterministic weighted score over active layers.
  const active = Object.values(layers).filter((l) => l && l.risk !== undefined && l.status !== "not_applicable" && l.status !== "unavailable");
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
