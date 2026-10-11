/**
 * Retention policy for stored screenshot evidence.
 *
 * The popup keeps a downscaled screenshot of the page with each result so the
 * verdict is explainable — but a picture of a page a user visited is the most
 * sensitive thing the extension holds, so it gets its own, shorter clock than
 * the result itself:
 *
 *   - an aged sweep strips the image from results older than
 *     `visualRetentionDays` (keeping the verdict, score and indicators),
 *   - "clear all visual evidence" strips every stored image immediately.
 *
 * The stripping functions are pure over a result, so they are tested directly;
 * the storage walks below are thin wrappers around them.
 */

import { storage } from "../lib/browser";
import type { AnalysisResult, LayerResult, LayersBreakdown } from "../types/analysis";
import type { CacheEntry } from "./logic";

/** Key under which per-tab results are stored (`result_<tabId>`). */
const RESULT_KEY_RE = /^result_(\d+)$/;
/** Learned brand fingerprints — derived from pages the user has visited. */
export const LEARNED_REFS_KEY = "visualLearnedRefs";
const SCREENSHOT_KEY = "screenshot_data_url";

export const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Whether a result's picture should be written to storage at all.
 *
 * A retention window of 0 means "store none": the image must not be persisted
 * even briefly, so the caller strips it at write time rather than waiting up to
 * an hour for the next sweep. Kept as a named, tested rule because the
 * difference between "purged later" and "never stored" is a privacy promise.
 */
export function shouldStoreImages(retentionDays: number): boolean {
  return retentionDays > 0;
}

/**
 * Remove every stored image from a result. Returns the *same* object when
 * there was nothing to strip (so callers can cheaply detect a no-op) and a new
 * object otherwise.
 *
 * Both places an image can live are handled: `visual.*` (the extension's own
 * capture) and `layers[].evidence.screenshot_data_url` (what the backend
 * attaches to the webpage layer, which the normaliser copies into evidence).
 */
export function stripVisualEvidence(result: AnalysisResult): AnalysisResult {
  let changed = false;

  let visual = result.visual ?? null;
  if (visual && (visual.screenshot_thumbnail || visual.reference_thumbnail)) {
    visual = { ...visual, screenshot_thumbnail: null, reference_thumbnail: null };
    changed = true;
  }

  let layers = result.layers;
  const layersRecord = (layers ?? {}) as unknown as Record<string, LayerResult | undefined>;
  const cleaned: Record<string, LayerResult> = {};
  for (const [key, layer] of Object.entries(layersRecord)) {
    if (!layer) continue;
    const evidence = layer.evidence;
    if (evidence && SCREENSHOT_KEY in evidence) {
      const { [SCREENSHOT_KEY]: _dropped, ...rest } = evidence;
      cleaned[key] = { ...layer, evidence: rest };
      changed = true;
    } else {
      cleaned[key] = layer;
    }
  }
  if (changed) {
    layers = cleaned as unknown as LayersBreakdown;
  }

  if (!changed) return result;
  return { ...result, visual, layers };
}

function isImage(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("data:image/");
}

/** True when this result still holds any stored image. */
export function hasStoredVisualEvidence(result: AnalysisResult): boolean {
  if (isImage(result.visual?.screenshot_thumbnail) || isImage(result.visual?.reference_thumbnail)) {
    return true;
  }
  const layers = (result.layers ?? {}) as unknown as Record<string, LayerResult | undefined>;
  return Object.values(layers).some((layer) => isImage(layer?.evidence?.[SCREENSHOT_KEY]));
}

/** Strip the images from cached results older than the retention window. */
export async function sweepStoredVisualEvidence(
  retentionDays: number,
  now: number = Date.now(),
): Promise<number> {
  const windowMs = Math.max(0, retentionDays) * DAY_MS;
  const all = await storage.get<Record<string, unknown>>(null);
  const updates: Record<string, unknown> = {};
  let stripped = 0;
  for (const [key, value] of Object.entries(all)) {
    if (!RESULT_KEY_RE.test(key)) continue;
    const entry = value as CacheEntry | undefined;
    if (!entry?.result) continue;
    if (now - (entry.cachedAt ?? 0) <= windowMs) continue;
    const next = stripVisualEvidence(entry.result);
    if (next === entry.result) continue;
    updates[key] = { ...entry, result: next };
    stripped += 1;
  }
  if (Object.keys(updates).length) await storage.set(updates);
  return stripped;
}

/**
 * Strip every stored image now, regardless of age, and forget the learned
 * brand fingerprints (they are visual references derived from browsing too).
 * Returns the number of results whose stored image was removed.
 */
export async function clearAllVisualEvidence(): Promise<number> {
  const all = await storage.get<Record<string, unknown>>(null);
  const updates: Record<string, unknown> = {};
  let cleared = 0;
  for (const [key, value] of Object.entries(all)) {
    if (!RESULT_KEY_RE.test(key)) continue;
    const entry = value as CacheEntry | undefined;
    if (!entry?.result) continue;
    const next = stripVisualEvidence(entry.result);
    if (next === entry.result) continue;
    updates[key] = { ...entry, result: next };
    cleared += 1;
  }
  if (Object.keys(updates).length) await storage.set(updates);
  await storage.remove(LEARNED_REFS_KEY);
  return cleared;
}

/** How much visual evidence is currently stored (for the options page). */
export async function visualEvidenceStats(): Promise<{ screenshots: number; learned: number }> {
  const all = await storage.get<Record<string, unknown>>(null);
  let screenshots = 0;
  for (const [key, value] of Object.entries(all)) {
    if (!RESULT_KEY_RE.test(key)) continue;
    const entry = value as CacheEntry | undefined;
    if (entry?.result && hasStoredVisualEvidence(entry.result)) screenshots += 1;
  }
  const learned = all[LEARNED_REFS_KEY];
  return {
    screenshots,
    learned: learned && typeof learned === "object" ? Object.keys(learned as object).length : 0,
  };
}
