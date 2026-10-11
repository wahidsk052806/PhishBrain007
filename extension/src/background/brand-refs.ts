/**
 * Brand icon (favicon) references for the extension's visual brand-clone check.
 *
 * Why icons instead of page screenshots: a full-page perceptual hash of a
 * sign-in screen shifts by 20-30 bits whenever the page changes copy, A/B
 * tests its layout or renders a cookie banner, so screenshot-to-screenshot
 * matching is unreliable. A brand icon is a small, stable artefact — and a
 * clone almost always copies it byte for byte, which hashes to distance 0.
 *
 * Why references are fetched at runtime instead of bundled: perceptual hashes
 * are only comparable when both sides are produced by the SAME implementation.
 * This extension hashes images in JavaScript (./phash.ts); the reference file
 * committed for the Python backend is hashed with Python's `imagehash`, and
 * the two engines disagree on identical bytes. So every icon this module
 * compares against is downloaded and hashed here, by this engine, then cached
 * in extension storage. That also means the reference set can never go stale
 * the way a bundled file does.
 *
 * `officialHosts` is used to never flag a brand's own page as a clone of
 * itself (its favicon is legitimately its own).
 */

import { storage } from "../lib/browser";
import { phashFromUrl } from "./phash";

export interface BrandIconSource {
  brand: string;
  /** Icon URL that serves the brand mark (verified to resolve). */
  iconUrl: string;
  /** Hosts that legitimately serve this brand's icon. */
  officialHosts: string[];
}

export const BRAND_ICON_SOURCES: BrandIconSource[] = [
  {
    brand: "adobe",
    iconUrl: "https://www.adobe.com/favicon.ico",
    officialHosts: ["adobe.com", "adobe.io", "adobelogin.com"],
  },
  {
    brand: "amazon",
    iconUrl: "https://www.amazon.com/favicon.ico",
    officialHosts: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.in"],
  },
  {
    brand: "apple",
    iconUrl: "https://www.apple.com/favicon.ico",
    officialHosts: ["apple.com", "icloud.com"],
  },
  {
    brand: "bankofamerica",
    iconUrl:
      "https://www.bankofamerica.com/homepage/spa-assets/images/assets-images-global-favicon-apple-touch-icon-CSX889b28c.png",
    officialHosts: ["bankofamerica.com"],
  },
  {
    brand: "chase",
    iconUrl: "https://www.chase.com/etc/designs/chase-ux/favicon-152.png",
    officialHosts: ["chase.com"],
  },
  {
    brand: "docusign",
    iconUrl: "https://www.docusign.com/assets/images/apple-touch-icon-57x57.png",
    officialHosts: ["docusign.com", "docusign.net"],
  },
  {
    brand: "dropbox",
    iconUrl: "https://cfl.dropboxstatic.com/static/metaserver/static/images/favicon.ico",
    officialHosts: ["dropbox.com", "dropboxstatic.com", "dropboxusercontent.com"],
  },
  {
    brand: "facebook",
    iconUrl: "https://static.xx.fbcdn.net/rsrc.php/y1/r/ay1hV6OlegS.ico",
    officialHosts: ["facebook.com", "fb.com", "fbcdn.net"],
  },
  {
    brand: "google",
    iconUrl: "https://www.gstatic.com/images/branding/searchlogo/ico/favicon.ico",
    officialHosts: [
      "google.com",
      "google.co.uk",
      "google.de",
      "gstatic.com",
      "youtube.com",
      "gmail.com",
    ],
  },
  {
    brand: "instagram",
    iconUrl: "https://static.cdninstagram.com/rsrc.php/yj/r/f01UdNyJjJj.webp",
    officialHosts: ["instagram.com", "cdninstagram.com"],
  },
  {
    brand: "linkedin",
    iconUrl: "https://static.licdn.com/aero-v1/sc/h/al2o9zrvru7aqj8e1x2rzsrca",
    officialHosts: ["linkedin.com", "licdn.com"],
  },
  {
    brand: "microsoft",
    iconUrl: "https://www.microsoft.com/favicon.ico?v2",
    officialHosts: ["microsoft.com", "microsoftonline.com", "live.com", "msn.com", "windows.com"],
  },
  {
    brand: "netflix",
    iconUrl: "https://assets.nflxext.com/us/ffe/siteui/common/icons/nficon2016.png",
    officialHosts: ["netflix.com", "nflxext.com", "nflximg.net"],
  },
  {
    brand: "office365",
    iconUrl:
      "https://res.cdn.office.net/officehub/images/content/images/unauth-copilotcom/favicon-copilot-brand-refresh-23392c1f66.ico",
    officialHosts: ["office.com", "office365.com", "microsoft365.com", "office.net"],
  },
  {
    brand: "outlook",
    iconUrl:
      "https://res.public.onecdn.static.microsoft/assets/mail/pwa/v4/pngs/apple-touch-icon.png",
    officialHosts: ["outlook.com", "live.com", "office.com", "onedcdn.static.microsoft"],
  },
  {
    brand: "paypal",
    iconUrl: "https://www.paypalobjects.com/marketing/web/icons/monogram/pp64.png",
    officialHosts: ["paypal.com", "paypalobjects.com", "paypal.me"],
  },
  {
    brand: "wellsfargo",
    iconUrl: "https://www17.wellsfargomedia.com/assets/images/icons/apple-touch-icon_120x120.png",
    officialHosts: ["wellsfargo.com", "wellsfargomedia.com"],
  },
];

const STORAGE_KEY = "brandIconRefs";
/** Idle refresh window; icons essentially never change, refetching is cheap. */
const REF_TTL_MS = 7 * 24 * 60 * 60 * 1000;

interface IconRefCache {
  /** brand -> 16-char hex pHash of that brand's icon, hashed by this engine. */
  hashes: Record<string, string>;
  /** brand -> epoch ms the hash was captured. */
  capturedAt: Record<string, number>;
}

const EMPTY: IconRefCache = { hashes: {}, capturedAt: {} };

async function loadCache(): Promise<IconRefCache> {
  try {
    const stored = await storage.get<{ [STORAGE_KEY]?: IconRefCache }>(STORAGE_KEY);
    const entry = stored[STORAGE_KEY];
    if (!entry || typeof entry !== "object") return { ...EMPTY };
    return {
      hashes: { ...(entry.hashes ?? {}) },
      capturedAt: { ...(entry.capturedAt ?? {}) },
    };
  } catch {
    return { ...EMPTY };
  }
}

async function refresh(sources: BrandIconSource[], cache: IconRefCache): Promise<IconRefCache> {
  const now = Date.now();
  const next: IconRefCache = { hashes: { ...cache.hashes }, capturedAt: { ...cache.capturedAt } };
  let changed = false;

  await Promise.all(
    sources.map(async (source) => {
      const age = now - (next.capturedAt[source.brand] ?? 0);
      if (next.hashes[source.brand] && age < REF_TTL_MS) return;
      const hash = await phashFromUrl(source.iconUrl);
      if (!hash) return; // offline / blocked: keep any previous hash
      next.hashes[source.brand] = hash;
      next.capturedAt[source.brand] = now;
      changed = true;
    }),
  );

  if (changed) {
    try {
      await storage.set({ [STORAGE_KEY]: next });
    } catch {
      /* caching is best-effort */
    }
  }
  return next;
}

/**
 * Brand icon hashes known to this engine, hashing+refreshing as needed.
 * Resolves to whatever is available — never throws, so visual analysis can
 * degrade gracefully when the machine is offline.
 */
export async function getBrandIconRefs(
  sources: BrandIconSource[] = BRAND_ICON_SOURCES,
): Promise<Record<string, string>> {
  const cache = await loadCache();
  const provided = new Set(sources.map((s) => s.brand));
  const usable = Object.fromEntries(
    Object.entries(cache.hashes).filter(
      ([brand, hash]) => provided.has(brand) && /^[0-9a-f]{16}$/i.test(hash),
    ),
  );
  const stale = sources.some(
    (s) => !cache.hashes[s.brand] || Date.now() - (cache.capturedAt[s.brand] ?? 0) >= REF_TTL_MS,
  );
  if (!stale) return usable;
  const refreshed = await refresh(sources, cache);
  return Object.fromEntries(
    Object.entries(refreshed.hashes).filter(
      ([brand, hash]) => provided.has(brand) && /^[0-9a-f]{16}$/i.test(hash),
    ),
  );
}

/** Host suffixes that legitimately serve each brand (for the non-clone check). */
export function officialHostsFor(brand: string): string[] {
  return BRAND_ICON_SOURCES.find((s) => s.brand === brand)?.officialHosts ?? [];
}

/** True when `host` belongs to the brand (so its own favicon is not a clone). */
export function isOfficialHost(brand: string, host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return officialHostsFor(brand).some((d) => h === d || h.endsWith(`.${d}`));
}
