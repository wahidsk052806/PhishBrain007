import { DEFAULT_CLOUD_EMAIL_URL, DEFAULT_CLOUD_SCAN_URL } from "../services/api";
import type { Settings } from "./settings";

/**
 * Where the hosted live-scan endpoints come from.
 *
 * Two URLs had to be typed in for a hosted setup to work: the dashboard URL
 * (used by "View details") and the live-scan URL. The hosted endpoints are
 * *served by the dashboard itself* (`/api/public/scan` ships inside the
 * dashboard deploy), so they are the same origin. Making the user repeat the
 * origin was a standing source of "the extension says the fallback is
 * unreachable" — and a shipped default pointing at a domain that no longer
 * resolves meant a fresh install on any device without a local backend could
 * not scan at all.
 *
 * Resolution order, most explicit first:
 *   1. A live-scan URL the user typed in Options (anything but the shipped default).
 *   2. The dashboard origin, when it is a real (non-loopback) origin.
 *   3. The shipped default.
 */

export type HostedSource = "configured" | "dashboard" | "default";

export interface ResolvedEndpoint {
  url: string;
  source: HostedSource;
}

const PUBLIC_SCAN_PATH = "/api/public/scan";
const PUBLIC_EMAIL_PATH = "/api/public/email-scan";

/**
 * Hosts this project used to ship as public defaults. Neither is deployed:
 * `phishbrain07.app` has no DNS record and `phishbrain007.lovable.app` answers
 * 404. A stored value pointing at one of them is a leftover from an older
 * build, not somebody's deployment — deriving an endpoint from it produced a
 * red “Backend unavailable … Tried https://www.phishbrain07.app/api/public/scan”
 * panel and an “Open Dashboard” button that led to Firefox's “Server Not Found”.
 */
const PLACEHOLDER_HOSTS = ["phishbrain07.app", "phishbrain007.lovable.app"];

/** True for those dead defaults, including any subdomain of them. */
export function isPlaceholderHostname(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/\.$/, "");
  return PLACEHOLDER_HOSTS.some(
    (placeholder) => host === placeholder || host.endsWith(`.${placeholder}`),
  );
}

/**
 * The dashboard origin, if it is a real deployment: a public http(s) origin that
 * is not one of the undeployed defaults.
 */
export function configuredDashboardOrigin(url: string): string | null {
  const origin = publicOrigin(url);
  if (!origin) return null;
  return isPlaceholderHostname(new URL(origin).hostname) ? null : origin;
}

/** A stored dashboard URL that parses but points at an undeployed default. */
export function isStaleDashboardUrl(url: string): boolean {
  return publicOrigin(url) !== null && configuredDashboardOrigin(url) === null;
}

/**
 * An origin worth opening in a tab: http(s), not one of the undeployed hosts.
 *
 * Unlike `publicOrigin` this keeps loopback and RFC 1918 addresses, because
 * "Open Dashboard" has to work for the documented local setup — the dashboard
 * is served by `npm run dev` on `127.0.0.1:8080`, which is exactly what
 * `configuredDashboardOrigin` rejects.
 */
export function openableOrigin(url: string): string | null {
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (!parsed.hostname) return null;
    if (isPlaceholderHostname(parsed.hostname)) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * Where "Open Dashboard" should go, from the most explicit candidate first.
 *
 * Returns a deployed origin when there is one, and otherwise the local one, so
 * the button opens the dashboard instead of quietly landing on the Options
 * page. `null` means nothing usable is configured, which is the only case where
 * sending the user to Settings is the right answer.
 */
export function dashboardOpenTarget(...candidates: (string | null | undefined)[]): string | null {
  let local: string | null = null;
  for (const candidate of candidates) {
    if (!candidate) continue;
    const deployed = configuredDashboardOrigin(candidate);
    if (deployed) return deployed;
    if (!local) local = openableOrigin(candidate);
  }
  return local;
}

/** True when `url` can only be reached from this computer. */
export function isLocalOrigin(url: string): boolean {
  try {
    return isLoopbackHostname(new URL(url.trim()).hostname);
  } catch {
    return false;
  }
}

/** A hostname that can only ever point back at this machine. */
export function isLoopbackHostname(hostname: string): boolean {
  const host = hostname
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
  return (
    host === "localhost" ||
    host === "::1" ||
    host === "0.0.0.0" ||
    host.startsWith("127.") ||
    host.endsWith(".localhost")
  );
}

/** `https://demo.example.com/path` → `https://demo.example.com`, else null. */
export function publicOrigin(url: string): string | null {
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (!parsed.hostname || isLoopbackHostname(parsed.hostname)) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * Lightweight reachability probe for the hosted fallback. Any 200/204 means the
 * deployment answers; a network error means the domain is unreachable.
 *
 * An empty endpoint is deliberately *not* probed: `fetch("")` resolves against
 * the page that calls it (the popup's own `chrome-extension://` URL) and answers
 * 200, which made a completely unconfigured install report “Hosted fallback”.
 */
export async function probeHosted(
  url: string,
): Promise<{ reachable: boolean; status: number | null }> {
  if (!url.trim()) return { reachable: false, status: null };
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

/**
 * The dashboard page that shows the report for `target`.
 *
 * The dashboard route is `/analysis?url=<target>`: it re-runs the pipeline for
 * that address through whichever engine the visitor's browser can reach, so a
 * click from the popup, the warning banner or the in-message card lands on a
 * real report — screenshot evidence, pre-filter score, model verdict and all —
 * instead of an empty form or the site's home page. Older builds linked
 * `/?analysis_id=…`, an id that only exists in the backend's history, so a
 * result produced through the hosted fallback opened nothing at all.
 *
 * Without a target (an email verdict has no page to re-scan) this is the plain
 * analysis page, where the message can be pasted in.
 */
export function analysisDeepLink(dashboardUrl: string, target: string): string {
  const base = (dashboardUrl || "").trim().replace(/\/+$/, "");
  const page = `${base}/analysis`;
  const trimmed = (target || "").trim();
  if (!trimmed || !/^https?:\/\//i.test(trimmed)) return page;
  return `${page}?url=${encodeURIComponent(trimmed)}`;
}

/** A URL we would actually be willing to POST a scan to. */
export function isUsableEndpoint(url: string): boolean {
  try {
    const parsed = new URL(url.trim());
    return (parsed.protocol === "http:" || parsed.protocol === "https:") && !!parsed.hostname;
  } catch {
    return false;
  }
}

/** A URL that points at one of the undeployed hosts this project used to ship. */
function isPlaceholderUrl(url: string): boolean {
  try {
    return isPlaceholderHostname(new URL(url).hostname);
  } catch {
    return false;
  }
}

function resolveEndpoint(
  settings: Settings,
  configured: string,
  fallbackDefault: string,
  path: string,
): ResolvedEndpoint {
  const trimmed = configured.trim();

  // 1. An explicit choice wins — but only when it is a real, usable URL, the
  //    user has actually changed it, and it does not point at an undeployed
  //    placeholder host. Older builds shipped
  //    `https://www.phishbrain07.app/api/public/scan` as the stored live-scan
  //    URL; honouring that leftover produced a permanent “Backend unavailable …
  //    Tried https://www.phishbrain07.app/api/public/scan” panel on a machine
  //    whose local backend was perfectly healthy.
  if (isUsableEndpoint(trimmed) && trimmed !== fallbackDefault && !isPlaceholderUrl(trimmed)) {
    return { url: trimmed.replace(/\/+$/, ""), source: "configured" };
  }

  // 2. Derive from the dashboard origin: the endpoints ship with the dashboard.
  //    A placeholder origin is skipped on purpose — it would turn a configuration
  //    problem into a network error against a host that cannot answer.
  const origin = configuredDashboardOrigin(settings.dashboardUrl);
  if (origin) {
    return { url: `${origin}${path}`, source: "dashboard" };
  }

  // 3. Shipped default (or the explicit value if the default is useless —
  //    never a placeholder host, which would turn a configuration problem into
  //    a permanent network error against a domain that cannot answer).
  const finalUrl =
    isUsableEndpoint(trimmed) && !isPlaceholderUrl(trimmed) ? trimmed : fallbackDefault;
  return { url: finalUrl.replace(/\/+$/, ""), source: "default" };
}

export function resolveHostedScan(settings: Settings): ResolvedEndpoint {
  return resolveEndpoint(settings, settings.cloudScanUrl, DEFAULT_CLOUD_SCAN_URL, PUBLIC_SCAN_PATH);
}

export function resolveHostedEmail(settings: Settings): ResolvedEndpoint {
  return resolveEndpoint(
    settings,
    settings.cloudEmailScanUrl,
    DEFAULT_CLOUD_EMAIL_URL,
    PUBLIC_EMAIL_PATH,
  );
}

/** One-line explanation for the Options page. */
export function describeSource(source: HostedSource): string {
  switch (source) {
    case "configured":
      return "using the live-scan URL you entered";
    case "dashboard":
      return "derived from your dashboard URL";
    default:
      return "no hosted endpoint is configured — set Dashboard URL to your deployed dashboard";
  }
}
