/**
 * Which engine answers a scan, and at which address.
 *
 * The dashboard runs in three different situations and used to guess between
 * them from the page origin alone:
 *
 *  - **This machine.** Page and API both on loopback: the FastAPI backend is
 *    reachable and must be used, because it is the only engine with the
 *    CatBoost pre-filter, the local LLM verdict and the Playwright screenshot.
 *  - **Another device on the same network.** Page served from e.g.
 *    `http://10.140.125.196:8080` while the configured API is still
 *    `http://localhost:8000`. `localhost` here means *the phone or laptop
 *    looking at the page*, so the browser found nothing and the dashboard fell
 *    back to its own server engine — while a perfectly good backend, with all
 *    three extra layers, was running on the very machine serving the page. The
 *    fix is to also probe the page's own host on the backend port.
 *  - **A public deployment.** No visitor has a backend, so the deployment's
 *    server engine (fetch, DNS-over-HTTPS, RDAP, DOM analysis) is the scan path.
 *
 * Resolution probes candidates in order and stops at the first that answers, so
 * the choice is made from what is actually reachable rather than assumed.
 */

import { isPublicOrigin, isLoopbackUrl, type DashboardSettings } from "./settings";

/** Port assumed when the configured backend URL does not name one. */
const DEFAULT_BACKEND_PORT = "8000";

/**
 * How long a single candidate probe may take.
 *
 * Measured on the real backend: `/api/v1/health` answers in about half a second
 * once warm, but several seconds while the CatBoost model and the Ollama runtime
 * are still warming at startup. A 2.5 s ceiling made the dashboard declare a
 * perfectly healthy backend unreachable in exactly that window, so the budget is
 * generous. It is only spent by a host that accepts the connection and then says
 * nothing — a host with nothing listening refuses immediately.
 */
export const PROBE_TIMEOUT_MS = 6000;

export type ScanEngine = "backend" | "hosted" | "local";

export interface BackendCandidate {
  url: string;
  source: "configured" | "same-host";
}

export interface BackendResolution {
  engine: ScanEngine;
  /** The endpoint that answered, or null when none did. */
  url: string | null;
  tried: { url: string; reachable: boolean }[];
}

/** Strip trailing slashes so `${base}/api/v1/health` never doubles them. */
export function normalizeBase(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

/** The port a backend URL names, or the scheme default. */
export function backendPort(url: string): string {
  try {
    const parsed = new URL(normalizeBase(url));
    if (parsed.port) return parsed.port;
    return parsed.protocol === "https:" ? "443" : DEFAULT_BACKEND_PORT;
  } catch {
    return DEFAULT_BACKEND_PORT;
  }
}

/**
 * True for addresses that only exist inside a private network.
 *
 * Used to decide whether probing "the host serving this page" is worthwhile. On
 * a public deployment that probe would always be wrong (there is no backend on
 * the edge host's port 8000), so it is skipped rather than waited on.
 */
export function isPrivateHostname(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (!h) return false;
  return (
    h === "localhost" ||
    h === "::1" ||
    h === "0.0.0.0" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    /^169\.254\./.test(h)
  );
}

function pageLocation(): { protocol: string; hostname: string } | null {
  if (typeof window === "undefined") return null;
  const { protocol, hostname } = window.location;
  if (!protocol || !hostname) return null;
  return { protocol, hostname };
}

/**
 * Backend addresses worth trying, best guess first.
 *
 * The configured URL always comes first: an operator who pointed the dashboard
 * at a specific API means it. The second candidate is the machine serving this
 * page on the configured backend's port — the address a LAN visitor can
 * actually reach — and only when the configured URL is loopback and this page
 * is being served from a private network host.
 */
export function backendCandidates(
  settings: Pick<DashboardSettings, "backendUrl">,
): BackendCandidate[] {
  const configured = normalizeBase(settings.backendUrl);
  const out: BackendCandidate[] = [{ url: configured, source: "configured" }];

  const page = pageLocation();
  if (page && isLoopbackUrl(configured) && isPrivateHostname(page.hostname) && isPublicOrigin()) {
    const derived = `${page.protocol}//${page.hostname}:${backendPort(configured)}`;
    if (derived !== configured) out.push({ url: derived, source: "same-host" });
  }

  return out.filter((c, i, all) => c.url && all.findIndex((x) => x.url === c.url) === i);
}

/** One health probe. Never throws: a failure is a `false`. */
export async function probeBackend(url: string, timeoutMs = PROBE_TIMEOUT_MS): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${url}/api/v1/health`, {
      method: "GET",
      signal: controller.signal,
      // The API is called cross-origin from a LAN address; ask for the answer
      // explicitly so a CORS refusal is reported instead of a generic failure.
      mode: "cors",
      headers: { accept: "application/json" },
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The address the rest of the dashboard should call.
 *
 * Kept in module state because `api.ts` is a plain object used from event
 * handlers, `useQuery` fetchers and `useEffect`s alike; threading the resolved
 * value through every call site would be all cost and no benefit. It is only
 * ever set from a successful probe, and `api.ts` falls back to the configured
 * URL when nothing has been resolved yet.
 */
let activeBase: string | null = null;
let inFlight: Promise<BackendResolution> | null = null;

export function setActiveBackendBase(url: string | null): void {
  activeBase = url ? normalizeBase(url) : null;
}

export function getActiveBackendBase(fallback: string): string {
  return activeBase ?? normalizeBase(fallback);
}

/**
 * A resolution currently being computed, if any.
 *
 * `api.ts` awaits this before choosing a base so a request issued while the
 * probe is running cannot jump the gun and hit the wrong host — which used to
 * surface as a history list that was empty on a LAN only because it had asked
 * the visitor's own `localhost` first.
 */
export function pendingBackendResolution(): Promise<BackendResolution> | null {
  return inFlight;
}

export function resetBackendResolution(): void {
  activeBase = null;
  inFlight = null;
}

/**
 * Decide which engine serves this browser, and publish the answer.
 *
 * `mode` is derived rather than assumed: a backend that answers wins, otherwise
 * a non-loopback origin uses the deployment's own server engine, and a
 * loopback origin (nothing installed, nothing deployed) uses the built-in
 * browser scanner.
 */
export async function resolveBackendEndpoint(
  settings: Pick<DashboardSettings, "backendUrl">,
  timeoutMs = PROBE_TIMEOUT_MS,
): Promise<BackendResolution> {
  if (inFlight) return inFlight;

  inFlight = (async (): Promise<BackendResolution> => {
    const tried: { url: string; reachable: boolean }[] = [];
    for (const candidate of backendCandidates(settings)) {
      const reachable = await probeBackend(candidate.url, timeoutMs);
      tried.push({ url: candidate.url, reachable });
      if (reachable) {
        setActiveBackendBase(candidate.url);
        return { engine: "backend", url: candidate.url, tried };
      }
    }
    setActiveBackendBase(null);
    return {
      engine: isPublicOrigin() ? "hosted" : "local",
      url: null,
      tried,
    };
  })();

  try {
    return await inFlight;
  } finally {
    inFlight = null;
  }
}
