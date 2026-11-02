/** Dashboard-side settings, persisted in localStorage (no backend secrets here). */

export interface DashboardSettings {
  backendUrl: string;
  demoMode: boolean;
  safeThreshold: number;
  suspiciousThreshold: number;
  theme: "dark" | "light";
}

/**
 * Where a *deployed* dashboard looks for the scan engine, without asking each
 * visitor to paste an address.
 *
 * On a public site, `localhost:8000` means the visitor's own machine, so the
 * dashboard fell back to its serverless engine for everyone — no CatBoost
 * pre-filter, no LLM verdict, no screenshot comparison, even when the operator's
 * backend was running perfectly at a public address. Building with
 * `VITE_PHISHBRAIN_BACKEND_URL=https://api.example.app` (see
 * `deploy/README.md`) makes the full pipeline the default; a visitor can still
 * override it on the Settings page, which is stored in localStorage.
 *
 * A malformed value is ignored: Vite stringifies whatever it is handed, and a
 * default without a scheme would be an address the dashboard can never reach.
 */
function buildDefaultBackendUrl(value: string | undefined): string {
  const trimmed = (value ?? "").trim().replace(/\/+$/, "");
  return /^https?:\/\/[^\s]+$/i.test(trimmed) ? trimmed : "";
}

/**
 * The API host the public site talks to (`deploy/README.md`, step 5).
 *
 * A production build is what a stranger loads, so its default must be the
 * deployed API: leaving it at `localhost:8000` meant every visitor's dashboard
 * probed *their own machine*, found nothing, and quietly served the reduced
 * server engine — no CatBoost pre-filter, no LLM verdict, no screenshot — while
 * the operator's backend was running perfectly. Development builds (`vite dev`,
 * `vite build --mode development`) keep the loopback default.
 */
const PRODUCTION_BACKEND_URL = "https://api.phishbrain007.app";

function defaultBackendUrl(): string {
  const override = buildDefaultBackendUrl(import.meta.env?.["VITE_PHISHBRAIN_BACKEND_URL"]);
  if (override) return override;
  return import.meta.env?.PROD ? PRODUCTION_BACKEND_URL : "http://localhost:8000";
}

export const DEFAULT_SETTINGS: DashboardSettings = {
  backendUrl: defaultBackendUrl(),
  demoMode: true,
  safeThreshold: 30,
  suspiciousThreshold: 70,
  theme: "dark",
};

/**
 * True when the page is served from a real host rather than this machine.
 *
 * A deployed dashboard is expected to serve *every* visitor, including ones who
 * have never run the FastAPI backend. In that situation the browser must not
 * open with a connection attempt to the visitor's own `localhost:8000`, and the
 * header must not label the site "backend offline" — nothing is broken, the
 * deployment scans with its own server engine.
 */
export function isPublicOrigin(): boolean {
  if (typeof window === "undefined") return false;
  const host = window.location.hostname.toLowerCase();
  return !(
    host === "localhost" ||
    host === "::1" ||
    host === "0.0.0.0" ||
    host.startsWith("127.") ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  );
}

/** True when a URL points back at the machine running the browser. */
export function isLoopbackUrl(url: string): boolean {
  try {
    const host = new URL(url.trim()).hostname.toLowerCase().replace(/^\[|\]$/g, "");
    return (
      host === "localhost" ||
      host === "::1" ||
      host === "0.0.0.0" ||
      host.startsWith("127.") ||
      host.endsWith(".localhost")
    );
  } catch {
    return false;
  }
}

const KEY = "phishbrain.settings";

export function loadSettings(): DashboardSettings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return DEFAULT_SETTINGS;
    return { ...DEFAULT_SETTINGS, ...(JSON.parse(raw) as Partial<DashboardSettings>) };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function saveSettings(settings: DashboardSettings): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(KEY, JSON.stringify(settings));
  window.dispatchEvent(new CustomEvent("phishbrain:settings"));
}
