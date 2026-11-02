/**
 * Guards the API/dashboard port split.
 *
 * Regression: `DEFAULT_DASHBOARD_URL` pointed at the API port (8000), so the
 * "Open dashboard" button and the content-script banner link landed users on
 * the FastAPI JSON root instead of the Vite dashboard. A couple of call sites
 * also kept a hardcoded `http://127.0.0.1:8000` fallback, so fixing only the
 * shared constant was not enough.
 *
 * These assertions are deliberately about the invariant (two distinct services,
 * two distinct origins) rather than about the literal port numbers, so changing
 * either default is fine as long as they don't collapse onto each other.
 */
import { describe, expect, it, vi } from "vitest";
import {
  buildDefaults,
  DEFAULT_BACKEND_URL,
  DEFAULT_DASHBOARD_URL,
  DEVELOPMENT_BACKEND_URL,
  DEVELOPMENT_DASHBOARD_URL,
  PRODUCTION_BACKEND_URL,
  PRODUCTION_DASHBOARD_URL,
} from "../src/services/api";
import { DEFAULT_SETTINGS } from "../src/lib/settings";
import { isPlaceholderHostname } from "../src/lib/hosted";

/** Load `services/api` again with the given build-time variables set. */
async function loadWith(env: { backend?: string; dashboard?: string }) {
  vi.resetModules();
  if (env.backend !== undefined) vi.stubEnv("VITE_PHISHBRAIN_BACKEND_URL", env.backend);
  if (env.dashboard !== undefined) vi.stubEnv("VITE_PHISHBRAIN_DASHBOARD_URL", env.dashboard);
  try {
    return await import("../src/services/api");
  } finally {
    vi.unstubAllEnvs();
  }
}

describe("default endpoints", () => {
  it("keeps the dashboard origin distinct from the API origin", () => {
    expect(DEFAULT_DASHBOARD_URL).not.toBe(DEFAULT_BACKEND_URL);
    expect(new URL(DEFAULT_DASHBOARD_URL).origin).not.toBe(new URL(DEFAULT_BACKEND_URL).origin);
  });

  it("defaults settings to the dashboard origin, not the API origin", () => {
    expect(DEFAULT_SETTINGS.dashboardUrl).toBe(DEFAULT_DASHBOARD_URL);
    expect(DEFAULT_SETTINGS.backendUrl).toBe(DEFAULT_BACKEND_URL);
    expect(new URL(DEFAULT_SETTINGS.dashboardUrl).port).not.toBe(
      new URL(DEFAULT_SETTINGS.backendUrl).port,
    );
  });

  it("bakes a deployment's origins in at build time", async () => {
    // What `VITE_…=… npm run build` produces for a published release: a fresh
    // install on any device scans without the user typing a URL in Options.
    const built = await loadWith({
      backend: "https://api.phishbrain007.app/",
      dashboard: "https://phishbrain007.app",
    });

    expect(built.DEFAULT_BACKEND_URL).toBe("https://api.phishbrain007.app");
    expect(built.DEFAULT_DASHBOARD_URL).toBe("https://phishbrain007.app");
  });

  it("ignores a malformed build-time origin", async () => {
    // Vite stringifies whatever it is given; a value without a scheme must not
    // become a default the extension can never reach.
    const built = await loadWith({ backend: "api.phishbrain007.app", dashboard: "" });

    expect(built.DEFAULT_BACKEND_URL).toBe("http://127.0.0.1:8000");
    expect(built.DEFAULT_DASHBOARD_URL).toBe("http://127.0.0.1:8080");
  });

  it("uses parseable absolute http(s) origins", () => {
    for (const value of [DEFAULT_BACKEND_URL, DEFAULT_DASHBOARD_URL]) {
      const parsed = new URL(value);
      expect(["http:", "https:"]).toContain(parsed.protocol);
    }
  });
});

/**
 * A store build runs on a stranger's computer.
 *
 * Their `127.0.0.1:8000` is their own machine and has no backend, so a shipped
 * loopback default made every scan fail on every device except the developer's
 * — the popup showed "Backend unavailable" while the hosted service was fine.
 */
describe("shipped defaults", () => {
  it("a production build targets the deployed API and dashboard", () => {
    const shipped = buildDefaults({ deployed: true });
    expect(shipped.backend).toBe(PRODUCTION_BACKEND_URL);
    expect(shipped.dashboard).toBe(PRODUCTION_DASHBOARD_URL);
    expect(new URL(shipped.backend).protocol).toBe("https:");
    expect(new URL(shipped.dashboard).protocol).toBe("https:");
  });

  it("never ships a host this project knows is undeployed", () => {
    const shipped = buildDefaults({ deployed: true });
    for (const value of [shipped.backend, shipped.dashboard]) {
      expect(isPlaceholderHostname(new URL(value).hostname), value).toBe(false);
    }
  });

  it("a development build keeps the loopback pair", () => {
    const dev = buildDefaults({ deployed: false });
    expect(dev.backend).toBe(DEVELOPMENT_BACKEND_URL);
    expect(dev.dashboard).toBe(DEVELOPMENT_DASHBOARD_URL);
  });

  it("a build-time override wins over either pair", () => {
    const built = buildDefaults({
      deployed: true,
      backendOverride: "https://api.example.org/",
      dashboardOverride: "https://dash.example.org",
    });
    expect(built.backend).toBe("https://api.example.org");
    expect(built.dashboard).toBe("https://dash.example.org");
  });

  it("ignores a malformed override instead of shipping an unreachable host", () => {
    for (const junk of ["api.example.org", "ftp://api.example.org", "   ", "https://"]) {
      const built = buildDefaults({
        deployed: true,
        backendOverride: junk,
        dashboardOverride: junk,
      });
      expect(built.backend, junk).toBe(PRODUCTION_BACKEND_URL);
      expect(built.dashboard, junk).toBe(PRODUCTION_DASHBOARD_URL);
    }
  });
});
