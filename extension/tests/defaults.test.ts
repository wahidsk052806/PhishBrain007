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
import { describe, expect, it } from "vitest";
import { DEFAULT_BACKEND_URL, DEFAULT_DASHBOARD_URL } from "../src/services/api";
import { DEFAULT_SETTINGS } from "../src/lib/settings";

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

  it("uses parseable absolute http(s) origins", () => {
    for (const value of [DEFAULT_BACKEND_URL, DEFAULT_DASHBOARD_URL]) {
      const parsed = new URL(value);
      expect(["http:", "https:"]).toContain(parsed.protocol);
    }
  });
});
