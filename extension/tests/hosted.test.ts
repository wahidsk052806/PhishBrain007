/**
 * Hosted-endpoint resolution.
 *
 * The extension has to work on a device that has no local backend at all, so
 * the hosted live-scan endpoint must come from somewhere real. It used to be a
 * hard-coded third-party URL, which meant a fresh install fell back to a domain
 * that no longer resolves and scanned nothing. The endpoint now follows the
 * dashboard origin the user configures, and this test pins that resolution
 * order so a future edit cannot quietly reintroduce a dead default.
 */
import { describe, expect, it, vi } from "vitest";
import {
  analysisDeepLink,
  configuredDashboardOrigin,
  dashboardOpenTarget,
  describeSource,
  isLocalOrigin,
  openableOrigin,
  isLoopbackHostname,
  isPlaceholderHostname,
  isStaleDashboardUrl,
  isUsableEndpoint,
  probeHosted,
  publicOrigin,
  resolveHostedEmail,
  resolveHostedScan,
} from "../src/lib/hosted";
import { DEFAULT_SETTINGS, type Settings } from "../src/lib/settings";

function settings(patch: Partial<Settings> = {}): Settings {
  return { ...DEFAULT_SETTINGS, ...patch };
}

/**
 * "Open Dashboard" has to land on a report.
 *
 * It used to link `/?analysis_id=…`, which the dashboard does not read, so the
 * button opened the home page and the scan the user had just made was not there.
 * Worse, an id produced by the hosted fallback does not exist in any backend's
 * history, so there was nothing to find even in principle. The link now names the
 * page that was scanned and the dashboard re-runs it.
 */
describe("dashboard deep link", () => {
  it("points at the analysis page with the scanned target", () => {
    expect(analysisDeepLink("https://phishbrain007.app", "https://evil.example/login"))
      .toBe("https://phishbrain007.app/analysis?url=https%3A%2F%2Fevil.example%2Flogin");
  });

  it("does not double the slash when the dashboard URL has one", () => {
    for (const base of ["https://phishbrain007.app/", "https://phishbrain007.app//"])
      expect(analysisDeepLink(base, "https://a.example/")).toBe(
        "https://phishbrain007.app/analysis?url=https%3A%2F%2Fa.example%2F",
      );
  });

  it("encodes query strings and fragments inside the target", () => {
    const link = analysisDeepLink("https://phishbrain007.app", "https://a.example/p?q=1&r=2#frag");
    expect(link.split("?url=")[1]).toBe("https%3A%2F%2Fa.example%2Fp%3Fq%3D1%26r%3D2%23frag");
    expect(link).not.toMatch(/&r=2/);
  });

  it("falls back to the analysis page when there is no page to re-scan", () => {
    // A message verdict carries no URL of its own; the user pastes the text in.
    for (const target of ["", "   ", "not-a-url"]) {
      expect(analysisDeepLink("https://phishbrain007.app", target)).toBe(
        "https://phishbrain007.app/analysis",
      );
    }
  });

  it("works for a local dashboard too, so `npm run dev` is reachable", () => {
    expect(analysisDeepLink("http://127.0.0.1:8080", "https://a.example")).toBe(
      "http://127.0.0.1:8080/analysis?url=https%3A%2F%2Fa.example",
    );
  });
});

describe("loopback detection", () => {
  it("recognises every spelling of this machine", () => {
    for (const host of ["localhost", "127.0.0.1", "127.0.0.53", "::1", "[::1]", "app.localhost"]) {
      expect(isLoopbackHostname(host), host).toBe(true);
    }
  });

  it("does not mistake a public host for loopback", () => {
    for (const host of ["example.com", "localhost.example.com", "notlocalhost"]) {
      expect(isLoopbackHostname(host), host).toBe(false);
    }
  });

  it("accepts only http(s) public origins", () => {
    expect(publicOrigin("https://demo.example.com/analysis?x=1")).toBe("https://demo.example.com");
    expect(publicOrigin("http://demo.example.com")).toBe("http://demo.example.com");
    expect(publicOrigin("http://127.0.0.1:8080")).toBeNull();
    expect(publicOrigin("http://localhost:8080")).toBeNull();
    expect(publicOrigin("javascript:alert(1)")).toBeNull();
    expect(publicOrigin("not a url")).toBeNull();
  });

  it("rejects endpoints that would silently no-op a fetch", () => {
    expect(isUsableEndpoint("https://demo.example.com/api/public/scan")).toBe(true);
    expect(isUsableEndpoint("")).toBe(false);
    expect(isUsableEndpoint("   ")).toBe(false);
    expect(isUsableEndpoint("ftp://demo.example.com")).toBe(false);
  });
});

describe("hosted endpoint resolution", () => {
  it("derives the endpoints from a deployed dashboard URL", () => {
    const s = settings({ dashboardUrl: "https://demo.example.com" });

    expect(resolveHostedScan(s)).toEqual({
      url: "https://demo.example.com/api/public/scan",
      source: "dashboard",
    });
    expect(resolveHostedEmail(s)).toEqual({
      url: "https://demo.example.com/api/public/email-scan",
      source: "dashboard",
    });
  });

  it("derives from the origin, not the path", () => {
    const s = settings({ dashboardUrl: "https://demo.example.com/analysis/?tab=url" });
    expect(resolveHostedScan(s).url).toBe("https://demo.example.com/api/public/scan");
  });

  it("never derives a hosted endpoint from a loopback dashboard", () => {
    const s = settings({ dashboardUrl: "http://127.0.0.1:8080" });
    const resolved = resolveHostedScan(s);

    // Nothing to derive from and nothing configured: the callers must report
    // "not configured" rather than fetch a host that cannot answer.
    expect(resolved.url).toBe("");
    expect(resolved.source).toBe("default");
  });

  it("prefers a live-scan URL the user typed over the dashboard origin", () => {
    const s = settings({
      dashboardUrl: "https://demo.example.com",
      cloudScanUrl: "https://scanner.other-host.net/public/scan",
    });
    expect(resolveHostedScan(s)).toEqual({
      url: "https://scanner.other-host.net/public/scan",
      source: "configured",
    });
  });

  it("uses a configured endpoint even when the dashboard is only local", () => {
    const s = settings({ cloudScanUrl: "https://demo.example.com/api/public/scan" });
    expect(resolveHostedScan(s).source).toBe("configured");
  });

  it("tolerates a trailing slash and surrounding whitespace", () => {
    const s = settings({ cloudScanUrl: "  https://demo.example.com/api/public/scan/  " });
    expect(resolveHostedScan(s).url).toBe("https://demo.example.com/api/public/scan");
  });

  it("falls back to the packaged default when the configured value is junk", () => {
    const s = settings({ dashboardUrl: "not-a-url", cloudScanUrl: "ftp://nope" });
    expect(resolveHostedScan(s).url).toBe("");
    expect(resolveHostedScan(s).source).toBe("default");
  });

  it("ships no dead third-party domain as a default", () => {
    // A hard-coded fallback host is exactly the bug this module replaced.
    expect(DEFAULT_SETTINGS.cloudScanUrl).toBe("");
    expect(DEFAULT_SETTINGS.cloudEmailScanUrl).toBe("");
  });

  it("explains where the URL came from, so the Options page can say it", () => {
    for (const source of ["configured", "dashboard", "default"] as const) {
      expect(describeSource(source).length).toBeGreaterThan(10);
    }
  });
});

/**
 * "Open Dashboard" destination.
 *
 * A development build stores the loopback dashboard, and the popup resolved its
 * dashboard URL through the *public*-origin helper — which rejects loopback by
 * design. The destination was therefore empty and both "Open Dashboard" and
 * "Settings" led to the Options page.
 */
describe("dashboard open target", () => {
  it("keeps a local dashboard instead of discarding it", () => {
    expect(dashboardOpenTarget("http://127.0.0.1:8080")).toBe("http://127.0.0.1:8080");
    expect(dashboardOpenTarget("", "http://localhost:8080/")).toBe("http://localhost:8080");
    expect(isLocalOrigin("http://127.0.0.1:8080")).toBe(true);
    expect(isLocalOrigin("https://phishbrain007.app")).toBe(false);
  });

  it("prefers a deployed dashboard over a local one", () => {
    expect(dashboardOpenTarget("http://127.0.0.1:8080", "https://phishbrain007.app")).toBe(
      "https://phishbrain007.app",
    );
    // A hosted endpoint URL resolves to its origin, not to the full path.
    expect(dashboardOpenTarget("https://phishbrain007.app/api/public/scan")).toBe(
      "https://phishbrain007.app",
    );
  });

  it("stays empty when nothing usable is configured, so Settings is the honest target", () => {
    expect(dashboardOpenTarget()).toBeNull();
    expect(dashboardOpenTarget(undefined, "")).toBeNull();
    // The undeployed placeholder must not be opened, and must not be offered as
    // a local fallback either.
    expect(dashboardOpenTarget("https://www.phishbrain07.app")).toBeNull();
    expect(openableOrigin("https://www.phishbrain07.app")).toBeNull();
    expect(openableOrigin("chrome-extension://abc/options.html")).toBeNull();
  });
});

/**
 * The extension used to ship `www.phishbrain07.app` as its public default.
 * That host has no DNS record, so an install that still had it stored showed
 * “Backend unavailable … Tried https://www.phishbrain07.app/api/public/scan”
 * and an “Open Dashboard” button that landed on Firefox's “Server Not Found”.
 * A leftover like that has to be treated as *not configured*, so the UI can ask
 * for a real URL instead of blaming the network.
 */
describe("undeployed placeholder hosts", () => {
  it("recognises the old defaults and their subdomains", () => {
    for (const host of ["phishbrain07.app", "www.phishbrain07.app", "PHISHBRAIN07.APP"])
      expect(isPlaceholderHostname(host), host).toBe(true);
    expect(isPlaceholderHostname("phishbrain007.lovable.app")).toBe(true);
  });

  it("does not match the real deployment, which differs by one zero", () => {
    // `phishbrain07.app` was the undeployed default; `phishbrain007.app` is the
    // deployment. Treating the latter as a placeholder would make a working
    // install report "not configured" and refuse to derive its endpoints.
    for (const host of ["phishbrain007.app", "www.phishbrain007.app", "api.phishbrain007.app"])
      expect(isPlaceholderHostname(host), host).toBe(false);
    expect(configuredDashboardOrigin("https://phishbrain007.app")).toBe(
      "https://phishbrain007.app",
    );
  });

  it("does not match a lookalike the user owns", () => {
    for (const host of [
      "phishbrain07.app.example.com",
      "notphishbrain07.app",
      "phishbrain07.app.evil.net",
      "demo.example.com",
    ])
      expect(isPlaceholderHostname(host), host).toBe(false);
  });

  it("treats a stored placeholder as unconfigured", () => {
    expect(configuredDashboardOrigin("https://www.phishbrain07.app")).toBeNull();
    expect(isStaleDashboardUrl("https://www.phishbrain07.app")).toBe(true);
    // …while a real deployment is still accepted.
    expect(configuredDashboardOrigin("https://phishbrain.example.com")).toBe(
      "https://phishbrain.example.com",
    );
    expect(isStaleDashboardUrl("https://phishbrain.example.com")).toBe(false);
  });

  it("never derives a hosted endpoint from the placeholder", () => {
    const s = settings({ dashboardUrl: "https://www.phishbrain07.app" });
    expect(resolveHostedScan(s)).toEqual({ url: "", source: "default" });
    expect(resolveHostedEmail(s).url).toBe("");
  });

  it("ignores a stored live-scan URL that points at the placeholder", () => {
    // Older builds shipped this as the default, and the value persisted in
    // storage. It is not a deployment the user configured, so honouring it
    // produced a permanent “Backend unavailable … Tried
    // https://www.phishbrain07.app/api/public/scan” panel on a machine whose
    // local backend was healthy.
    const legacy = settings({
      dashboardUrl: "",
      cloudScanUrl: "https://www.phishbrain07.app/api/public/scan",
    });

    expect(resolveHostedScan(legacy)).toEqual({ url: "", source: "default" });

    // A real dashboard still wins, and a real typed endpoint is still used.
    expect(
      resolveHostedScan(
        settings({ dashboardUrl: "https://demo.example.com", cloudScanUrl: "https://www.phishbrain07.app/api/public/scan" }),
      ).url,
    ).toBe("https://demo.example.com/api/public/scan");
    expect(
      resolveHostedScan(
        settings({ cloudScanUrl: "https://scanner.example.com/api/public/scan" }),
      ).source,
    ).toBe("configured");
  });

  it("never probes an empty endpoint, so it cannot report a fake fallback", async () => {
    const spy = vi.fn();
    const original = globalThis.fetch;
    globalThis.fetch = spy as unknown as typeof fetch;
    try {
      // `fetch("")` resolves against the calling page (the popup's own
      // chrome-extension:// URL) and answers 200, which made an unconfigured
      // install claim "Hosted fallback".
      await expect(probeHosted("")).resolves.toEqual({ reachable: false, status: null });
      expect(spy).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = original;
    }
  });

  it("still honours a real endpoint the user typed", () => {
    const s = settings({
      dashboardUrl: "https://www.phishbrain07.app",
      cloudScanUrl: "https://scan.example.com/api/public/scan",
    });
    expect(resolveHostedScan(s)).toEqual({
      url: "https://scan.example.com/api/public/scan",
      source: "configured",
    });
  });
});
