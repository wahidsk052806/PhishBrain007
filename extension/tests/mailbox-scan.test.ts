/**
 * Mailbox tabs and the "Rescan this page" button.
 *
 * The bug these cover: Firefox only injects a declared content script into
 * pages loaded *after* the add-on starts, so a Gmail tab that was already open
 * had no listener. The mailbox reported nothing, `REPARSE_EMAIL` went nowhere,
 * and the popup answered "No scan result yet for this tab" for good. The
 * worker now proves the script is there (injecting it when it is not) and the
 * mailbox rescan answers at once when no message is open, instead of spinning
 * for the full twenty-second wait.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installHarness, waitFor, type HarnessOptions } from "./helpers/browser-harness";

const GMAIL = "https://mail.google.com/mail/u/0/#inbox/FMfcgzQjggfrVDhbpTGXgXfnXslbscpn";

interface TabScript {
  /** False until something (the worker's injection or a page load) put the script there. */
  listening: boolean;
}

type AnyChrome = {
  runtime: Record<string, unknown> & { lastError?: { message: string } };
  tabs: { sendMessage: unknown };
  scripting: { executeScript: unknown };
};

/**
 * Replaces the harness's tab messaging with a mailbox that behaves the way a
 * real tab does: a missing content script fails the ping the way Chrome/Firefox
 * do ("receiving end does not exist"), and `executeScript` installs it.
 */
function stubMailboxTab(script: TabScript, reply?: (type: string | undefined) => unknown) {
  const chrome = (globalThis as unknown as { chrome: AnyChrome }).chrome;
  const injected: string[] = [];
  const sent: string[] = [];

  chrome.scripting.executeScript = (injection: { files?: string[] }, cb: (r: unknown) => void) => {
    injected.push(...(injection.files ?? []));
    script.listening = true;
    cb([]);
  };

  chrome.tabs.sendMessage = (
    _tabId: number,
    message: { type?: string },
    cb: (response?: unknown) => void,
  ) => {
    sent.push(message.type ?? "");
    if (!script.listening) {
      // What the browser reports when no content script answers.
      chrome.runtime.lastError = { message: "Could not establish connection." };
      cb(undefined);
      delete chrome.runtime.lastError;
      return;
    }
    cb(reply?.(message.type));
  };

  return { injected, sent };
}

const EMAIL = {
  provider: "gmail",
  sender: "noreply@unstop.news",
  reply_to: null,
  display_name: "Team Unstop",
  subject: "Prompt to Podium",
  body_text: "You've been working on your skills. Now put them to the test!",
  links: ["www.unstop.com|https://unstop.com/prompt-to-podium"],
  has_attachments: false,
  quoted_content_excluded: false,
  spf: "Not available from browser context",
  dkim: "Not available from browser context",
  dmarc: "Not available from browser context",
};

describe("mailbox tabs", () => {
  let harness: ReturnType<typeof installHarness>;

  const load = async (options: HarnessOptions = {}) => {
    harness = installHarness({
      ...options,
      settings: { autoScan: true, bannerMode: "banner", riskThreshold: 50, ...options.settings },
    });
    vi.resetModules();
    await import("../src/background/service-worker");
    return harness;
  };

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    harness?.fetchMock.mockClear();
  });

  it("injects the content script into a mailbox tab that was open before the add-on", async () => {
    await load();
    const script: TabScript = { listening: false };
    const tab = stubMailboxTab(script);

    harness.emitTabsUpdated(5, GMAIL);

    expect(await waitFor(() => tab.injected.length > 0)).toBe(true);
    expect(tab.injected).toContain("content.js");
    // The mail UI itself is never analysed as a website: the message is the
    // subject, and a URL scan of Gmail would race the email verdict for the
    // same badge.
    expect(harness.fetchMock).not.toHaveBeenCalled();
  });

  it("does not inject twice when the page already runs the script", async () => {
    await load();
    const script: TabScript = { listening: true };
    const tab = stubMailboxTab(script);

    harness.emitTabsUpdated(5, GMAIL);
    await waitFor(() => tab.sent.length > 0);
    await new Promise((r) => setTimeout(r, 20));

    expect(tab.sent).toContain("PING");
    expect(tab.injected).toHaveLength(0);
  });

  it("answers Rescan at once when no message is open", async () => {
    await load();
    stubMailboxTab({ listening: true }, () => ({ ok: false }));

    const started = Date.now();
    const reply = await harness.sendRuntimeMessage({ type: "RESCAN", tabId: 5, url: GMAIL });

    expect(reply).toBeNull();
    // No verdict is coming, so the twenty-second wait must not be paid.
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("keeps the newest message's verdict when an older scan finishes last", async () => {
    await load();
    const fallthrough = harness.fetchMock.getMockImplementation();
    harness.fetchMock.mockImplementation(async (url: unknown, init?: RequestInit) => {
      const href = String(url);
      if (!href.includes("/api/v1/analyze/email")) {
        return fallthrough ? fallthrough(url, init) : new Response("ok", { status: 200 });
      }
      const body = JSON.parse(String(init?.body ?? "{}")) as { subject?: string };
      // The message the user already left takes longer than the one now open.
      if (body.subject === "Old message") await new Promise((r) => setTimeout(r, 150));
      return new Response(
        JSON.stringify({
          analysis_id: body.subject === "Old message" ? "old-message" : "new-message",
          url: GMAIL,
          threat_score: 20,
          risk_level: "SAFE",
          confidence: 0.8,
          indicators: [],
          layers: {
            email: { risk: 0, indicators: [], evidence: {} },
            url: { risk: 0, indicators: [], evidence: {} },
            domain: { risk: 0, indicators: [], evidence: {} },
            webpage: { risk: 0, indicators: [], evidence: {} },
          },
          explanation: "",
          recommended_action: "",
          latency_ms: 3,
          degraded: [],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    const report = (subject: string) =>
      harness.sendRuntimeMessage(
        { type: "EMAIL_SUMMARY", tabId: 9, url: GMAIL, email: { ...EMAIL, subject } },
        0,
      );

    void report("Old message");
    // The user opens the next message while the first scan is still thinking.
    await new Promise((r) => setTimeout(r, 20));
    void report("New message");

    const stored = () => (harness.store.result_9 as { result?: { analysis_id: string } } | undefined);
    expect(await waitFor(() => stored()?.result?.analysis_id === "new-message")).toBe(true);

    // Let the superseded scan finish; it must not touch the tab.
    await new Promise((r) => setTimeout(r, 400));
    expect(stored()?.result?.analysis_id).toBe("new-message");
    const verdicts = harness.banners.filter(
      (m) => (m as { type?: string }).type === "SHOW_MAIL_VERDICT",
    ) as { result: { analysis_id: string } }[];
    expect(verdicts.at(-1)?.result.analysis_id).toBe("new-message");
  });

  it("returns the verdict the re-read message produces", async () => {
    await load({ backendResult: { risk_level: "HIGH_RISK", threat_score: 88 } });
    stubMailboxTab({ listening: true }, (type) => {
      if (type !== "REPARSE_EMAIL") return { ok: true };
      // Stand in for the content script: re-reading the open message reports it.
      setTimeout(() => {
        // A real content script sends the `-1` sentinel; the harness always
        // reports tab 1 as the sender, so name the rescanned tab explicitly.
        void harness.sendRuntimeMessage(
          { type: "EMAIL_SUMMARY", tabId: 5, url: GMAIL, email: EMAIL },
          0,
        );
      }, 10);
      return { ok: true };
    });

    const reply = (await harness.sendRuntimeMessage({
      type: "RESCAN",
      tabId: 5,
      url: GMAIL,
    })) as { risk_level?: string; analysis_id?: string } | null;

    expect(reply).not.toBeNull();
    expect(reply?.analysis_id).toBe("ext-test-1");
    expect(reply?.risk_level).toBe("HIGH_RISK");
  });
});
