import { describe, it, expect } from "vitest";
import { JSDOM } from "jsdom";
import { summarizePage } from "../src/content/page-analyzer";

function makeDoc(html: string, url = "https://example.com/login") {
  const dom = new JSDOM(html, { url });
  return { doc: dom.window.document, location: dom.window.location as unknown as Location };
}

describe("summarizePage", () => {
  it("detects password and otp fields", () => {
    const { doc, location } = makeDoc(`
      <html><head><title>Login</title></head><body>
        <form>
          <input type="password" name="password" />
          <input type="text" name="otp" autocomplete="one-time-code" />
        </form>
      </body></html>
    `);
    const summary = summarizePage(doc, location);
    expect(summary.hasPasswordField).toBe(true);
    expect(summary.hasOtpField).toBe(true);
    expect(summary.formCount).toBe(1);
  });

  it("detects meta refresh and iframes", () => {
    const { doc, location } = makeDoc(`
      <html><head><meta http-equiv="refresh" content="0"></head>
      <body><iframe src="https://other.com"></iframe></body></html>
    `);
    const summary = summarizePage(doc, location);
    expect(summary.hasMetaRefresh).toBe(true);
    expect(summary.iframeCount).toBe(1);
  });

  it("finds external script domains", () => {
    const { doc, location } = makeDoc(`
      <html><body><script src="https://cdn.evil.com/a.js"></script></body></html>
    `);
    const summary = summarizePage(doc, location);
    expect(summary.externalDomainCount).toBe(1);
    expect(summary.externalDomains).toContain("cdn.evil.com");
  });

  it("finds brand mentions in body text", () => {
    const { doc, location } = makeDoc(`
      <html><body><p>Please verify your PayPal account now.</p></body></html>
    `);
    const summary = summarizePage(doc, location);
    expect(summary.brandMentions).toContain("paypal");
  });

  it("caps sanitized text length", () => {
    const longText = "a".repeat(5000);
    const { doc, location } = makeDoc(`<html><body><p>${longText}</p></body></html>`);
    const summary = summarizePage(doc, location);
    expect(summary.sanitizedText.length).toBeLessThanOrEqual(2000);
  });
});
