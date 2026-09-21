import { describe, it, expect } from "vitest";
import { JSDOM } from "jsdom";
import { parseEmail } from "../src/content/email-parser";

function makeDoc(html: string, url: string) {
  const dom = new JSDOM(html, { url });
  return { doc: dom.window.document, location: dom.window.location as unknown as Location };
}

describe("parseEmail", () => {
  it("returns null on unrecognized hosts", () => {
    const { doc, location } = makeDoc("<html><body></body></html>", "https://example.com/inbox");
    expect(parseEmail(doc, location)).toBeNull();
  });

  it("parses Gmail sender, subject and body", () => {
    const html = `
      <html><body>
        <h3 class="iw"><span class="gD" email="attacker@phish.example" name="IT Support">IT Support</span></h3>
        <h2 class="hP">Urgent: verify your account</h2>
        <div class="a3s">Click here to verify: <a href="https://phish.example/verify">verify</a></div>
      </body></html>
    `;
    const { doc, location } = makeDoc(html, "https://mail.google.com/mail/u/0/");
    const parsed = parseEmail(doc, location);
    expect(parsed).not.toBeNull();
    expect(parsed?.provider).toBe("gmail");
    expect(parsed?.sender).toBe("attacker@phish.example");
    expect(parsed?.subject).toMatch(/verify your account/);
    expect(parsed?.links).toContain("https://phish.example/verify");
    expect(parsed?.spf).toBe("Not available from browser context");
  });

  it("parses Outlook sender and subject", () => {
    const html = `
      <html><body>
        <div data-testid="SenderCard"><span title="scam@phish.example">Scam Sender &lt;scam@phish.example&gt;</span></div>
        <div data-testid="SubjectLine">Your package could not be delivered</div>
        <div data-testid="MessageBody">Please pay a fee <a href="https://phish.example/pay">here</a></div>
      </body></html>
    `;
    const { doc, location } = makeDoc(html, "https://outlook.office.com/mail/inbox");
    const parsed = parseEmail(doc, location);
    expect(parsed).not.toBeNull();
    expect(parsed?.provider).toBe("outlook");
    expect(parsed?.sender).toBe("scam@phish.example");
    expect(parsed?.subject).toMatch(/could not be delivered/);
    expect(parsed?.links).toContain("https://phish.example/pay");
  });
});
