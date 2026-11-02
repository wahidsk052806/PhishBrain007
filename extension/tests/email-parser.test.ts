import { describe, it, expect } from "vitest";
import { JSDOM } from "jsdom";
import { parseEmail } from "../src/content/email-parser";
import { isMailRedirector, unwrapMailRedirect } from "../src/content/mail-links";

function makeDoc(html: string, url: string) {
  const dom = new JSDOM(html, { url });
  return { doc: dom.window.document, location: dom.window.location as unknown as Location };
}

const GMAIL_URL = "https://mail.google.com/mail/u/0/#inbox/thread-1";

/** Gmail's reading pane: role=main, so header chrome elsewhere cannot win. */
function gmailReadingPane(inner: string): string {
  return `<html><body>
    <div class="aeN"><span class="gD" email="decoy@example.com" name="Decoy">Decoy</span></div>
    <div role="main">${inner}</div>
  </body></html>`;
}

describe("parseEmail", () => {
  it("returns null on unrecognized hosts", () => {
    const { doc, location } = makeDoc("<html><body></body></html>", "https://example.com/inbox");
    expect(parseEmail(doc, location)).toBeNull();
  });

  it("returns a record with no sender for a mailbox with no message open", () => {
    const { doc, location } = makeDoc(
      gmailReadingPane(`<div class="a3s">inbox list, no message</div>`),
      GMAIL_URL,
    );
    const parsed = parseEmail(doc, location);

    // The list view has no header, so the caller's "no message open" check
    // (sender and body both empty) decides — not a mis-read decoy sender.
    expect(parsed?.sender).toBeNull();
    expect(parsed?.subject).toBeNull();
  });

  it("never treats the message list as an open message", () => {
    // Gmail's list rows carry sender avatars (`data-hovercard-id`) but no
    // rendered body. Reading the avatar as the sender made the extension
    // analyse the inbox itself and pin a verdict to a message nobody opened.
    const { doc, location } = makeDoc(
      gmailReadingPane(`
        <table><tr class="zA">
          <td><span data-hovercard-id="someone@example.com" class="zF" email="someone@example.com">S</span></td>
          <td><span class="y2">Your account is limited — act now</span></td>
        </tr></table>
      `),
      GMAIL_URL,
    );
    const parsed = parseEmail(doc, location);

    expect(parsed?.sender).toBe("someone@example.com");
    // The body is what decides: a list row is not a message.
    expect(parsed?.bodyText).toBeNull();
    expect(parsed?.hasBody).toBe(false);
  });

  it("marks a message with a rendered body as open", () => {
    const { doc, location } = makeDoc(
      gmailReadingPane(`<div class="a3s">Hello there.</div>`),
      GMAIL_URL,
    );
    expect(parseEmail(doc, location)?.hasBody).toBe(true);
  });

  it("parses Gmail sender, subject and body", () => {
    const html = gmailReadingPane(`
      <h3 class="iw"><span class="gD" email="attacker@phish.example" name="IT Support">IT Support</span></h3>
      <h2 class="hP">Urgent: verify your account</h2>
      <div class="a3s">Click here to verify: <a href="https://phish.example/verify">verify</a></div>
    `);
    const { doc, location } = makeDoc(html, GMAIL_URL);
    const parsed = parseEmail(doc, location);

    expect(parsed).not.toBeNull();
    expect(parsed?.provider).toBe("gmail");
    expect(parsed?.sender).toBe("attacker@phish.example");
    expect(parsed?.displayName).toBe("IT Support");
    expect(parsed?.subject).toMatch(/verify your account/);
    expect(parsed?.links).toContain("verify|https://phish.example/verify");
    expect(parsed?.spf).toBe("Not available from browser context");
  });

  it("reads the sender from the modern data-hovercard-id spelling", () => {
    const html = gmailReadingPane(`
      <h3 class="iw"><span data-hovercard-id="modern@phish.example">Modern Sender</span></h3>
      <h2 class="hP">Invoice</h2>
      <div class="a3s">Body text</div>
    `);
    const { doc, location } = makeDoc(html, GMAIL_URL);
    const parsed = parseEmail(doc, location);

    expect(parsed?.sender).toBe("modern@phish.example");
    expect(parsed?.displayName).toBe("Modern Sender");
  });

  it("unwraps Gmail's redirector so links point at the real destination", () => {
    const wrapped =
      "https://www.google.com/url?q=https%3A%2F%2Fsecure-paypa1.top%2Flogin&source=gmail&ust=1";
    const html = gmailReadingPane(`
      <h3 class="iw"><span class="gD" email="billing@paypa1.top" name="PayPal">PayPal</span></h3>
      <h2 class="hP">Verify now</h2>
      <div class="a3s"><a href="${wrapped}">https://www.paypal.com/verify</a></div>
    `);
    const { doc, location } = makeDoc(html, GMAIL_URL);
    const parsed = parseEmail(doc, location);

    // The pair is what lets the email layer see text-domain ≠ href-domain.
    expect(parsed?.links).toEqual([
      "https://www.paypal.com/verify|https://secure-paypa1.top/login",
    ]);
  });

  it("reports the newest message body in a thread, not the first", () => {
    const html = gmailReadingPane(`
      <h3 class="iw"><span class="gD" email="alice@example.com" name="Alice">Alice</span></h3>
      <h2 class="hP">Re: contract</h2>
      <div class="a3s">Oldest message in the thread</div>
      <div class="a3s">Newest message: wire the deposit to the new account</div>
    `);
    const { doc, location } = makeDoc(html, GMAIL_URL);
    const parsed = parseEmail(doc, location);

    expect(parsed?.bodyText).toContain("Newest message");
    expect(parsed?.bodyText).not.toContain("Oldest message");
  });

  it("reads Reply-To from the expanded details panel", () => {
    const html = gmailReadingPane(`
      <h3 class="iw"><span class="gD" email="service@brand.com" name="Brand">Brand</span></h3>
      <div class="ajA">
        <table>
          <tr><td class="ajy">from:</td><td class="ajz"><span email="service@brand.com">Brand</span></td></tr>
          <tr><td class="ajy">reply-to:</td><td class="ajz"><span email="collect@evil.tld">collect@evil.tld</span></td></tr>
        </table>
      </div>
      <div class="a3s">Please confirm your account.</div>
    `);
    const { doc, location } = makeDoc(html, GMAIL_URL);
    const parsed = parseEmail(doc, location);

    expect(parsed?.sender).toBe("service@brand.com");
    expect(parsed?.replyTo).toBe("collect@evil.tld");
  });

  it("flags message attachments but not the composer's attach button", () => {
    const attached = makeDoc(
      gmailReadingPane(`
        <h3 class="iw"><span class="gD" email="hr@phish.example" name="HR">HR</span></h3>
        <div class="a3s">Please review the attached invoice</div>
        <div class="aZo" download_url="invoice.pdf">invoice.pdf</div>
      `),
      GMAIL_URL,
    );
    const composerOnly = makeDoc(
      gmailReadingPane(`
        <h3 class="iw"><span class="gD" email="hr@phish.example" name="HR">HR</span></h3>
        <div class="a3s">No attachment here</div>
        <div aria-label="Attach files">📎</div>
      `),
      GMAIL_URL,
    );

    expect(parseEmail(attached.doc, attached.location)?.hasAttachments).toBe(true);
    expect(parseEmail(composerOnly.doc, composerOnly.location)?.hasAttachments).toBe(false);
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
    expect(parsed?.links).toContain("here|https://phish.example/pay");
  });

  it("unwraps Outlook's SafeLinks redirector", () => {
    const wrapped =
      "https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-collect.top%2Fx&data=05";
    const html = `
      <html><body>
        <div data-testid="SenderCard"><span title="billing@paypa1.top">PayPal</span></div>
        <div data-testid="SubjectLine">Action required</div>
        <div data-testid="MessageBody"><a href="${wrapped}">paypal.com</a></div>
      </body></html>
    `;
    const { doc, location } = makeDoc(html, "https://outlook.office.com/mail/inbox");
    const parsed = parseEmail(doc, location);

    expect(parsed?.links).toEqual(["paypal.com|https://evil-collect.top/x"]);
  });
});

describe("quoted replies and signatures", () => {
  /** A one-line reply under a quoted phishing original — the false positive. */
  const replyMarkup = `
    <h3 class="iw"><span class="gD" email="alice@company.example" name="Alice">Alice</span></h3>
    <h2 class="hP">Re: Your account will be suspended</h2>
    <div class="a3s">
      Thanks, I have forwarded this to security.<br>
      <div class="gmail_quote">
        <div class="gmail_attr">On Mon, 3 Mar 2026 at 09:12, PayPal &lt;billing@paypa1.top&gt; wrote:</div>
        <blockquote class="gmail_quote">
          URGENT: your account will be suspended. Verify your password immediately at
          <a href="https://www.google.com/url?q=${encodeURIComponent("https://paypa1-secure.top/login")}">https://paypal.com/login</a>
        </blockquote>
      </div>
    </div>`;

  it("scores only the reply, not the message it quotes", () => {
    const { doc, location } = makeDoc(gmailReadingPane(replyMarkup), GMAIL_URL);
    const parsed = parseEmail(doc, location);

    expect(parsed?.bodyText).toContain("forwarded this to security");
    expect(parsed?.bodyText).not.toMatch(/suspended|password/i);
    // The quoted original's link belongs to the original, not to this reply.
    expect(parsed?.links).toEqual([]);
    expect(parsed?.quotedContentExcluded).toBe(true);
  });

  it("keeps an independent message untouched", () => {
    const { doc, location } = makeDoc(
      gmailReadingPane(`
        <h3 class="iw"><span class="gD" email="sender@phish.example" name="Sender">Sender</span></h3>
        <h2 class="hP">Verify your account</h2>
        <div class="a3s">Your account will be suspended. <a href="https://phish.example/v">verify</a></div>
      `),
      GMAIL_URL,
    );
    const parsed = parseEmail(doc, location);

    expect(parsed?.bodyText).toMatch(/suspended/);
    expect(parsed?.links).toEqual(["verify|https://phish.example/v"]);
    expect(parsed?.quotedContentExcluded).toBe(false);
  });

  it("drops an RFC 3676 signature block", () => {
    const { doc, location } = makeDoc(
      gmailReadingPane(`
        <h3 class="iw"><span class="gD" email="alice@company.example" name="Alice">Alice</span></h3>
        <h2 class="hP">Meeting notes</h2>
        <div class="a3s"><div>See you tomorrow.</div><div>--&nbsp;</div><div>Alice | www.paypa1-support.top</div></div>
      `),
      GMAIL_URL,
    );
    const parsed = parseEmail(doc, location);

    expect(parsed?.bodyText).toBe("See you tomorrow.");
    expect(parsed?.quotedContentExcluded).toBe(true);
  });

  it("leaves a blockquote alone when nothing marks it as a quote", () => {
    // A sender can write <blockquote> for styling; a container that merely
    // *looks* like a quote must not become an invisible place to hide a payload.
    const { doc, location } = makeDoc(
      gmailReadingPane(`
        <h3 class="iw"><span class="gD" email="attacker@evil.top" name="PayPal">PayPal</span></h3>
        <h2 class="hP">Notice</h2>
        <div class="a3s">
          <blockquote>Your account will be suspended — verify your password now.</blockquote>
          <div class="gmail_quote">Confirm your password to keep access.</div>
        </div>
      `),
      GMAIL_URL,
    );
    const parsed = parseEmail(doc, location);

    expect(parsed?.bodyText).toMatch(/suspended/);
    expect(parsed?.bodyText).toMatch(/Confirm your password/);
    expect(parsed?.quotedContentExcluded).toBe(false);
  });

  it("does not empty the body when the whole message is marked as a quote", () => {
    const { doc, location } = makeDoc(
      gmailReadingPane(`
        <h3 class="iw"><span class="gD" email="attacker@evil.top" name="PayPal">PayPal</span></h3>
        <h2 class="hP">Notice</h2>
        <div class="a3s">
          <div class="gmail_quote">
            <div class="gmail_attr">On Mon, 3 Mar 2026 at 09:12, PayPal wrote:</div>
            Verify your password at https://paypa1-secure.top/login
          </div>
        </div>
      `),
      GMAIL_URL,
    );
    const parsed = parseEmail(doc, location);

    expect(parsed?.bodyText).toMatch(/Verify your password/);
    expect(parsed?.quotedContentExcluded).toBe(false);
  });

  it("drops Outlook's appended original", () => {
    const { doc, location } = makeDoc(
      `<html><body>
        <div data-testid="SenderCard"><span title="alice@company.example">Alice</span></div>
        <div data-testid="SubjectLine">Re: Invoice</div>
        <div data-testid="MessageBody">
          <div>Noted, thank you.</div>
          <div id="appendonsend"></div>
          <div>From: PayPal &lt;billing@paypa1.top&gt; Sent: Monday To: Alice</div>
          <div>URGENT: verify your password at <a href="https://paypa1-secure.top/l">paypal.com</a></div>
        </div>
      </body></html>`,
      "https://outlook.office.com/mail/inbox",
    );
    const parsed = parseEmail(doc, location);

    expect(parsed?.bodyText).toBe("Noted, thank you.");
    expect(parsed?.links).toEqual([]);
    expect(parsed?.quotedContentExcluded).toBe(true);
  });
});

describe("mail redirector unwrapping", () => {
  it("unwraps Google and Outlook wrappers", () => {
    expect(unwrapMailRedirect("https://www.google.com/url?q=https%3A%2F%2Fa.top%2Fx")).toBe(
      "https://a.top/x",
    );
    expect(
      unwrapMailRedirect("https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fb.top"),
    ).toBe("https://b.top");
  });

  it("leaves ordinary links and other hosts alone", () => {
    expect(unwrapMailRedirect("https://paypal.com/login")).toBe("https://paypal.com/login");
    expect(unwrapMailRedirect("https://example.com/url?q=https://a.top")).toBe(
      "https://example.com/url?q=https://a.top",
    );
    expect(unwrapMailRedirect("not a url")).toBe("not a url");
  });

  it("refuses to promote a non-http payload out of a wrapper", () => {
    const smuggled = `https://www.google.com/url?q=${encodeURIComponent("javascript:alert(1)")}`;
    expect(unwrapMailRedirect(smuggled)).toBe(smuggled);
  });

  it("peels nested wrappers", () => {
    const inner = "https://evil.top/x";
    const once = `https://www.google.com/url?q=${encodeURIComponent(inner)}`;
    const twice = `https://www.google.com/url?q=${encodeURIComponent(once)}`;

    expect(unwrapMailRedirect(twice)).toBe(inner);
  });

  it("identifies redirector hosts", () => {
    expect(isMailRedirector("https://www.google.com/url?q=x")).toBe(true);
    expect(isMailRedirector("https://mail.google.com/mail/u/0/")).toBe(false);
    expect(isMailRedirector("https://na01.safelinks.protection.outlook.com/?url=x")).toBe(true);
    expect(isMailRedirector("https://example.com/")).toBe(false);
  });
});
