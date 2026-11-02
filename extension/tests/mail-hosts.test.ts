/**
 * Mailbox detection.
 *
 * This decision is shared by the content script (report the open message) and
 * the background worker (do *not* scan the mail UI as a website). If the two
 * ever disagree, a Gmail tab gets two competing results again — a page verdict
 * for "Google Mail" racing the real email verdict for the same badge.
 */
import { describe, expect, it } from "vitest";
import { isMailProviderHost, isMailProviderUrl, mailProviderFor } from "../src/lib/mail-hosts";

describe("mailProviderFor", () => {
  it("recognises Gmail", () => {
    expect(mailProviderFor("mail.google.com")).toBe("gmail");
  });

  it("recognises Outlook Web on every host it uses", () => {
    for (const host of [
      "outlook.office.com",
      "outlook.office365.com",
      "outlook.live.com",
      "outlook.com",
      "outlook.office.de",
      "outlook.office365.us",
      "partner.outlook.cn",
    ]) {
      expect(mailProviderFor(host), host).toBe("outlook");
    }
  });

  it("does not treat other Google or Microsoft hosts as mailboxes", () => {
    for (const host of [
      "google.com",
      "accounts.google.com",
      "drive.google.com",
      "www.microsoft.com",
      "login.microsoftonline.com",
      "example.com",
      "outlook.example.com",
    ]) {
      expect(mailProviderFor(host), host).toBe("unknown");
    }
  });

  it("is case-insensitive and whitespace-tolerant", () => {
    expect(mailProviderFor("  MAIL.GOOGLE.COM ")).toBe("gmail");
  });
});

describe("isMailProviderUrl", () => {
  it("accepts a real mailbox URL", () => {
    expect(isMailProviderUrl("https://mail.google.com/mail/u/0/#inbox/abc")).toBe(true);
    expect(isMailProviderUrl("https://outlook.office.com/mail/inbox")).toBe(true);
  });

  it("rejects non-web schemes, malformed values and other sites", () => {
    for (const url of [
      "about:blank",
      "chrome://extensions",
      "file:///C:/mail.html",
      "javascript:alert(1)",
      "not a url",
      "https://example.com",
    ]) {
      expect(isMailProviderUrl(url), url).toBe(false);
    }
  });

  it("agrees with isMailProviderHost", () => {
    expect(isMailProviderHost("mail.google.com")).toBe(true);
    expect(isMailProviderHost("example.com")).toBe(false);
  });
});
