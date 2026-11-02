/**
 * Extracts email metadata from Gmail and Outlook Web DOMs for the email
 * analysis layer. SPF/DKIM/DMARC cannot be verified from browser context and
 * are always marked explicitly as unavailable.
 *
 * Two details decide whether the email layer produces a real verdict or noise:
 *
 *  - **The links must be the real destinations.** Gmail and Outlook rewrite
 *    every link through their own redirector, so the href in the DOM points at
 *    google.com / microsoft.com. Each link is unwrapped (`mail-links.ts`) and
 *    reported as `text|href`, which is the pair form the backend compares — it
 *    is what makes "the visible text says paypal.com but the href goes
 *    elsewhere" detectable at all.
 *  - **The newest message must be the one read.** In a Gmail thread every
 *    expanded message is in the DOM; the last body is the one the reader is
 *    looking at, and taking the first reported the oldest message in the
 *    conversation.
 */

import { mailProviderFor, type MailProvider } from "../lib/mail-hosts";
import { extractScorableBody } from "./mail-body";
import { unwrapMailRedirect } from "./mail-links";

export interface ParsedEmail {
  provider: MailProvider;
  sender: string | null;
  replyTo: string | null;
  displayName: string | null;
  subject: string | null;
  /** The new message only: quoted replies and signatures are excluded. */
  bodyText: string | null;
  /**
   * True only when a rendered message body was found. Gmail's message list has
   * sender avatars (`[data-hovercard-id]`) and no `div.a3s`, so a bare
   * `sender != null` test treated the inbox itself as an open email and sent a
   * verdict for a message nobody had opened.
   */
  hasBody: boolean;
  /** `text|href` pairs, hrefs unwrapped, deduplicated, capped. */
  links: string[];
  hasAttachments: boolean;
  /** True when a quoted reply or a signature was left out of `bodyText`. */
  quotedContentExcluded: boolean;
  spf: "Not available from browser context";
  dkim: "Not available from browser context";
  dmarc: "Not available from browser context";
}

const NOT_AVAILABLE = "Not available from browser context" as const;
const MAX_BODY_LENGTH = 4000;
const MAX_LINKS = 50;
const MAX_LINK_TEXT = 120;

function extractEmailFromText(text: string): string | null {
  const match = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  return match ? match[0] : null;
}

function normalizeWhitespace(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/**
 * Restrict the search to the reading pane. Without it a hidden pane, the
 * message list, or a background conversation can supply the sender and body.
 */
function readingPane(doc: Document): ParentNode {
  return (
    doc.querySelector('div[role="main"]') ??
    doc.querySelector("div.nH.bkK") ??
    doc.querySelector("div.aeN") ??
    doc
  );
}

/**
 * Gmail has moved the sender address between attributes over time: `email` on
 * `span.gD`, then `data-hovercard-id`, and the address is also written into the
 * visible text for contacts. Every spelling is tried before giving up.
 */
function readGmailSender(root: ParentNode): { sender: string | null; displayName: string | null } {
  const selectors = [
    "span.gD[email]",
    "span[email]",
    "[data-hovercard-id]",
    "h3.iw span",
    "h3 span",
  ];

  for (const selector of selectors) {
    for (const node of Array.from(root.querySelectorAll(selector))) {
      const element = node as HTMLElement;
      const address =
        element.getAttribute("email") ??
        element.getAttribute("data-hovercard-id") ??
        extractEmailFromText(element.textContent ?? "");

      // `data-hovercard-id` is a person id on some surfaces, not an address.
      if (!address || !address.includes("@")) continue;

      const declared = element.getAttribute("name")?.trim();
      const visible = normalizeWhitespace((element.textContent ?? "").replace(/<.*?>/, ""));
      const displayName =
        declared || (visible.includes("@") ? visible.split("@")[0] : visible) || null;

      return { sender: address, displayName: displayName || null };
    }
  }

  return { sender: null, displayName: null };
}

/**
 * Gmail only renders Reply-To inside the expanded "show details" panel, where
 * it appears as a label cell next to a value cell. The lookup is therefore
 * label-driven rather than class-driven: a label that says Reply-To, and the
 * address in its own row. A missing panel simply yields null.
 */
function readGmailReplyTo(root: ParentNode): string | null {
  for (const node of Array.from(root.querySelectorAll(".ajy, .ajA span, [data-tooltip]"))) {
    const label = normalizeWhitespace(node.textContent ?? "").toLowerCase();
    if (!label.startsWith("reply-to")) continue;

    const row = node.closest("tr") ?? node.parentElement?.parentElement ?? node.parentElement;
    const value =
      row?.querySelector(".ajz [email], .ajz") ??
      row?.querySelector("[email]") ??
      node.nextElementSibling;

    const address = value?.getAttribute("email") ?? extractEmailFromText(value?.textContent ?? "");
    if (address) return address;
  }
  return null;
}

/**
 * The message body. In a Gmail thread every expanded message is present, and
 * the last one is the newest; Outlook renders one message at a time.
 */
function readBody(root: ParentNode): HTMLElement | null {
  const bodies = Array.from(root.querySelectorAll("div.a3s, .a3s")) as HTMLElement[];
  if (bodies.length) return bodies[bodies.length - 1];
  return (
    (root.querySelector(
      '[data-testid="MessageBody"], div.ii.gt, div[role="document"]',
    ) as HTMLElement | null) ?? null
  );
}

function readLinks(body: HTMLElement | null): string[] {
  if (!body) return [];

  const seen = new Set<string>();
  const links: string[] = [];

  for (const anchor of Array.from(body.querySelectorAll("a[href]"))) {
    const href = unwrapMailRedirect((anchor as HTMLAnchorElement).href);
    // Only real web destinations: `mailto:` and `javascript:` never reach a
    // server-side fetch, and passing them on only adds noise.
    if (!/^https?:\/\//i.test(href)) continue;
    if (seen.has(href)) continue;
    seen.add(href);

    const text = normalizeWhitespace(anchor.textContent ?? "").slice(0, MAX_LINK_TEXT);
    links.push(text ? `${text}|${href}` : href);
    if (links.length >= MAX_LINKS) break;
  }

  return links;
}

/** Attachment chips, not the "Attach files" button in the composer. */
function detectGmailAttachments(root: ParentNode): boolean {
  return Boolean(
    root.querySelector("[download_url], .aZo, span.aV3, [aria-label*='Download attachment' i]"),
  );
}

function detectOutlookAttachments(root: ParentNode): boolean {
  return Boolean(
    root.querySelector(
      "[data-testid*='ttachment' i], [aria-label*='ttachment' i]:not([aria-label*='Attach file' i])",
    ),
  );
}

function parseGmail(doc: Document): Partial<ParsedEmail> {
  const root = readingPane(doc);
  const { sender, displayName } = readGmailSender(root);

  const subjectEl =
    root.querySelector("h2.hP") ??
    root.querySelector("[data-thread-perm-id] h2") ??
    root.querySelector(".ha h2, h2[data-legacy-thread-id]");
  const subject = subjectEl?.textContent?.trim() ?? null;

  const bodyEl = readBody(root);
  const body = extractScorableBody(bodyEl);
  const bodyText = bodyEl ? normalizeWhitespace(body.text).slice(0, MAX_BODY_LENGTH) : null;

  return {
    sender,
    displayName,
    subject,
    bodyText,
    hasBody: Boolean(bodyText),
    // Links come from the cleaned clone: a link inside the quoted original
    // belongs to a message the reader already had analysed, and fetching it
    // would flag the reply for the original's destination.
    links: readLinks(body.node),
    replyTo: readGmailReplyTo(root),
    hasAttachments: detectGmailAttachments(root),
    quotedContentExcluded: body.excluded,
  };
}

function parseOutlook(doc: Document): Partial<ParsedEmail> {
  const root = readingPane(doc);

  const senderEl = root.querySelector(
    '[data-testid="SenderCard"] span, span.OZZZK',
  ) as HTMLElement | null;
  const senderText = senderEl?.textContent?.trim() ?? "";
  const sender =
    extractEmailFromText(senderText) ??
    (senderEl?.getAttribute("title")
      ? extractEmailFromText(senderEl.getAttribute("title") || "")
      : null);
  const displayName = normalizeWhitespace(senderText.replace(/<.*>/, "")) || null;

  const subjectEl = root.querySelector('[data-testid="SubjectLine"], .allowTextSelection h1');
  const subject = subjectEl?.textContent?.trim() ?? null;

  const bodyEl = readBody(root);
  const body = extractScorableBody(bodyEl);
  const bodyText = bodyEl ? normalizeWhitespace(body.text).slice(0, MAX_BODY_LENGTH) : null;

  return {
    sender,
    displayName,
    subject,
    bodyText,
    hasBody: Boolean(bodyText),
    links: readLinks(body.node),
    replyTo: null,
    hasAttachments: detectOutlookAttachments(root),
    quotedContentExcluded: body.excluded,
  };
}

export function parseEmail(
  doc: Document = document,
  location: Location = window.location,
): ParsedEmail | null {
  const provider = mailProviderFor(location.hostname);
  if (provider === "unknown") return null;

  const parsed = provider === "gmail" ? parseGmail(doc) : parseOutlook(doc);

  return {
    provider,
    sender: parsed.sender ?? null,
    replyTo: parsed.replyTo ?? null,
    displayName: parsed.displayName ?? null,
    subject: parsed.subject ?? null,
    bodyText: parsed.bodyText ?? null,
    hasBody: parsed.hasBody ?? false,
    links: parsed.links ?? [],
    hasAttachments: parsed.hasAttachments ?? false,
    quotedContentExcluded: parsed.quotedContentExcluded ?? false,
    spf: NOT_AVAILABLE,
    dkim: NOT_AVAILABLE,
    dmarc: NOT_AVAILABLE,
  };
}
