/**
 * Extracts email metadata from Gmail and Outlook Web DOMs for the email
 * analysis layer. SPF/DKIM/DMARC cannot be verified from browser context and
 * are always marked explicitly as unavailable.
 */

export interface ParsedEmail {
  provider: "gmail" | "outlook" | "unknown";
  sender: string | null;
  replyTo: string | null;
  displayName: string | null;
  subject: string | null;
  bodyText: string | null;
  links: string[];
  spf: "Not available from browser context";
  dkim: "Not available from browser context";
  dmarc: "Not available from browser context";
}

const NOT_AVAILABLE = "Not available from browser context" as const;
const MAX_BODY_LENGTH = 4000;
const MAX_LINKS = 50;

function detectProvider(hostname: string): ParsedEmail["provider"] {
  if (hostname.includes("mail.google.com")) return "gmail";
  if (hostname.includes("outlook.")) return "outlook";
  return "unknown";
}

function extractEmailFromText(text: string): string | null {
  const match = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  return match ? match[0] : null;
}

function parseGmail(doc: Document): Partial<ParsedEmail> {
  const senderEl = doc.querySelector("h3.iw span[email], span.gD[email]") as HTMLElement | null;
  const sender = senderEl?.getAttribute("email") ?? null;
  const displayName = senderEl?.getAttribute("name") ?? senderEl?.textContent?.trim() ?? null;

  const subjectEl = doc.querySelector("h2.hP");
  const subject = subjectEl?.textContent?.trim() ?? null;

  const bodyEl = doc.querySelector("div.a3s, div.ii.gt");
  const bodyText = bodyEl ? (bodyEl.textContent || "").trim().slice(0, MAX_BODY_LENGTH) : null;

  const links = bodyEl
    ? Array.from(bodyEl.querySelectorAll("a[href]"))
        .map((a) => (a as HTMLAnchorElement).href)
        .slice(0, MAX_LINKS)
    : [];

  // Gmail hides reply-to unless "show original" is expanded; best-effort only.
  const replyToEl = doc.querySelector('[email][data-tooltip*="Reply-To" i]');
  const replyTo = replyToEl?.getAttribute("email") ?? null;

  return { sender, displayName, subject, bodyText, links, replyTo };
}

function parseOutlook(doc: Document): Partial<ParsedEmail> {
  const senderEl = doc.querySelector('[data-testid="SenderCard"] span, span.OZZZK') as HTMLElement | null;
  const senderText = senderEl?.textContent?.trim() ?? "";
  const sender = extractEmailFromText(senderText) ?? (senderEl?.getAttribute("title") ? extractEmailFromText(senderEl.getAttribute("title") || "") : null);
  const displayName = senderText.replace(/<.*>/, "").trim() || null;

  const subjectEl = doc.querySelector('[data-testid="SubjectLine"], .allowTextSelection h1');
  const subject = subjectEl?.textContent?.trim() ?? null;

  const bodyEl = doc.querySelector('[data-testid="MessageBody"], div[role="document"]');
  const bodyText = bodyEl ? (bodyEl.textContent || "").trim().slice(0, MAX_BODY_LENGTH) : null;

  const links = bodyEl
    ? Array.from(bodyEl.querySelectorAll("a[href]"))
        .map((a) => (a as HTMLAnchorElement).href)
        .slice(0, MAX_LINKS)
    : [];

  return { sender, displayName, subject, bodyText, links, replyTo: null };
}

export function parseEmail(doc: Document = document, location: Location = window.location): ParsedEmail | null {
  const provider = detectProvider(location.hostname);
  if (provider === "unknown") return null;

  const parsed = provider === "gmail" ? parseGmail(doc) : parseOutlook(doc);

  return {
    provider,
    sender: parsed.sender ?? null,
    replyTo: parsed.replyTo ?? null,
    displayName: parsed.displayName ?? null,
    subject: parsed.subject ?? null,
    bodyText: parsed.bodyText ?? null,
    links: parsed.links ?? [],
    spf: NOT_AVAILABLE,
    dkim: NOT_AVAILABLE,
    dmarc: NOT_AVAILABLE,
  };
}
