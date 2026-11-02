/**
 * Webmail provider detection, shared by the content script and the service
 * worker so both sides agree on which tabs are mailboxes.
 *
 * It matters on both sides: the content script reports the *open message* on
 * these hosts, and the background worker must not additionally scan the
 * provider's UI as if it were a website. Doing both raced them for the same
 * tab — the badge and banner showed whichever finished last — and spent a full
 * page fetch plus LLM reasoning analysing “Google Mail” instead of the email
 * the user is reading.
 */

export type MailProvider = "gmail" | "outlook" | "unknown";

export function mailProviderFor(hostname: string): MailProvider {
  const host = hostname.trim().toLowerCase();
  if (host === "mail.google.com" || host === "gmail.com") return "gmail";

  // Outlook Web lives under the bare domain, under Microsoft's own `outlook.*`
  // mail hosts (outlook.office.com, outlook.office365.us, outlook.live.com, …)
  // and under the 21Vianet-operated `partner.outlook.cn`. A host that merely
  // *starts with* or contains "outlook" — `outlook.example.com` — is somebody
  // else's site, not a mailbox, so the match is on Microsoft's own names.
  if (host === "outlook.com" || host === "outlook.cn") return "outlook";
  if (/^outlook\.(office365|office|live)\.[a-z]{2,4}$/.test(host)) return "outlook";
  if (/\.outlook\.(com|cn)$/.test(host)) return "outlook";

  return "unknown";
}

export function isMailProviderHost(hostname: string): boolean {
  return mailProviderFor(hostname) !== "unknown";
}

/** Same check for a full URL, so the background worker never needs a parser. */
export function isMailProviderUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    return isMailProviderHost(parsed.hostname);
  } catch {
    return false;
  }
}
