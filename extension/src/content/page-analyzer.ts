/**
 * Collects a bounded, privacy-conscious summary of the current page for the
 * webpage analysis layer. Never sends full page HTML — only structural
 * signals and small, sanitized text snippets, all size-capped.
 */

import { unwrapMailRedirect } from "./mail-links";

export const MAX_TEXT_LENGTH = 2000;
export const MAX_LINKS = 50;
export const MAX_BRAND_MENTIONS = 20;
export const MAX_MISMATCHES = 20;

export interface FormFieldSummary {
  type: string;
  count: number;
}

export interface LinkMismatch {
  hrefHost: string;
  visibleText: string;
}

export interface PageSummary {
  title: string;
  url: string;
  formCount: number;
  fieldTypes: FormFieldSummary[];
  hasPasswordField: boolean;
  hasOtpField: boolean;
  hasCardField: boolean;
  iframeCount: number;
  externalScriptCount: number;
  externalDomainCount: number;
  externalDomains: string[];
  hasMetaRefresh: boolean;
  linkMismatches: LinkMismatch[];
  faviconUrl: string | null;
  brandMentions: string[];
  sanitizedText: string;
}

const OTP_HINTS = ["otp", "one-time", "one time", "verification code", "2fa", "auth code"];
const CARD_HINTS = ["cc-number", "cardnumber", "card-number", "cvc", "cvv", "expiry", "card"];
const KNOWN_BRANDS = [
  "paypal",
  "microsoft",
  "apple",
  "google",
  "amazon",
  "netflix",
  "bank of america",
  "chase",
  "wells fargo",
  "facebook",
  "instagram",
  "coinbase",
  "docusign",
  "irs",
];

function sanitizeText(raw: string, maxLength: number): string {
  const collapsed = raw.replace(/\s+/g, " ").trim();
  return collapsed.slice(0, maxLength);
}

function getHostname(href: string, base: string): string | null {
  try {
    return new URL(href, base).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function classifyInput(el: HTMLInputElement): string {
  const type = (el.type || "text").toLowerCase();
  const name = (el.name || "").toLowerCase();
  const id = (el.id || "").toLowerCase();
  const autocomplete = (el.autocomplete || "").toLowerCase();
  const haystack = `${type} ${name} ${id} ${autocomplete}`;

  if (type === "password") return "password";
  if (OTP_HINTS.some((h) => haystack.includes(h))) return "otp";
  if (CARD_HINTS.some((h) => haystack.includes(h))) return "card";
  return type;
}

export function summarizePage(
  doc: Document = document,
  location: Location = window.location,
): PageSummary {
  const url = location.href;
  const title = sanitizeText(doc.title || "", 200);

  const inputs = Array.from(doc.querySelectorAll("input")) as HTMLInputElement[];
  const fieldTypeCounts = new Map<string, number>();
  for (const input of inputs) {
    const type = classifyInput(input);
    fieldTypeCounts.set(type, (fieldTypeCounts.get(type) ?? 0) + 1);
  }
  const fieldTypes: FormFieldSummary[] = Array.from(fieldTypeCounts.entries()).map(
    ([type, count]) => ({ type, count }),
  );
  const hasPasswordField = fieldTypeCounts.has("password");
  const hasOtpField = fieldTypeCounts.has("otp");
  const hasCardField = fieldTypeCounts.has("card");

  const forms = doc.querySelectorAll("form");
  const iframes = doc.querySelectorAll("iframe");

  const scripts = Array.from(doc.querySelectorAll("script[src]")) as HTMLScriptElement[];
  const pageHost = getHostname(url, url);
  const externalDomainsSet = new Set<string>();
  let externalScriptCount = 0;
  for (const script of scripts) {
    const host = getHostname(script.src, url);
    if (host && host !== pageHost) {
      externalScriptCount += 1;
      externalDomainsSet.add(host);
    }
  }

  const metaRefresh = doc.querySelector('meta[http-equiv="refresh" i]');
  const hasMetaRefresh = !!metaRefresh;

  const anchors = Array.from(doc.querySelectorAll("a[href]")).slice(
    0,
    MAX_LINKS,
  ) as HTMLAnchorElement[];
  const linkMismatches: LinkMismatch[] = [];
  for (const a of anchors) {
    if (linkMismatches.length >= MAX_MISMATCHES) break;
    // Unwrap provider redirectors first: a link routed through
    // `google.com/url?q=` or Outlook SafeLinks has an href *host* of google.com
    // or microsoft.com, which would otherwise be compared against the visible
    // text and reported as a mismatch on any page that uses a redirector.
    const hrefHost = getHostname(unwrapMailRedirect(a.href), url);
    const visibleText = sanitizeText(a.textContent || "", 100);
    if (!hrefHost || !visibleText) continue;
    // Detect text that looks like a URL/domain but doesn't match the href host
    const looksLikeUrl =
      /\.[a-z]{2,}/i.test(visibleText) &&
      /^[\w.-]+\.[a-z]{2,}/i.test(visibleText.replace(/^https?:\/\//i, ""));
    if (looksLikeUrl) {
      const textHost = visibleText
        .replace(/^https?:\/\//i, "")
        .split(/[/\s]/)[0]
        .toLowerCase();
      if (
        textHost &&
        textHost !== hrefHost &&
        !hrefHost.endsWith(textHost) &&
        !textHost.endsWith(hrefHost)
      ) {
        linkMismatches.push({ hrefHost, visibleText });
      }
    }
  }

  let faviconUrl: string | null = null;
  const iconLink = doc.querySelector('link[rel~="icon"]') as HTMLLinkElement | null;
  if (iconLink?.href) {
    faviconUrl = iconLink.href;
  }

  const bodyText = doc.body ? doc.body.innerText || doc.body.textContent || "" : "";
  const lowerBody = bodyText.toLowerCase();
  const brandMentions = KNOWN_BRANDS.filter((brand) => lowerBody.includes(brand)).slice(
    0,
    MAX_BRAND_MENTIONS,
  );

  const sanitizedText = sanitizeText(bodyText, MAX_TEXT_LENGTH);

  return {
    title,
    url,
    formCount: forms.length,
    fieldTypes,
    hasPasswordField,
    hasOtpField,
    hasCardField,
    iframeCount: iframes.length,
    externalScriptCount,
    externalDomainCount: externalDomainsSet.size,
    externalDomains: Array.from(externalDomainsSet).slice(0, MAX_LINKS),
    hasMetaRefresh,
    linkMismatches,
    faviconUrl,
    brandMentions,
    sanitizedText,
  };
}
