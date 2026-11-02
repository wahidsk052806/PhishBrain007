/**
 * Mail providers rewrite every link in a message through their own redirector:
 *
 *   Gmail    https://www.google.com/url?q=https%3A%2F%2Fevil.top%2Flogin&source=gmail
 *   Outlook  https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.top
 *
 * Reporting the wrapper would make every link in every email point at
 * google.com / microsoft.com, so the URL layer, the link-text-vs-href
 * comparison and the server-side fetch would all analyse the provider instead
 * of the destination — a phishing link would be reported as a Google link and
 * score clean. Unwrapping here means the rest of the pipeline sees the URL the
 * message actually points at.
 *
 * Only known redirectors are unwrapped, only for `http(s)` results, and only a
 * few levels deep: a `javascript:` or `data:` payload smuggled in a redirector
 * parameter must not become the analysed target.
 */

/** How many nested wrappers to peel before giving up. */
const MAX_DEPTH = 3;

const GOOGLE_HOST = /^(www\.)?google\.[a-z.]{2,}$/i;
const OUTLOOK_SAFELINK_HOST = /(^|\.)safelinks\.protection\.outlook\.com$/i;

/**
 * Returns the URL a mail-provider wrapper points at, or the input unchanged
 * when it is not a known wrapper.
 */
export function unwrapMailRedirect(href: string, depth = 0): string {
  if (depth >= MAX_DEPTH) return href;

  let parsed: URL;
  try {
    parsed = new URL(href);
  } catch {
    return href;
  }

  const host = parsed.hostname.toLowerCase();
  let candidate: string | null = null;

  if (GOOGLE_HOST.test(host) && parsed.pathname === "/url") {
    // `q` is Gmail's parameter; `url` appears on some Google surfaces.
    candidate = parsed.searchParams.get("q") ?? parsed.searchParams.get("url");
  } else if (OUTLOOK_SAFELINK_HOST.test(host)) {
    candidate = parsed.searchParams.get("url");
  }

  if (!candidate) return href;

  // `searchParams.get` has already percent-decoded once; a redirector that
  // double-encodes would need a second pass, which is what the recursion is for.
  const decoded = candidate.trim();
  if (!/^https?:\/\//i.test(decoded)) return href;

  return unwrapMailRedirect(decoded, depth + 1);
}

/**
 * True when a host is a mail-provider redirector, whether or not this
 * particular URL carries a usable target.
 */
export function isMailRedirector(href: string): boolean {
  try {
    const { hostname, pathname } = new URL(href);
    if (GOOGLE_HOST.test(hostname)) return pathname === "/url";
    return OUTLOOK_SAFELINK_HOST.test(hostname);
  } catch {
    return false;
  }
}
