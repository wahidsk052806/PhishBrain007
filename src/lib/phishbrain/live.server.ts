/**
 * Live scanning helpers. Runs ONLY on the server (Worker runtime).
 *
 * Performs real network work against the target:
 *  - HTTP(S) fetch with redirect chain + timing
 *  - DNS resolution through DNS-over-HTTPS (dns.google)
 *  - RDAP registration lookup (rdap.org) for real domain age
 *  - HTML parsing for credential-harvesting signals
 *
 * Everything is best-effort: any sub-system that fails is reported as
 * "unavailable" instead of fabricating a value.
 */

const PRIVATE_HOST =
  /^(localhost|127\.|10\.|192\.168\.|169\.254\.|::1$|0\.0\.0\.0|172\.(1[6-9]|2\d|3[01])\.)/i;

export interface LiveScanContext {
  final_url: string;
  redirect_chain: number;
  /** Every redirect hop that was actually followed, in order. */
  redirect_hops: { status: number; from: string; to: string }[];
  /** Where the fetch stopped and why, when it did not complete. */
  fetch_failure: { url: string; reason: string } | null;
  http_status: number | "unavailable";
  server_header: string | null;
  content_type: string | null;
  response_time_ms: number;
  tls: "valid" | "none" | "unavailable";
  domain: {
    domain_age_days: number | "unavailable";
    registrar: string;
    nameservers: string[] | "unavailable";
    dns_a_records: string[] | "unavailable";
    certificate: string;
  };
  page:
    | {
        title: string;
        has_password_field: boolean;
        has_otp_field: boolean;
        has_card_field: boolean;
        form_action_external: boolean;
        iframe_count: number;
        external_script_domains: number;
        /** Brands the visible text mentions — evidence, not a claim. */
        brand_mentions: string[];
        /** Brands the title or a top-level heading claims to be. */
        brands_claimed: string[];
        hidden_input_count: number;
        obfuscated_script: boolean;
        favicon_external: boolean;
        text_length: number;
      }
    | undefined;
  degraded: string[];
}

export function normalizeUrl(raw: string): string {
  const trimmed = raw.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export function guardTarget(raw: string): URL {
  const parsed = new URL(normalizeUrl(raw));
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http(s) URLs can be scanned.");
  }
  if (PRIVATE_HOST.test(parsed.hostname)) {
    throw new Error("Refusing to scan private / loopback addresses.");
  }
  return parsed;
}

async function withTimeout<T>(p: (signal: AbortSignal) => Promise<T>, ms: number): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await p(ctrl.signal);
  } finally {
    clearTimeout(t);
  }
}

/** Redirects to follow before declaring a loop. */
const MAX_REDIRECTS = 5;
/** Ceiling for a single HTTP attempt. */
const FETCH_ATTEMPT_TIMEOUT_MS = 12_000;
/**
 * Ceiling for the whole redirect walk, retries included.
 *
 * A shared budget rather than a per-attempt one: without it, five slow hops and
 * two attempts each could hold a scan for two minutes, which is worse for the
 * operator than an honest "gave up" after half a minute.
 */
const FETCH_BUDGET_MS = 25_000;

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/**
 * The real reason a fetch died, read out of the whole `cause` chain.
 *
 * Node's fetch reports every transport failure as `TypeError: fetch failed`, which
 * told the operator nothing: a target that reset the TLS handshake, a host with
 * no DNS entry and a refused connection all produced the same sentence. The
 * underlying code (`ECONNRESET`, `ENOTFOUND`, `EPROTO`) is one level down in
 * `err.cause`, and for a scanner it is not just diagnostics — a server that
 * drops a non-browser client mid-handshake is itself an observation.
 */
export function describeFetchFailure(err: unknown): string {
  const parts: string[] = [];
  let current: unknown = err;
  for (let depth = 0; depth < 4 && current instanceof Error; depth++) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === "string" && code && !parts.includes(code)) parts.push(code);
    if (current.message !== "fetch failed" && !parts.includes(current.message)) {
      parts.push(current.message);
    }
    current = (current as { cause?: unknown }).cause;
  }
  const seen = parts.join(": ");
  return seen || "network error";
}

/**
 * Worth one retry: a connection that dropped, not an answer that will not change.
 *
 * A DNS failure (`ENOTFOUND`) or a refusal (`ECONNREFUSED`) is deterministic, so
 * retrying only doubles the wait before reporting the same thing. A reset, a
 * protocol error or a half-open socket frequently is not — measured here, a
 * first attempt at a slow host can die while the second one returns the page.
 */
export function isRetryableFetchFailure(reason: string): boolean {
  return /ECONNRESET|EPROTO|ECONNABORTED|ETIMEDOUT|EAI_AGAIN|UND_ERR_SOCKET|UND_ERR_CONNECT|socket hang up|other side closed|timed out/i.test(
    reason,
  );
}

/**
 * True when our own timeout fired rather than the peer failing.
 *
 * undici reports this as `AbortError: This operation was aborted`, which is
 * indistinguishable in a report from a target that hangs up. Saying "no response
 * within 12 s" instead tells the operator which side went quiet.
 */
function isTimeoutFailure(err: unknown): boolean {
  let current: unknown = err;
  for (let depth = 0; depth < 4 && current instanceof Error; depth++) {
    if (current.name === "AbortError" || /aborted|timed out/i.test(current.message)) return true;
    current = (current as { cause?: unknown }).cause;
  }
  return false;
}

interface FetchOutcome {
  finalUrl: URL;
  status: number | "unavailable";
  server: string | null;
  contentType: string | null;
  html: string;
  hops: { status: number; from: string; to: string }[];
  failure: { url: string; reason: string } | null;
}

const BROWSER_HEADERS = {
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36 PhishBrain/1.0",
  accept: "text/html,application/xhtml+xml",
};

/**
 * Fetch a target, following redirects by hand.
 *
 * `redirect: "follow"` was used before, and it hid the single most useful fact
 * about a failed scan: *which* host broke. `https://epicsports.in/` answers 301
 * to `https://go.epicsports.in/`, and that second host resets the TLS handshake
 * — so the report said "Page fetch failed (fetch failed)" and "redirected:
 * false", both untrue and both unusable. Following the chain explicitly records
 * every hop, reports the host and reason it stopped, and retries once when the
 * drop looks transient.
 */
async function fetchTarget(target: URL): Promise<FetchOutcome> {
  const hops: { status: number; from: string; to: string }[] = [];
  const deadline = Date.now() + FETCH_BUDGET_MS;
  let current = target;

  const gaveUp = (reason: string): FetchOutcome => ({
    finalUrl: current,
    status: "unavailable",
    server: null,
    contentType: null,
    html: "",
    hops,
    failure: { url: current.toString(), reason },
  });

  /** One attempt, with our own timeout, reported in the terms the cause belongs to. */
  const attempt = async (): Promise<{ res: Response } | { reason: string; timedOut: boolean }> => {
    const remaining = deadline - Date.now();
    if (remaining <= 500) return { reason: "no time left in the fetch budget", timedOut: false };
    const timeoutMs = Math.min(FETCH_ATTEMPT_TIMEOUT_MS, remaining);
    try {
      const res = await withTimeout(
        (signal) =>
          fetch(current.toString(), {
            signal,
            // Manual, so the redirect target is inspectable rather than opaque.
            redirect: "manual",
            headers: BROWSER_HEADERS,
          }),
        timeoutMs,
      );
      return { res };
    } catch (err) {
      if (isTimeoutFailure(err)) {
        return {
          reason: `no response within ${Math.round(timeoutMs / 1000)} s (timed out)`,
          timedOut: true,
        };
      }
      return { reason: describeFetchFailure(err), timedOut: false };
    }
  };

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let outcome = await attempt();
    if (!("res" in outcome) && (outcome.timedOut || isRetryableFetchFailure(outcome.reason))) {
      // One retry per hop: a reset, a protocol error or a cold slow host often
      // answers on the second try, and the shared budget bounds the cost.
      await new Promise((resolve) => setTimeout(resolve, 250));
      outcome = await attempt();
    }
    if (!("res" in outcome)) return gaveUp(outcome.reason);
    const res = outcome.res;

    const location = res.headers.get("location");
    if (REDIRECT_STATUS.has(res.status) && location) {
      let next: URL;
      try {
        next = new URL(location, current);
      } catch {
        return {
          finalUrl: current,
          status: res.status,
          server: res.headers.get("server"),
          contentType: res.headers.get("content-type"),
          html: "",
          hops,
          failure: null,
        };
      }
      hops.push({ status: res.status, from: current.toString(), to: next.toString() });
      if (hop === MAX_REDIRECTS) {
        return {
          finalUrl: next,
          status: "unavailable",
          server: null,
          contentType: null,
          html: "",
          hops,
          failure: { url: next.toString(), reason: `more than ${MAX_REDIRECTS} redirects` },
        };
      }
      current = next;
      continue;
    }

    let html = "";
    try {
      const body = await withTimeout(() => res.text(), 6000);
      html = body.slice(0, 800_000);
    } catch (err) {
      return {
        finalUrl: current,
        status: res.status,
        server: res.headers.get("server"),
        contentType: res.headers.get("content-type"),
        html: "",
        hops,
        failure: { url: current.toString(), reason: `response body: ${describeFetchFailure(err)}` },
      };
    }

    return {
      finalUrl: current,
      status: res.status,
      server: res.headers.get("server"),
      contentType: res.headers.get("content-type"),
      html,
      hops,
      failure: null,
    };
  }

  return gaveUp("redirect handling did not settle");
}

/**
 * Say what happened to a fetch in one sentence a reader can act on.
 *
 * The hop is named because the hop is the finding: the apex domain resolved and
 * answered 301, and the host it pointed at refused the client.
 */
export function describeFetchFailureSentence(outcome: FetchOutcome): string {
  if (!outcome.failure) return "";
  const lastHop = outcome.hops.at(-1);
  const via = lastHop ? ` (reached after a ${lastHop.status} redirect from ${lastHop.from})` : "";
  return `Page fetch failed at ${outcome.failure.url} — ${outcome.failure.reason}${via}; webpage layer unavailable.`;
}

function registrable(hostname: string): string {
  const labels = hostname.split(".");
  if (labels.length <= 2) return hostname;
  const twoLevel = ["co.uk", "com.au", "co.in", "com.br", "co.jp", "org.uk", "gov.uk"];
  const last2 = labels.slice(-2).join(".");
  if (twoLevel.includes(last2)) return labels.slice(-3).join(".");
  return last2;
}

async function dnsLookup(hostname: string, type: "A" | "NS"): Promise<string[] | "unavailable"> {
  try {
    const res = await withTimeout(
      (signal) =>
        fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${type}`, {
          signal,
          headers: { accept: "application/dns-json" },
        }),
      6000,
    );
    if (!res.ok) return "unavailable";
    const json = (await res.json()) as { Answer?: { data: string }[] };
    const answers = (json.Answer ?? []).map((a) => a.data);
    return answers.length ? answers : "unavailable";
  } catch {
    return "unavailable";
  }
}

async function rdapLookup(
  hostname: string,
): Promise<{ age: number | "unavailable"; registrar: string }> {
  const domain = registrable(hostname);
  try {
    const res = await withTimeout(
      (signal) =>
        fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
          signal,
          headers: { accept: "application/rdap+json" },
        }),
      8000,
    );
    if (!res.ok) return { age: "unavailable", registrar: "unavailable" };
    const json = (await res.json()) as {
      events?: { eventAction: string; eventDate: string }[];
      entities?: { roles?: string[]; vcardArray?: unknown }[];
    };
    const reg = json.events?.find((e) => /registration/i.test(e.eventAction));
    let age: number | "unavailable" = "unavailable";
    if (reg?.eventDate) {
      const ms = Date.now() - new Date(reg.eventDate).getTime();
      if (Number.isFinite(ms)) age = Math.max(0, Math.round(ms / 86_400_000));
    }
    let registrar = "unavailable";
    const entity = json.entities?.find((e) => e.roles?.includes("registrar"));
    const vcard = entity?.vcardArray as unknown[] | undefined;
    if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
      for (const field of vcard[1] as unknown[]) {
        if (Array.isArray(field) && field[0] === "fn" && typeof field[3] === "string") {
          registrar = field[3];
        }
      }
    }
    return { age, registrar };
  } catch {
    return { age: "unavailable", registrar: "unavailable" };
  }
}

const BRAND_LIST = [
  "paypal",
  "microsoft",
  "office365",
  "google",
  "apple",
  "amazon",
  "netflix",
  "facebook",
  "instagram",
  "linkedin",
  "whatsapp",
  "dhl",
  "fedex",
  "hdfc",
  "icici",
  "sbi",
  "chase",
  "wellsfargo",
  "coinbase",
  "binance",
];

function parseHtml(html: string, finalUrl: URL): NonNullable<LiveScanContext["page"]> {
  const lower = html.toLowerCase();
  const title = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(html)?.[1]?.trim() ?? "";
  const inputs = lower.match(/<input\b[^>]*>/g) ?? [];
  const hasPassword = inputs.some((i) => /type\s*=\s*["']?password/.test(i));
  const hasOtp = inputs.some((i) => /(otp|one-?time|2fa|verification[_-]?code|passcode)/.test(i));
  const hasCard = inputs.some((i) =>
    /(card|cvv|cvc|creditcard|cc-number|expiry|autocomplete=["']?cc)/.test(i),
  );
  const hiddenInputs = inputs.filter((i) => /type\s*=\s*["']?hidden/.test(i)).length;

  const formActions = [...html.matchAll(/<form\b[^>]*action\s*=\s*["']([^"']+)["']/gi)].map(
    (m) => m[1] ?? "",
  );
  let formExternal = false;
  for (const action of formActions) {
    try {
      const u = new URL(action, finalUrl);
      if (u.hostname && u.hostname !== finalUrl.hostname) formExternal = true;
    } catch {
      /* relative / invalid action -> same origin */
    }
  }

  const iframeCount = (lower.match(/<iframe\b/g) ?? []).length;
  const scriptSrcs = [...html.matchAll(/<script\b[^>]*src\s*=\s*["']([^"']+)["']/gi)].map(
    (m) => m[1] ?? "",
  );
  const scriptDomains = new Set<string>();
  for (const src of scriptSrcs) {
    try {
      const u = new URL(src, finalUrl);
      if (u.hostname && u.hostname !== finalUrl.hostname) scriptDomains.add(u.hostname);
    } catch {
      /* ignore */
    }
  }

  // Brands are read from the page's *visible text*, never from its markup.
  //
  // Matching the raw HTML counted `apple-touch-icon` — a <link> half the web
  // ships — as a claim about Apple, so netflix.com's unsupported-browser page
  // came back with "Page presents the brand apple" and 18/100 for a tag that
  // says nothing about Apple. Scripts, styles and tags are stripped first, and
  // whole words are matched, before any brand is named.
  const text = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ");
  const visibleLower = text.toLowerCase();
  const brandPattern = (brand: string) => new RegExp(`\\b${brand}\\b`);
  const brandMentions = BRAND_LIST.filter((b) => brandPattern(b).test(visibleLower));

  // Impersonation is a *claim*, not a mention: only a brand in the title or a
  // top-level heading says "this page is that brand". A brand linked in the
  // footer, or listed next to a download button, is recorded as a mention and
  // is not scored.
  const titleLower = title.toLowerCase();
  const headingText = [...html.matchAll(/<h[12]\b[^>]*>([\s\S]{0,300}?)<\/h[12]>/gi)]
    .map((m) => (m[1] ?? "").replace(/<[^>]+>/g, " "))
    .join(" ")
    .toLowerCase();
  const brandsClaimed = BRAND_LIST.filter(
    (b) => brandPattern(b).test(titleLower) || brandPattern(b).test(headingText),
  );

  const obfuscated =
    /eval\s*\(\s*(atob|unescape|decodeURIComponent)/i.test(html) ||
    /document\.write\s*\(\s*unescape/i.test(html) ||
    (html.match(/\\x[0-9a-f]{2}/gi) ?? []).length > 50;

  let faviconExternal = false;
  const icon = /<link[^>]*rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']/i.exec(html)?.[1];
  if (icon) {
    try {
      const u = new URL(icon, finalUrl);
      faviconExternal = u.hostname !== finalUrl.hostname;
    } catch {
      /* ignore */
    }
  }

  return {
    title,
    has_password_field: hasPassword,
    has_otp_field: hasOtp,
    has_card_field: hasCard,
    form_action_external: formExternal,
    iframe_count: iframeCount,
    external_script_domains: scriptDomains.size,
    brand_mentions: brandMentions,
    brands_claimed: brandsClaimed,
    hidden_input_count: hiddenInputs,
    obfuscated_script: obfuscated,
    favicon_external: faviconExternal,
    text_length: text.replace(/\s+/g, " ").trim().length,
  };
}

export async function liveScan(rawUrl: string): Promise<LiveScanContext> {
  const target = guardTarget(rawUrl);
  const degraded: string[] = [];
  const started = Date.now();

  const fetched = await fetchTarget(target);
  const finalUrl = fetched.finalUrl;
  const status = fetched.status;
  const html = fetched.html;
  const server = fetched.server;
  const contentType = fetched.contentType;
  let tls: LiveScanContext["tls"] = target.protocol === "https:" ? "unavailable" : "none";

  if (fetched.failure) {
    degraded.push(describeFetchFailureSentence(fetched));
  } else if (finalUrl.protocol === "https:") {
    // A completed fetch over TLS means the certificate chain was accepted by
    // this client; a later error message would say so if it had not been.
    tls = "valid";
  }

  const responseTime = Date.now() - started;

  const [rdap, aRecords, nsRecords] = await Promise.all([
    rdapLookup(finalUrl.hostname),
    dnsLookup(finalUrl.hostname, "A"),
    dnsLookup(registrable(finalUrl.hostname), "NS"),
  ]);

  if (rdap.age === "unavailable") {
    degraded.push("RDAP registration date unavailable for this TLD; domain age not scored.");
  }
  if (aRecords === "unavailable") {
    degraded.push("DNS A record lookup returned no answer.");
  }

  const page = html ? parseHtml(html, finalUrl) : undefined;

  return {
    final_url: finalUrl.toString(),
    redirect_chain: fetched.hops.length,
    redirect_hops: fetched.hops,
    fetch_failure: fetched.failure,
    http_status: status,
    server_header: server,
    content_type: contentType,
    response_time_ms: responseTime,
    tls,
    domain: {
      domain_age_days: rdap.age,
      registrar: rdap.registrar,
      nameservers: nsRecords,
      dns_a_records: aRecords,
      certificate: tls === "valid" ? "valid (TLS handshake succeeded)" : "unavailable",
    },
    page,
    degraded,
  };
}
