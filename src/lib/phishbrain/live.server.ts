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
        brand_mentions: string[];
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

  const brandMentions = BRAND_LIST.filter((b) => lower.includes(b));
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

  const text = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ");

  return {
    title,
    has_password_field: hasPassword,
    has_otp_field: hasOtp,
    has_card_field: hasCard,
    form_action_external: formExternal,
    iframe_count: iframeCount,
    external_script_domains: scriptDomains.size,
    brand_mentions: brandMentions,
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

  let finalUrl = target;
  let status: number | "unavailable" = "unavailable";
  let html = "";
  let server: string | null = null;
  let contentType: string | null = null;
  let tls: LiveScanContext["tls"] = target.protocol === "https:" ? "unavailable" : "none";

  try {
    const res = await withTimeout(
      (signal) =>
        fetch(target.toString(), {
          signal,
          redirect: "follow",
          headers: {
            "user-agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36 PhishBrain/1.0",
            accept: "text/html,application/xhtml+xml",
          },
        }),
      12_000,
    );
    status = res.status;
    server = res.headers.get("server");
    contentType = res.headers.get("content-type");
    try {
      finalUrl = new URL(res.url || target.toString());
    } catch {
      /* keep target */
    }
    if (finalUrl.protocol === "https:") tls = "valid";
    const body = await res.text();
    html = body.slice(0, 800_000);
  } catch (err) {
    degraded.push(
      `Page fetch failed (${err instanceof Error ? err.message : "network error"}); webpage layer unavailable.`,
    );
    if (target.protocol === "https:") tls = "unavailable";
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
    redirect_chain: finalUrl.toString() === target.toString() ? 0 : 1,
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
