/**
 * Server-only glue: run a real network scan of a target URL and feed the
 * observed evidence into the deterministic scoring engine.
 */

import { analyzeDemo, DEFAULT_WEIGHTS } from "./demo";
import { liveScan } from "./live.server";
import type { DemoEmailContext } from "./demo";
import type { AnalysisResult } from "./types";

export async function runLiveAnalysis(
  rawUrl: string,
  thresholds = { safe: 30, suspicious: 70 },
  email?: DemoEmailContext,
): Promise<AnalysisResult> {
  const scan = await liveScan(rawUrl);

  const result = analyzeDemo(
    {
      url: scan.final_url,
      ...(email ? { email } : {}),
      domain: {
        domain_age_days: scan.domain.domain_age_days,
        registrar: scan.domain.registrar,
        ...(scan.domain.nameservers === "unavailable"
          ? {}
          : { nameservers: scan.domain.nameservers }),

        certificate: scan.domain.certificate,
      },
      ...(scan.page
        ? {
            page: {
              title: scan.page.title,
              has_password_field: scan.page.has_password_field,
              has_otp_field: scan.page.has_otp_field,
              has_card_field: scan.page.has_card_field,
              form_action_external: scan.page.form_action_external,
              iframe_count: scan.page.iframe_count,
              external_script_domains: scan.page.external_script_domains,
              brand_mentions: scan.page.brand_mentions,
            },
          }
        : {}),
    },
    DEFAULT_WEIGHTS,
    thresholds,
    {
      live: true,
      degraded: scan.degraded,
      networkEvidence: {
        final_url: scan.final_url,
        redirected: scan.redirect_chain > 0,
        http_status: scan.http_status,
        server_header: scan.server_header ?? "unavailable",
        content_type: scan.content_type ?? "unavailable",
        response_time_ms: scan.response_time_ms,
        tls: scan.tls,
        dns_a_records: scan.domain.dns_a_records,
        scanned_at: new Date().toISOString(),
      },
    },
  );

  // Extra live-only page signals that the shared scorer does not model.
  if (scan.page) {
    const extra: string[] = [];
    if (scan.page.obfuscated_script) extra.push("Page contains obfuscated / encoded JavaScript");
    if (scan.page.hidden_input_count > 5)
      extra.push(`Page contains ${scan.page.hidden_input_count} hidden input fields`);
    if (scan.page.favicon_external) extra.push("Favicon is loaded from a third-party domain");
    if (scan.page.text_length < 200 && scan.page.has_password_field)
      extra.push("Login page has almost no readable content (typical of cloned kits)");
    if (extra.length) {
      const layer = result.layers.webpage;
      layer.indicators = [
        ...layer.indicators.filter((i) => !i.startsWith("No credential")),
        ...extra,
      ];
      layer.risk = Math.min(100, layer.risk + extra.length * 6);
    }
    result.layers.webpage.evidence = {
      ...result.layers.webpage.evidence,
      page_title: scan.page.title || "unavailable",
      hidden_input_count: scan.page.hidden_input_count,
      obfuscated_script: scan.page.obfuscated_script,
      favicon_external: scan.page.favicon_external,
      visible_text_length: scan.page.text_length,
    };
  }

  return result;
}
