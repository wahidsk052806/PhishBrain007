import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { firstHttpHref } from "./normalize";

const scanInput = z.object({
  url: z.string().min(3).max(2048),
  safeThreshold: z.number().min(0).max(100).default(30),
  suspiciousThreshold: z.number().min(0).max(100).default(70),
});

export const liveAnalyzeUrl = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => scanInput.parse(input))
  .handler(async ({ data }) => {
    const { runLiveAnalysis } = await import("./live-analyze.server");
    const result = await runLiveAnalysis(data.url, {
      safe: data.safeThreshold,
      suspicious: data.suspiciousThreshold,
    });
    // Serialize to plain JSON so the RPC boundary stays structurally typed.
    return JSON.stringify(result);
  });

// `nullish`, not `optional`: callers that model “absent” as `null` (the browser
// extension's parser) must not get a 400 for a message with no Reply-To.
const emailInput = z.object({
  from: z.string().max(320).nullish(),
  reply_to: z.string().max(320).nullish(),
  display_name: z.string().max(320).nullish(),
  subject: z.string().max(1000).nullish(),
  body: z.string().max(50000).nullish(),
  links: z.array(z.string().max(2048)).max(50).default([]),
  has_attachments: z.boolean().nullish(),
  has_quoted_content: z.boolean().nullish(),
  safeThreshold: z.number().min(0).max(100).default(30),
  suspiciousThreshold: z.number().min(0).max(100).default(70),
});

/**
 * Email-layer analysis. Header/body/sender signals are scored deterministically;
 * when the message contains links the first one is also scanned live so the
 * URL, domain and webpage layers carry real evidence.
 */
export const liveAnalyzeEmail = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => emailInput.parse(input))
  .handler(async ({ data }) => {
    const { runLiveAnalysis } = await import("./live-analyze.server");
    const { analyzeDemo } = await import("./demo");
    const email = {
      ...(data.from ? { from: data.from } : {}),
      ...(data.reply_to ? { reply_to: data.reply_to } : {}),
      ...(data.display_name ? { display_name: data.display_name } : {}),
      ...(data.subject ? { subject: data.subject } : {}),
      ...(data.body ? { body: data.body } : {}),
      links: data.links,
      ...(data.has_attachments == null ? {} : { has_attachments: data.has_attachments }),
      ...(data.has_quoted_content == null ? {} : { has_quoted_content: data.has_quoted_content }),
    };
    const thresholds = { safe: data.safeThreshold, suspicious: data.suspiciousThreshold };
    // `links` may be bare hrefs (the dashboard form) or `text|href` pairs (the
    // browser extension); only the href can be fetched.
    const firstLink = firstHttpHref(data.links);
    if (firstLink) {
      const result = await runLiveAnalysis(firstLink, thresholds, email);
      return JSON.stringify(result);
    }
    // No link to fetch: score sender/content evidence only.
    const result = analyzeDemo(
      { url: "mailto:" + (data.from ?? "unknown"), email },
      undefined,
      thresholds,
      {
        live: true,
        degraded: [
          "Message contained no http(s) link, so URL, domain and webpage layers had nothing to fetch.",
        ],
      },
    );
    return JSON.stringify(result);
  });
