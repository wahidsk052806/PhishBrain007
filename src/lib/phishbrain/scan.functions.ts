import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

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

const emailInput = z.object({
  from: z.string().max(320).optional(),
  reply_to: z.string().max(320).optional(),
  display_name: z.string().max(320).optional(),
  subject: z.string().max(1000).optional(),
  body: z.string().max(50000).optional(),
  links: z.array(z.string().max(2048)).max(50).default([]),
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
    };
    const thresholds = { safe: data.safeThreshold, suspicious: data.suspiciousThreshold };
    const firstLink = data.links.find((l) => /^https?:\/\//i.test(l));
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
