import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

/**
 * Hosted email-layer analysis endpoint (serverless — no FastAPI required).
 *
 * Mirrors the dashboard's `liveAnalyzeEmail` server function and the
 * extension's email flow:
 *   - Sender / reply-to / display-name / subject / body signals are scored
 *     deterministically (mismatch, brand impersonation, urgency, credential
 *     requests, prompt-injection text).
 *   - When the message contains http(s) links the first one is live-scanned
 *     (fetch + redirect chain + DNS + RDAP + HTML signals) so URL, domain and
 *     webpage layers carry real evidence.
 *
 * POST {"from": "...", "reply_to": "...", "display_name": "...",
 *       "subject": "...", "body": "...", "links": ["https://..."]}
 */
const bodySchema = z.object({
  from: z.string().max(320).optional(),
  reply_to: z.string().max(320).optional(),
  display_name: z.string().max(320).optional(),
  subject: z.string().max(1000).optional(),
  body: z.string().max(50000).optional(),
  links: z.array(z.string().max(2048)).max(50).optional(),
  safeThreshold: z.number().min(0).max(100).optional(),
  suspiciousThreshold: z.number().min(0).max(100).optional(),
});

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

export const Route = createFileRoute("/api/public/email-scan")({
  server: {
    handlers: {
      OPTIONS: async () => new Response(null, { status: 204, headers: cors }),
      POST: async ({ request }) => {
        let parsed;
        try {
          parsed = bodySchema.parse(await request.json());
        } catch {
          return new Response(JSON.stringify({ error: "Invalid request body" }), {
            status: 400,
            headers: cors,
          });
        }

        const { from, reply_to, display_name, subject, body, links } = parsed;
        const thresholds = {
          safe: parsed.safeThreshold ?? 30,
          suspicious: parsed.suspiciousThreshold ?? 70,
        };
        const email = {
          ...(from ? { from } : {}),
          ...(reply_to ? { reply_to } : {}),
          ...(display_name ? { display_name } : {}),
          ...(subject ? { subject } : {}),
          ...(body ? { body } : {}),
          links: links ?? [],
        };

        try {
          const { runLiveAnalysis } = await import("@/lib/phishbrain/live-analyze.server");
          const { analyzeDemo } = await import("@/lib/phishbrain/demo");

          const firstLink = (links ?? []).find((l) => /^https?:\/\//i.test(l));
          let result;
          if (firstLink) {
            result = await runLiveAnalysis(firstLink, thresholds, email);
          } else {
            // No link to fetch: score sender/content evidence only.
            result = analyzeDemo(
              { url: "mailto:" + (from ?? "unknown"), email },
              undefined,
              thresholds,
              {
                live: true,
                degraded: [
                  "Message contained no http(s) link, so URL, domain and webpage layers had nothing to fetch.",
                ],
              },
            );
          }
          return new Response(JSON.stringify(result), { status: 200, headers: cors });
        } catch (err) {
          return new Response(
            JSON.stringify({ error: err instanceof Error ? err.message : "Email scan failed" }),
            { status: 502, headers: cors },
          );
        }
      },
    },
  },
});
