import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

const bodySchema = z.object({
  url: z.string().min(3).max(2048),
  safeThreshold: z.number().min(0).max(100).optional(),
  suspiciousThreshold: z.number().min(0).max(100).optional(),
});

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

export const Route = createFileRoute("/api/public/scan")({
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

        try {
          const { runLiveAnalysis } = await import("@/lib/phishbrain/live-analyze.server");
          const result = await runLiveAnalysis(parsed.url, {
            safe: parsed.safeThreshold ?? 30,
            suspicious: parsed.suspiciousThreshold ?? 70,
          });
          return new Response(JSON.stringify(result), { status: 200, headers: cors });
        } catch (err) {
          return new Response(
            JSON.stringify({ error: err instanceof Error ? err.message : "Scan failed" }),
            { status: 502, headers: cors },
          );
        }
      },
    },
  },
});
