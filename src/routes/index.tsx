import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  /**
   * The root is only a doorway, but it still has to carry the extension's deep
   * link: an install that linked `/?url=…` (older builds linked `/?analysis_id=…`)
   * landed on the dashboard and lost the page that was just scanned. Forwarding
   * the target keeps such links useful instead of silently discarding them.
   */
  validateSearch: (search: Record<string, unknown>): { url?: string } => {
    const raw = search["url"];
    const url = typeof raw === "string" && raw.trim() ? raw.trim() : undefined;
    return url === undefined ? {} : { url };
  },
  beforeLoad: ({ search }) => {
    if (search.url) throw redirect({ to: "/analysis", search: { url: search.url } });
    throw redirect({ to: "/dashboard" });
  },
});
