import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  BellRing,
  BrainCircuit,
  FlaskConical,
  History,
  Info,
  LayoutDashboard,
  Settings,
  ShieldCheck,
  Wifi,
  WifiOff,
} from "lucide-react";
import type { ReactNode } from "react";
import type { HealthStatus } from "@/lib/phishbrain/types";
import { api } from "@/lib/phishbrain/api";
import { useBackendEndpoint } from "@/lib/phishbrain/useBackendEndpoint";
import { usePhishbrainSettings } from "@/lib/phishbrain/usePhishbrainSettings";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/analysis", label: "Analyze", icon: Activity },
  { to: "/history", label: "History", icon: History },
  { to: "/alerts", label: "Alerts", icon: BellRing },
  { to: "/settings", label: "Settings", icon: Settings },
  { to: "/about", label: "About", icon: Info },
] as const;

/**
 * Which subsystems the health payload reports as down.
 *
 * `status: "degraded"` on its own was a dead end: the badge said the backend
 * was degraded and nothing on the page said why. The API already names each
 * dependency, so the badge names the broken ones too.
 */
function degradedSubsystems(health: HealthStatus): { label: string; detail: string }[] {
  const down: { label: string; detail: string }[] = [];
  if (health.database !== "ok") {
    down.push({
      label: "database",
      detail: `The ${health.database_backend ?? "configured"} database cannot be reached: analyses are still scored, but they are not saved, so History and Alerts stay empty.`,
    });
  }
  if (health.cache !== "ok") {
    down.push({
      label: "cache",
      detail: `The ${health.cache_backend ?? "configured"} cache did not answer, so every scan re-runs the whole pipeline.`,
    });
  }
  if (health.ollama !== "ok") {
    down.push({
      label: "local LLM",
      detail:
        health.ollama === "unknown"
          ? "The Ollama reachability check did not run."
          : "Ollama is unreachable, so scans fall back to the deterministic assessment.",
    });
  }
  return down;
}

function BackendStatus() {
  const { settings } = usePhishbrainSettings();
  // Which engine serves this browser is resolved by probing, not assumed from
  // the page origin: a dashboard opened over the LAN now finds the backend on
  // the machine serving the page and reports it as online, instead of calling
  // the visitor's own `localhost` and labelling the whole deployment "hosted".
  const { resolution, isLoading: resolving } = useBackendEndpoint();
  const engine = resolution?.engine;
  const backendUrl = resolution?.url ?? settings.backendUrl;
  const { data, isError, isLoading } = useQuery({
    queryKey: ["health", backendUrl],
    queryFn: () => api.health(),
    retry: false,
    enabled: engine === "backend",
    refetchInterval: 30_000,
  });

  const online = !!data && !isError;
  const degraded = data ? degradedSubsystems(data) : [];

  if (!engine || resolving) {
    return (
      <div
        className="flex items-center gap-2 rounded-md border border-border bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground"
        title={`Probing ${resolution?.tried.map((t) => t.url).join(", ") || settings.backendUrl} for a PhishBrain backend.`}
      >
        <Activity aria-hidden="true" className="size-3.5" />
        <span className="font-mono">checking backend…</span>
      </div>
    );
  }

  if (engine !== "backend") {
    return (
      <div
        className="flex items-center gap-2 rounded-md border border-safe/40 bg-safe-soft px-2.5 py-1 text-xs font-medium text-safe"
        title={`No backend answered at ${resolution?.tried.map((t) => t.url).join(" or ")}. ${engine === "hosted" ? "This deployment scans with its own server engine (HTTP fetch, DNS-over-HTTPS, RDAP, DOM analysis)." : "Scans use the built-in browser scanner."}`}
      >
        <Activity aria-hidden="true" className="size-3.5" />
        <span className="font-mono">
          {engine === "hosted" ? "hosted engine" : "built-in scanner"}
        </span>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-md border px-2.5 py-1 text-xs font-medium",
        online
          ? "border-safe/40 bg-safe-soft text-safe"
          : "border-border bg-muted text-muted-foreground",
      )}
      title={
        !online
          ? `Backend stopped answering at ${backendUrl}`
          : degraded.length
            ? `PhishBrain backend reachable at ${backendUrl}, but degraded:\n${degraded
                .map((d) => `• ${d.label}: ${d.detail}`)
                .join("\n")}`
            : `PhishBrain backend reachable at ${backendUrl} — CatBoost pre-filter, local LLM verdict and screenshot layer active.`
      }
    >
      {online ? (
        <Wifi aria-hidden="true" className="size-3.5" />
      ) : (
        <WifiOff aria-hidden="true" className="size-3.5" />
      )}
      <span className="font-mono">
        {isLoading
          ? "checking backend…"
          : !online
            ? "backend offline"
            : degraded.length
              ? `backend degraded · ${degraded.map((d) => d.label).join(", ")}`
              : "backend ok"}
      </span>
    </div>
  );
}

export function AppShell({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const { settings } = usePhishbrainSettings();

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar px-3 py-4 md:flex">
        <Link to="/dashboard" className="mb-6 flex items-center gap-2 px-2">
          <span className="grid size-9 place-items-center rounded-md bg-primary/15 text-primary">
            <BrainCircuit aria-hidden="true" className="size-5" />
          </span>
          <span>
            <span className="block text-sm font-bold tracking-tight text-sidebar-foreground">
              PhishBrain
            </span>
            <span className="block font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              zero-day defence
            </span>
          </span>
        </Link>

        <nav className="flex flex-col gap-1">
          {NAV.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              className="flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-sidebar-foreground/80 transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              activeProps={{
                className:
                  "bg-sidebar-accent text-sidebar-accent-foreground font-medium border-l-2 border-primary",
              }}
            >
              <Icon aria-hidden="true" className="size-4" />
              {label}
            </Link>
          ))}
        </nav>

        <div className="mt-auto space-y-2 px-1 pt-4">
          {settings.demoMode ? (
            <p className="flex items-start gap-2 rounded-md border border-suspicious/30 bg-suspicious-soft p-2 text-[11px] leading-snug text-suspicious">
              <FlaskConical aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
              <span>
                <strong className="font-mono">DEMO FALLBACK ON</strong> — when the backend and the
                built-in scanner both fail, the result is computed locally and labelled DEMO DATA.
                Live scans still use the backend whenever it answers.
              </span>
            </p>
          ) : null}
          <p className="flex items-center gap-1.5 px-1 text-[11px] text-muted-foreground">
            <ShieldCheck aria-hidden="true" className="size-3.5" />
            Local-only. No proprietary AI APIs.
          </p>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 border-b border-border bg-background/85 backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 md:px-6">
            <div className="min-w-0">
              <h1 className="truncate text-lg font-semibold tracking-tight">{title}</h1>
              {description ? (
                <p className="truncate text-sm text-muted-foreground">{description}</p>
              ) : null}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {actions}
              <BackendStatus />
            </div>
          </div>
          <nav className="flex gap-1 overflow-x-auto border-t border-border px-2 py-1.5 md:hidden">
            {NAV.map(({ to, label, icon: Icon }) => (
              <Link
                key={to}
                to={to}
                className="flex items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-1.5 text-xs text-muted-foreground"
                activeProps={{ className: "bg-accent text-accent-foreground font-medium" }}
              >
                <Icon aria-hidden="true" className="size-3.5" />
                {label}
              </Link>
            ))}
          </nav>
        </header>
        <main className="px-4 py-5 md:px-6 md:py-6">{children}</main>
      </div>
    </div>
  );
}
