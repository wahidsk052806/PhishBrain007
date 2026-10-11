import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { FlaskConical, Loader2, Mail, ScanSearch } from "lucide-react";
import { AppShell } from "@/components/phishbrain/AppShell";
import { AnalysisReport } from "@/components/phishbrain/AnalysisReport";
import { api, BackendRejectedError, BackendUnavailableError } from "@/lib/phishbrain/api";
import { analyzeDemo, DEMO_SAMPLES, saveDemoAnalysis } from "@/lib/phishbrain/demo";
import { normalizeTargetInput } from "@/lib/phishbrain/normalize";
import type { DemoSample } from "@/lib/phishbrain/demo";
import { liveAnalyzeUrl, liveAnalyzeEmail } from "@/lib/phishbrain/scan.functions";
import type { AnalysisResult } from "@/lib/phishbrain/types";
import { usePhishbrainSettings } from "@/lib/phishbrain/usePhishbrainSettings";

export const Route = createFileRoute("/analysis/")({
  head: () => ({
    meta: [
      { title: "Analyze a URL — PhishBrain" },
      {
        name: "description",
        content:
          "Run the PhishBrain multi-layer pipeline on a URL: URL, domain, webpage and email evidence combined with local LLM reasoning and explainable 0-100 threat scoring.",
      },
      { property: "og:title", content: "Analyze a URL — PhishBrain" },
      {
        property: "og:description",
        content:
          "Multi-layer phishing analysis with explainable 0-100 threat scoring, running entirely on local open-source components.",
      },
    ],
  }),
  component: AnalyzePage,
});

function AnalyzePage() {
  const { settings } = usePhishbrainSettings();
  const navigate = useNavigate();
  const scanLive = useServerFn(liveAnalyzeUrl);
  const scanEmail = useServerFn(liveAnalyzeEmail);
  const [mode, setMode] = useState<"url" | "email">("url");
  const [email, setEmail] = useState({
    from: "",
    reply_to: "",
    display_name: "",
    subject: "",
    body: "",
  });
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  // Id of the demo sample currently loaded into the form, if any.
  const [activeDemo, setActiveDemo] = useState<string | null>(null);

  // While a sample is loaded the form is a *demo* form: submitting it re-scores
  // the synthetic sample offline instead of sending a hostname that cannot
  // answer. The sample domains are unregistered or reserved, so a live scan
  // could only ever come back as a DNS failure — which is exactly how the
  // prompt-injection sample managed to look like a backend outage.
  const loadedSample = activeDemo ? (DEMO_SAMPLES.find((s) => s.id === activeDemo) ?? null) : null;

  function runDemoSample(sample: DemoSample) {
    setBusy(true);
    setError(null);
    const demo = analyzeDemo(sample);
    saveDemoAnalysis(demo);
    setResult(demo);
    setNotice(
      `DEMO DATA — synthetic sample scored offline (${sample.label}). No request left this browser.`,
    );
    setBusy(false);
  }

  function loadSample(sample: DemoSample) {
    setActiveDemo(sample.id);
    if (sample.kind === "email") {
      setMode("email");
      setEmail({
        from: sample.email?.from ?? "",
        reply_to: sample.email?.reply_to ?? "",
        display_name: sample.email?.display_name ?? "",
        subject: sample.email?.subject ?? "",
        body: sample.email?.body ?? "",
      });
    } else {
      setUrl(sample.url);
    }
    runDemoSample(sample);
  }

  /** Editing any input detaches the loaded sample, so the next submit is live. */
  function editEmail(patch: Partial<typeof email>) {
    setEmail((prev) => ({ ...prev, ...patch }));
    setActiveDemo(null);
  }

  async function run(rawTarget: string, options: { live?: boolean } = {}) {
    // Normalise at the boundary: `hianime.to` is what people type, and sending
    // it verbatim made the backend refuse the whole request for having an empty
    // scheme. Both the backend and the built-in scanner receive the absolute
    // URL, and the input box is updated so the operator can see what was
    // actually scanned.
    const target = normalizeTargetInput(rawTarget);
    if (!target) return;

    // A loaded demo sample stays offline unless a live scan is asked for
    // explicitly.
    if (!options.live && loadedSample && loadedSample.url === target) {
      runDemoSample(loadedSample);
      return;
    }
    if (target !== rawTarget.trim()) setUrl(target);

    setBusy(true);
    setError(null);
    setNotice(null);
    setResult(null);

    // 1. Self-hosted FastAPI backend (full pipeline incl. Ollama + Playwright).
    try {
      const res = await api.analyzeUrl(target);
      setResult(res);
      setBusy(false);
      return;
    } catch (err) {
      // The backend answered and refused the target (bad scheme, unresolvable
      // host, a guard decision). That is an answer, not an outage: report the
      // backend's own reason instead of silently re-scanning without the ML
      // pre-filter, LLM reasoning or screenshot layers.
      if (err instanceof BackendRejectedError) {
        // A guard refusal is an answer, not an outage. An unresolvable host is
        // the common case and has a concrete, user-fixable cause, so say that
        // instead of quoting the raw guard message.
        const unresolved = /DNS resolution failed for ([^\s:]+)/i.exec(err.detail);
        setError(
          unresolved
            ? `This host does not resolve — the DNS lookup for ${unresolved[1]} failed, so nothing was fetched and no layer could be evaluated. Check the domain for typos: reserved documentation names such as example.org serve no subdomains, and unregistered domains answer nothing.`
            : `The backend refused this target: ${err.detail} (HTTP ${err.status}). No report was produced — the request was stopped before any layer ran, and the built-in scanner is not used as a silent substitute because it cannot produce the ML pre-filter, LLM or visual evidence.`,
        );
        return;
      }
      const detail = err instanceof BackendUnavailableError ? err.detail : String(err);
      // 2. Built-in live scan engine: real fetch, DNS, RDAP and DOM parsing.
      try {
        const raw = await scanLive({
          data: {
            url: target,
            safeThreshold: settings.safeThreshold,
            suspiciousThreshold: settings.suspiciousThreshold,
          },
        });
        const live = JSON.parse(raw as unknown as string) as AnalysisResult;
        saveDemoAnalysis(live);
        setResult(live);
        setNotice(
          `LIVE SCAN (REDUCED LAYERS) — the FastAPI backend could not be reached (${detail}), so this result came from the built-in scanner: real HTTP fetch, DNS, RDAP and DOM analysis. The ML pre-filter, LLM reasoning and screenshot/brand-clone layers all live in the backend, so none of them were applied to this score.`,
        );
      } catch (liveErr) {
        const liveDetail = liveErr instanceof Error ? liveErr.message : String(liveErr);
        if (settings.demoMode) {
          const demo = analyzeDemo({ url: target });
          saveDemoAnalysis(demo);
          setResult(demo);
          setError(
            `Live scan failed (${liveDetail}). Demo Mode produced this DEMO DATA result from URL features only.`,
          );
        } else {
          setError(`Analysis failed. Backend: ${detail}. Live scan: ${liveDetail}`);
        }
      }
    } finally {
      setBusy(false);
    }
  }

  async function runEmail() {
    // A loaded email sample is synthetic and scored offline; its links are
    // demonstrations, not targets to fetch.
    if (loadedSample && loadedSample.kind === "email") {
      runDemoSample(loadedSample);
      return;
    }

    setBusy(true);
    setError(null);
    setNotice(null);
    setResult(null);
    try {
      const links = Array.from(new Set(email.body.match(/https?:\/\/[^\s<>"')]+/gi) ?? [])).slice(
        0,
        50,
      );
      const raw = await scanEmail({
        data: {
          from: email.from || undefined,
          reply_to: email.reply_to || undefined,
          display_name: email.display_name || undefined,
          subject: email.subject || undefined,
          body: email.body || undefined,
          links,
          safeThreshold: settings.safeThreshold,
          suspiciousThreshold: settings.suspiciousThreshold,
        },
      });
      const res = JSON.parse(raw as unknown as string) as AnalysisResult;
      saveDemoAnalysis(res);
      setResult(res);
      setNotice(
        links.length
          ? `LIVE EMAIL SCAN — sender and content scored, and the first link (${links[0]}) was fetched for URL, domain and webpage evidence.`
          : "LIVE EMAIL SCAN — sender and content scored. The message contained no link to fetch.",
      );
    } catch (err) {
      setError(`Email analysis failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  }

  const field =
    "w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring";

  return (
    <AppShell
      title="Analyze"
      description="Run the full CAPTURE → PARSE → PRE-FILTER → MULTI-LAYER → LLM → SCORE pipeline"
    >
      <div className="mb-3 flex gap-2">
        {(
          [
            ["url", "URL / website", ScanSearch],
            ["email", "Email message", Mail],
          ] as const
        ).map(([id, label, Icon]) => (
          <button
            key={id}
            type="button"
            onClick={() => setMode(id)}
            className={`inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm font-medium ${
              mode === id
                ? "border-primary bg-primary/10 text-primary"
                : "border-border bg-secondary text-muted-foreground hover:bg-accent"
            }`}
          >
            <Icon aria-hidden="true" className="size-4" /> {label}
          </button>
        ))}
      </div>

      {mode === "email" ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void runEmail();
          }}
          className="panel grid gap-3 p-4"
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-xs text-muted-foreground">
              From address
              <input
                value={email.from}
                onChange={(e) => editEmail({ from: e.target.value })}
                placeholder="billing@secure-paypa1.com"
                className={field}
              />
            </label>
            <label className="text-xs text-muted-foreground">
              Reply-To address
              <input
                value={email.reply_to}
                onChange={(e) => editEmail({ reply_to: e.target.value })}
                placeholder="recover@mail.ru"
                className={field}
              />
            </label>
            <label className="text-xs text-muted-foreground">
              Display name
              <input
                value={email.display_name}
                onChange={(e) => editEmail({ display_name: e.target.value })}
                placeholder="PayPal Support"
                className={field}
              />
            </label>
            <label className="text-xs text-muted-foreground">
              Subject
              <input
                value={email.subject}
                onChange={(e) => editEmail({ subject: e.target.value })}
                placeholder="Your account will be suspended"
                className={field}
              />
            </label>
          </div>
          <label className="text-xs text-muted-foreground">
            Message body (paste the full text — links inside are extracted and scanned live)
            <textarea
              value={email.body}
              onChange={(e) => editEmail({ body: e.target.value })}
              rows={8}
              className={field}
            />
          </label>
          <button
            type="submit"
            disabled={busy || (!email.body.trim() && !email.from.trim())}
            className="inline-flex w-fit items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
          >
            {busy ? (
              <Loader2 aria-hidden="true" className="size-4 animate-spin" />
            ) : (
              <Mail aria-hidden="true" className="size-4" />
            )}
            {loadedSample?.kind === "email" ? "Re-run demo sample" : "Analyze email"}
          </button>
          {loadedSample?.kind === "email" ? (
            <p className="flex items-start gap-2 rounded-md border border-suspicious/40 bg-suspicious-soft px-3 py-2 text-xs text-suspicious">
              <FlaskConical aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
              <span>
                <strong className="font-mono">DEMO SAMPLE loaded</strong> — this message is
                synthetic and scored offline, so its links are never fetched. Editing any field
                detaches it and the next submit is a live scan.
              </span>
            </p>
          ) : null}
        </form>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (url.trim()) void run(url.trim());
          }}
          className="panel flex flex-wrap items-center gap-2 p-4"
        >
          <label htmlFor="target-url" className="sr-only">
            URL to analyze
          </label>
          <input
            id="target-url"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              // Any edit detaches the loaded sample: the next submit is live.
              if (activeDemo) setActiveDemo(null);
            }}
            onBlur={() => setUrl((value) => (value.trim() ? normalizeTargetInput(value) : value))}
            placeholder="example.com/login or https://example.com/login"
            className="min-w-0 flex-1 rounded-md border border-input bg-background px-3 py-2 font-mono text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
          <button
            type="submit"
            disabled={busy || !url.trim()}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
          >
            {busy ? (
              <Loader2 aria-hidden="true" className="size-4 animate-spin" />
            ) : (
              <ScanSearch aria-hidden="true" className="size-4" />
            )}
            Analyze
          </button>
          {loadedSample && loadedSample.kind !== "email" ? (
            <p className="flex w-full flex-wrap items-center gap-x-1.5 gap-y-1 text-xs text-suspicious">
              <FlaskConical aria-hidden="true" className="size-3.5 shrink-0" />
              <span>
                <strong className="font-mono">DEMO SAMPLE loaded</strong> — “{loadedSample.label}”
                is synthetic and scored offline. Edit the URL above to detach it, or
              </span>
              <button
                type="button"
                onClick={() => {
                  const sample = loadedSample;
                  setActiveDemo(null);
                  void run(sample.url, { live: true });
                }}
                className="rounded-sm border border-suspicious/40 px-1.5 py-0.5 font-medium underline-offset-2 hover:underline"
              >
                scan this URL live instead
              </button>
            </p>
          ) : null}
        </form>
      )}

      <section className="panel mt-4 p-4">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          <FlaskConical aria-hidden="true" className="size-4" /> Demo samples — DEMO DATA
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Synthetic, safe-to-use examples. No live phishing URLs are contacted.
        </p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {DEMO_SAMPLES.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => loadSample(s)}
              className="rounded-md border border-border bg-secondary/50 p-3 text-left transition-colors hover:bg-accent"
            >
              <span className="block text-sm font-medium">{s.label}</span>
              <span className="mt-1 block text-xs text-muted-foreground">{s.description}</span>
              <span className="mt-1 block truncate font-mono text-[11px] text-primary">
                {s.url}
              </span>
            </button>
          ))}
        </div>
      </section>

      {notice ? (
        <p className="mt-4 rounded-md border border-primary/40 bg-primary/10 px-3 py-2 text-sm text-primary">
          {notice}
        </p>
      ) : null}

      {error ? (
        <p className="mt-4 rounded-md border border-suspicious/40 bg-suspicious-soft px-3 py-2 text-sm text-suspicious">
          {error}
        </p>
      ) : null}

      {result ? (
        <div className="mt-4">
          <div className="mb-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                // Re-run the way this result was produced: a loaded demo
                // sample stays offline, everything else is re-scanned live.
                if (loadedSample && loadedSample.url === result.target) {
                  runDemoSample(loadedSample);
                } else {
                  void run(result.target);
                }
              }}
              className="rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium hover:bg-accent"
            >
              Rescan
            </button>
            {!result.demo ? (
              <button
                type="button"
                onClick={() =>
                  navigate({
                    to: "/analysis/$analysisId",
                    params: { analysisId: result.analysis_id },
                  })
                }
                className="rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium hover:bg-accent"
              >
                Open permalink
              </button>
            ) : null}
          </div>
          <AnalysisReport result={result} />
        </div>
      ) : null}
    </AppShell>
  );
}
