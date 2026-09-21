import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/phishbrain/AppShell";

export const Route = createFileRoute("/about")({
  head: () => ({
    meta: [
      { title: "About PhishBrain — Architecture and Scope" },
      {
        name: "description",
        content:
          "How PhishBrain combines email, URL, domain and webpage evidence with local LLM reasoning, what is implemented today, and what requires optional local models or datasets.",
      },
      { property: "og:title", content: "About PhishBrain" },
      {
        property: "og:description",
        content:
          "Architecture, pipeline stages, honest scope statement and limitations of the PhishBrain detection system.",
      },
    ],
  }),
  component: AboutPage,
});

const PIPELINE = `CAPTURE
  |
  v
PARSING  ->  PRE-FILTERING (CatBoost / documented fallback)
  |
  v
MULTI-LAYER FEATURE EXTRACTION
  email | url | domain | webpage (+ visual)
  |
  v
FEATURE AGGREGATION -> STRUCTURED PROMPT
  |
  v
LOCAL LLM REASONING (Ollama, open-weight model)
  |
  v
DETERMINISTIC THREAT SCORING (0-100, configurable weights)
  |
  v
EXPLAINABLE REPORT -> USER ALERT -> SOC / SIEM LOG`;

const IMPLEMENTED = [
  ["Browser extension (MV3)", "Implemented — load unpacked from extension/dist"],
  ["URL feature extraction & typosquatting", "Implemented (deterministic, no external service)"],
  ["Domain intelligence (RDAP/DNS/TLS)", 'Implemented — degrades to "unavailable" when offline'],
  ["Webpage / DOM analysis", "Implemented"],
  ["Visual similarity", "Implemented — requires Playwright + a local reference set"],
  ["Email analysis", "Implemented for DOM-visible webmail fields"],
  ["SPF / DKIM / DMARC", "Only when raw headers are supplied; otherwise reported as unavailable"],
  ["CatBoost pre-filter", "Interface implemented; no trained model ships with the repo"],
  ["Local LLM reasoning", "Implemented — requires Ollama running locally"],
  ["Threat scoring & explanation", "Implemented (deterministic application code)"],
  ["History / SOC logging", "Implemented — PostgreSQL, in-memory fallback"],
  ["Detection accuracy figures", "Not evaluated — no dataset has been evaluated in this repo"],
];

function AboutPage() {
  return (
    <AppShell title="About PhishBrain" description="Architecture, scope and honest limitations">
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            What this is
          </h2>
          <p className="mt-2 text-sm leading-relaxed">
            PhishBrain is an AI-assisted zero-day phishing detection system. A Manifest V3 browser
            extension captures the current page, a local FastAPI backend extracts evidence across
            four layers — email, URL, domain and webpage — and a locally hosted open-weight LLM (via
            Ollama) reasons over that structured evidence. The final 0–100 threat score is computed
            by deterministic application code, not by the model.
          </p>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
            No proprietary AI APIs, API keys or paid services are used anywhere in the system.
          </p>
        </section>

        <section className="panel p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Pipeline
          </h2>
          <pre className="mt-2 overflow-auto rounded-md bg-background/70 p-3 font-mono text-xs leading-relaxed">
            {PIPELINE}
          </pre>
        </section>

        <section className="panel p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Implemented vs. requires local dependency
          </h2>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted-foreground">
                  <th className="py-2 pr-4 font-medium">Capability</th>
                  <th className="py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {IMPLEMENTED.map(([cap, status]) => (
                  <tr key={cap} className="border-b border-border/60 last:border-0">
                    <td className="py-2 pr-4">{cap}</td>
                    <td className="py-2 text-muted-foreground">{status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Limitations
          </h2>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            <li>
              No accuracy, precision, recall or zero-day detection rate is claimed. Until a real
              dataset is evaluated with the time-split methodology in <code>ml/evaluation</code>,
              every metric reads &quot;Not evaluated&quot;.
            </li>
            <li>
              Email authentication (SPF/DKIM/DMARC) is not observable from a webmail DOM and is
              reported as &quot;Not available from browser context&quot; unless raw headers are
              supplied.
            </li>
            <li>
              Screenshot capture and visual similarity require Playwright in the backend container
              and a local reference hash set; otherwise the visual layer reports unavailable.
            </li>
            <li>
              LLM output is validated and constrained; the model can only shift the score within a
              bounded range and never sets it directly. Private chain-of-thought is never displayed.
            </li>
            <li>Demo Mode results are synthetic and always labelled DEMO DATA.</li>
          </ul>
        </section>
      </div>
    </AppShell>
  );
}
