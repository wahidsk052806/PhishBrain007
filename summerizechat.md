# PhishBrain — Development Log & Project Dossier

**Purpose of this file.** A single, detailed record of what was built in this project, in what
order, why each decision was made, what broke and how it was fixed, and what the numbers actually
are — written so it can be lifted straight into slides, a report, a viva, or a handover.

**How it was reconstructed.** The repository does not store chat transcripts, so this log is
assembled from the project's own primary evidence: the 8-entry git history (with full commit
bodies), the working tree and its diff, `README.md`, `workingexplaination.txt`,
`deploy/README.md`, the ML gate reports, the test suites, and the diagnostics run on
**2026-10-28**. Where something is a reconstruction of intent rather than a recorded artefact it is
labelled *(reconstructed)*. Everything in **§6 Verification** was re-run and is quoted from the
actual output.

**Reading paths**

| If you need to… | Read |
| --- | --- |
| Give a 5-minute talk | §0, §2.1, §3.1, §8.3 |
| Build a 12-slide deck | §8.1 + the tables in §6 |
| Write a report chapter | §2, §5, §9 |
| Explain the "Backend unavailable" screenshot | §4 |
| Defend the design in questions | §8.4 |
| Operate or demo it | §10 |

---

## 0. Executive summary

PhishBrain is a **privacy-first, explainable phishing detector** for web pages, URLs and email. It
combines four deterministic evidence layers (URL, domain, rendered page, email) with a trained
**CatBoost pre-filter**, a **local LLM verdict** (`llama3.2:3b` via Ollama) and a
**rendered-screenshot brand-clone comparison**, producing a 0–100 threat score that always ships
with the evidence behind it.

It runs entirely on infrastructure you own: no Google Safe Browsing, no VirusTotal, no OpenAI, no
third-party threat API. That is what makes the privacy claim true rather than marketing.

It ships as three interoperable pieces — a **FastAPI backend**, a **TanStack Start dashboard**,
and a **Manifest V3 browser extension** — with three supported deployment shapes (full Docker
Compose stack, dashboard on Cloudflare Workers + backend on a small VM behind a tunnel, or
dashboard-only reduced mode).

**Headline numbers (verified 2026-10-28):**

| Metric | Value |
| --- | --- |
| Backend tests | **254 passed** in 28.4 s (23 modules) |
| Extension tests | **201 passed** in 15 files (52.4 s) |
| Extension typecheck | clean (`tsc --noEmit`, exit 0) |
| Pre-filter zero-day recall | **0.8633** on 7,849 phishing URLs across 5,294 unseen domains |
| Pre-filter precision / ROC-AUC | **0.9982** / **0.9443** |
| Pre-filter cost | **0.0011 ms/sample**, 8.7 ms per batch |
| Time to first verdict | **~5 s** (provisional, streamed) vs ~47 s for the LLM verdict |
| Fast scan (no LLM) | **8.3 s** mean; full scan **~55–62 s** |
| Code size | backend 5,531 py · dashboard 10,987 ts/tsx · extension 7,270 ts/tsx · tests 6,149 · ML 2,886 |
| Commits | 8 (2026-09-22 → 2026-10-11) + a 54-file uncommitted wave |

---

## 1. The project at a glance

### 1.1 The problem

Phishing detection is usually a black box with a number. A user is told "87/100, don't visit" and
cannot see why, cannot audit it, and cannot tell whether the page was even fetched. Meanwhile the
analysis itself normally means shipping every visited URL to somebody else's cloud.

Two failure modes follow:

1. **Opaque verdicts** — unusable for teaching, for a SOC analyst, or for a report.
2. **Privacy leakage** — the defence becomes the surveillance.

### 1.2 The solution

| Principle | Implementation |
| --- | --- |
| Explain, don't assert | Every layer returns `indicators`, raw `evidence`, `notes` and a risk score; the report renders all of it. |
| Never fail silently | A layer that could not run is `unavailable` and named in `degraded`; the LLM falling back is labelled `llm.deterministic_fallback`, never hidden. |
| Local by default | Playwright, CatBoost and Ollama run on your box; the only network calls are to the site being analysed and to public RDAP/DNS. |
| Progressive, not blank | The deterministic verdict appears in ~5 s as a labelled *provisional* score; the LLM verdict replaces it in place. |
| One score, many witnesses | Weighted layers → disclosed pre-filter blend (15 %) → bounded LLM adjustment (±15) → SAFE / SUSPICIOUS / HIGH_RISK. |

### 1.3 Three pitches, three lengths

**One sentence.** PhishBrain explains *why* a page or email is phishing, using four evidence
layers, a CatBoost pre-filter, a local LLM and a screenshot brand comparison — all on your own
hardware.

**Thirty seconds.** Most phishing tools hand you a number from somebody else's cloud. PhishBrain
runs the whole pipeline locally: it fetches and renders the page with Playwright, checks the URL
structure, the domain's registration age and DNS/TLS, the page's credential forms and brand claims,
and — for email — sender/Reply-To mismatches and link-text-vs-destination tricks. A CatBoost model
contributes a disclosed 15 %, a local `llama3.2:3b` adds a written verdict bounded to ±15 points,
and a perceptual-hash comparison against known brand login screens catches clones that have no
malicious string in them at all. Every result is exportable and every degraded layer is named.

**Two minutes.** *(see §8.3 for the full spoken track)*

### 1.4 What makes it different (slide bullets)

- **No third-party threat intelligence** — the privacy claim is architectural, not a policy.
- **Screenshot-based brand-clone detection** — catches pixel-identical fakes that reuse clean
  domains and clean HTML.
- **Honest degradation** — reduced engines announce themselves; scores are never passed off as
  full-pipeline scores.
- **Explainable in the browser** — the popup is a full report (layers, raw evidence, pre-filter,
  LLM, screenshot), not a badge.
- **SOC-ready** — every result can be emitted as a structured event and POSTed to a webhook.
- **Zero-cost deployable** — Workers free tier + an always-free VM + a tunnel; the only unavoidable
  spend is the domain.

---

## 2. Architecture

### 2.1 The three pieces

| Piece | Directory | Role |
| --- | --- | --- |
| Browser extension | `extension/` | MV3 add-on (Chrome/Edge/Firefox). Watches tabs and Gmail/Outlook Web, sends what it sees to an engine, renders badge + banner + in-message card + full popup report. |
| Dashboard | `src/` | TanStack Start app. Manual analysis, history, alerts, settings, exports, and two public `/api/public/*` endpoints so a deployment can scan with **no** backend at all. |
| Backend API | `backend/` | FastAPI. The real pipeline: fetch → Playwright render → RDAP/DNS/TLS → CatBoost → Ollama → score → Postgres, plus SSE streaming. |
| ML tooling | `ml/` | Dataset preparation, gated training, time-split evaluation, calibration, reports. |

### 2.2 Architecture diagram

```text
                      +------------------------------+
                      |  Browser extension (MV3)     |
                      |  popup · banner · mail card  |
                      +--------------+---------------+
                                     |  HTTPS / JSON
                     +---------------+----------------+
                     |                                |
                     v                                v
      +------------------------------+   +------------------------------+
      |  FastAPI backend  :8000      |   |  Dashboard (TanStack Start)  |
      |                              |   |  :8080 / Workers             |
      |  CAPTURE → PARSE →           |   |  /analysis /history          |
      |  PRE-FILTER → LAYERS →       |   |  /alerts  /settings          |
      |  LLM → SCORE                 |   |                              |
      |                              |   |  /api/public/* reduced scan  |
      |  CatBoost · Ollama ·         |   |  (real fetch, DNS, RDAP, DOM)|
      |  Playwright (screenshots)    |   +--------------+---------------+
      +----+----------+----------+---+                  |
           |          |          |                      |
           v          v          v                      |
     +-----------+ +--------+ +--------+                |
     | PostgreSQL| | Valkey | | Ollama |                |
     | (history) | | (cache)| | (LLM)  |                |
     +-----------+ +--------+ +--------+                |
                                                        |
                     served by the same deployment ------+
```

### 2.3 Three deployment shapes

| Shape | What runs where | Full pipeline? |
| --- | --- | --- |
| Docker Compose on one box | dashboard + backend + Postgres + Valkey + Ollama | ✅ everything |
| Dashboard on Cloudflare Workers, backend on a Linux VM behind a tunnel | SSR dashboard, full backend at `api.<domain>` | ✅ everything (recommended for a public site) |
| Dashboard alone | Workers/Nitro only | ❌ reduced: real fetch, DNS-over-HTTPS, RDAP, DOM — no CatBoost, no LLM, no Playwright |

### 2.4 What happens during a scan (numbered, for a slide)

1. **Normalise** — `hianime.to`, `example.com/login`, `//example.com`, `https:/example.com` all
   become absolute URLs before the SSRF guard runs. `javascript:`, `data:`, `file:` are refused by
   name.
2. **SSRF guard** — private/loopback/metadata addresses refused before any fetch.
3. **CAPTURE** — async HTTP fetch with an 8 s connect cap and a browser-like User-Agent; domain
   lookups start *before* the fetch is awaited so they overlap.
4. **PARSE** — HTML → forms, password/OTP fields, iframes, meta refresh, external resources,
   title/heading brand claims, favicon targets.
5. **PRE-FILTER** — CatBoost over URL/email lexical features; contributes 15 % of the base score
   *only* when a trained artifact is deployed.
6. **LAYERS** — URL, domain (RDAP age, DNS, TLS, registrar), webpage (claims vs serving domain),
   email (sender/Reply-To/lookalike/link-text).
7. **VISUAL** — Playwright renders the page; a perceptual hash is compared region-by-region against
   a local reference set of brand login screens; the thumbnail is returned with the report.
8. **LLM** — a bounded digest of the evidence goes to `llama3.2:3b`; structured JSON back
   (`verdict`, `phishing_likelihood`, `confidence`, `key_indicators`, `reasoning_summary`,
   `recommended_action`, `score_adjustment`), validated by Pydantic.
9. **SCORE** — weighted layers → pre-filter blend → LLM clamp → band + confidence + explanation +
   recommended action + SOC event.
10. **PERSIST / STREAM** — stored in Postgres (history/alerts/exports) and, on the streaming
    endpoint, emitted as SSE events: `started`, `layer(s)`, `prefilter`, `provisional`, `llm`,
    `final`.

### 2.5 How the score is produced

```text
layers  = 0.30·url + 0.30·domain + 0.20·webpage + 0.20·email      (weights normalised from config)
score   = (1 − 0.15)·layers + 0.15·catboost                     (PREFILTER_WEIGHT = 0.15)
LLM     = a bounded adjustment (±15) plus a written assessment
verdict = SAFE (<30) · SUSPICIOUS (30–65) · HIGH_RISK (≥65)
```

Three engineering details that matter in a viva:

- **Single-layer floor** — the composite is floored at 90 % of the strongest available layer, so a
  confirmed typosquat stays HIGH_RISK even when the page fetch or RDAP fails.
- **Pre-filter weight is clamped to [0, 0.5]** — a lone lexical score can never drag a clean
  multi-layer analysis into SUSPICIOUS by itself.
- **Confidence is computed, not asserted** —
  `0.5·layer_coverage + 0.3·llm_confidence + 0.2·(1 − degradation_penalty)`.

---

## 3. Timeline of the build

### 3.1 Overview

| # | Date | Theme | Evidence |
| --- | --- | --- | --- |
| 1 | 2026-09-22 | Foundation snapshot: pipeline, dashboard, extension, ML tooling | `b10d200` |
| 2 | 2026-10-11 | Backend correctness: bare hosts, fetch failures, screenshots, retention | `5f62703` |
| 3 | 2026-10-11 | ML honesty: time-ordered split + deployment gate | `ab80a4e` |
| 4 | 2026-10-11 | Dashboard evidence surfaces (pre-filter, screenshot, clear) | `9e46c66` |
| 5 | 2026-10-11 | Extension: explainable report, alerts, visual comparison | `1875a70` |
| 6 | 2026-10-11 | Brand-capture integrity (bot walls) | `8bfff51` |
| 7 | 2026-10-11 | Docs/deploy fix (Node server preset) | `85c9cd8` |
| 8 | 2026-10-11 | Streaming scans (SSE) | `af403f3` |
| 9 | post-`af403f3` | Hardening wave: email, packaging, engine resolution, CORS/DB/LLM budgets | uncommitted working tree |
| 10 | 2026-10-28 | "Backend unavailable" diagnosis and engine-resolution fix | this session |

### 3.2 Phase 1 — Foundation (2026-09-22, `b10d200`)

**Goal.** Put the working tree under version control as a coherent snapshot rather than a folder of
files.

**What exists in that snapshot.** The FastAPI backend with the
`CAPTURE → PARSE → PRE-FILTER → MULTI-LAYER → LLM → SCORE` pipeline; the TanStack dashboard; the
browser extension; and the ML training/evaluation tooling.

**Decision.** Generated artefacts (datasets, trained models, build output, virtualenvs, local
databases) are gitignored — they are reproducible from committed scripts, and committing them would
bloat history and hide the reproduction steps.

**Consequence that shows up later.** No `.cbm` model ships in the repo, so a fresh clone reports
`ml.deterministic_fallback` and *deliberately excludes* the pre-filter from the score rather than
pretending it ran.

### 3.3 Phase 2 — Make the backend tell the truth about failure (`5f62703`)

**Problems.**

- A scheme-less target like `hianime.to` reached the fetch unnormalised and was refused outright —
  the most natural way a person names a site was treated as an attack.
- A page that could not be read produced an empty webpage layer with nothing in `degraded`, so a
  failed fetch was **indistinguishable from a clean page**.
- The Playwright screenshot the visual layer had already captured was thrown away after hashing, so
  the dashboard could describe a comparison but not show it.
- Screenshots that were stored had no expiry.

**Changes.**

- Targets are normalised before the SSRF guard sees them (`backend/app/core/security.py`); both
  dashboard and backend share the rule.
- The fetch outcome is named inside the layer (`status_code`, note about "an error body is the
  server's own notice").
- The captured screenshot is returned, downscaled, in `pixels` or `wireframe` mode.
- Retention: `RETENTION_DAYS` (30) for analyses, `VISUAL_RETENTION_DAYS` (7) for images, plus an
  on-demand sweep and a clear endpoint.

**Why it matters for a demo.** "A failed fetch looks like a clean page" is a security bug, not a UX
bug: it converts ignorance into reassurance.

### 3.4 Phase 3 — Gate the ML model honestly (`ab80a4e`)

**Problem.** The deployment gate passed on a **random** split. A model can look excellent on a
random split and still fail on the time ordering that actually happens in the field — training on
the future and testing on the past.

**Changes.**

- Evaluation uses a **time-ordered, zero-day split** (cutoff `2026-07-02 21:16:31 UTC`), with
  same-domain-as-training rows removed from the test set.
- Two named gate tiers instead of one silently tuned threshold: `strict` (fit to decide alone) and
  `triage` (fit to be one disclosed signal). A rejected candidate leaves the deployed model
  untouched and writes its reasons to `ml/evaluation/reports/train_gate.md`.
- Calibration step so the pre-filter probability can be blended as a weighted score rather than
  only hinted at in the prompt.

**Result.** `triage` **PASS**, `strict` **FAIL** — published, not hidden. That sentence is one of
the strongest slides in the deck (see §6.2).

### 3.5 Phase 4 — Put the evidence on screen (`9e46c66`)

**Problems.** The report showed per-layer evidence but not the pre-filter's contribution, not the
screenshot the visual layer scored, and not what was being retained. Typing `hianime.to` was
refused instead of scanned.

**Changes.** Pre-filter score **and its weight** are rendered; the captured screenshot appears in
the visual card; a one-click "clear stored visual evidence" action; bare hosts normalised before a
scan in the dashboard as well.

### 3.6 Phase 5 — Make the extension explain itself (`1875a70`)

**Problem.** The toolbar popup showed a five-line summary. A verdict you cannot explain from the
browser is a verdict the user has to trust blindly.

**Changes.**

- Full popup report: verdict, indicators, per-layer breakdown with raw evidence, pre-filter card
  (score, weight, gate tier), LLM card, visual card.
- Desktop notification on HIGH_RISK.
- Visual comparison switched from a single hash distance to **region-by-region** comparison against
  brand references.
- Screenshot-style (pixels/wireframe) and retention settings are honoured, with their own clear
  action.

### 3.7 Phase 6 — Don't poison the brand reference set (`8bfff51`)

**Problem.** A brand capture that hit a bot wall (a challenge page, a 403 body) was accepted as a
reference. Every later comparison against that brand would then measure the clone against a
blocked page — silently wrong for every future scan.

**Changes.** Captures are validated for real page content, retried with a persistent browser
profile, and brands that still cannot be captured are recorded in a documented, testable gap list
(`extension/tests/reference-gaps.test.ts`) instead of quietly disappearing.

**Lesson for the report.** A reference dataset needs the same integrity checks as a classifier.

### 3.8 Phase 7 — Fix the self-host path (`85c9cd8`)

The documented Node deploy built with the default Cloudflare preset, which emits a Worker that
cannot answer a request under Node or Bun. The frontend Dockerfile and README now build with the
`node-server` preset. Docs also cover screenshot evidence, retention policy and extension alerts.

### 3.9 Phase 8 — Stream the scan (`af403f3`)

**Problem.** A full scan spends 80–90 % of its wall time in the local LLM, so waiting for one
response meant a blank screen for ~50 s while information that already existed after five sat
unsent.

**Changes.** The pipeline reports each stage through an `on_event` hook;
`POST /api/v1/analyze/url/stream` emits SSE (`started`, `layers`, `prefilter`, a clearly labelled
**provisional** score, `llm`, `final`). The dashboard renders the provisional report immediately and
replaces it in place. A refused target is still a plain 4xx, so a refusal can never look like a
stalled stream.

**Measured (4-core CPU, uncached `example.com`):** `started` 2 s · first layer 3 s ·
**provisional 5 s** · LLM verdict 47 s.

### 3.10 Phase 9 — The hardening wave (uncommitted)

The working tree carries a large, coherent second wave (**54 tracked files changed, +4,243/−988,
plus 30 new paths**). It is best read as four themes:

**(a) Email becomes a first-class surface.** `extension/src/content/email-parser.ts`,
`mail-body.ts`, `mail-links.ts`, `mail-hosts.ts`, `MailVerdictCard.tsx`: Gmail/Outlook Web messages
are parsed for sender, Reply-To, display name, subject, body, `text|href` link pairs, quoted content
and attachments; an **in-message verdict card** replaces the page banner inside a mailbox (the
banner covered the message header and offered to allowlist the mailbox itself). The hosted
`/api/public/email-scan` route was made tolerant of `null` fields — a Gmail reply with no Reply-To
header used to be a 400 because the parser models "absent" as `null`, not `undefined`.

**(b) Packaged, reviewable Firefox build.** `stage-firefox.mjs`, `zip-source.mjs`,
`zip-writer.mjs`, `check-content-bundle.mjs`, `manifest.firefox.json`: a separate `dist-firefox/`
artefact (loading `dist/` in Firefox produces "Error processing service_worker" and a worker that
never starts), source-zip generation for AMO review, and a bundle check that fails if remote code
sneaks in.

**(c) Backend hardening.** New `backend/app/core/concurrency.py` (admission gates for CPU-bound
LLM/visual work, with queue timeouts that degrade to a *labelled* deterministic verdict), CORS
origin handling for `chrome-extension://` / `moz-extension://`, DB URL normalisation, LLM budget
enforcement, and tests for each: `test_cors_origins.py` (20), `test_db_url.py` (2),
`test_llm_budget.py` (3), `test_scan_gates.py` (7), `test_unresolved_host.py` (4).

**(d) Engine resolution in the extension** — the subject of §4. Two URLs had to be typed in for a
hosted setup; shipped defaults pointed at a domain that was never deployed; a release build shipped
a public API origin while the developer's own healthy backend on `127.0.0.1:8000` was ignored.
`extension/src/lib/hosted.ts` and the defaults/probing logic in `services/api.ts` fix all three.

### 3.11 Phase 10 — The "Backend unavailable" incident (2026-10-28, this session)

See §4 for the full investigation. Summary: the panel the user saw was **accurate** — no engine was
running and no hosted endpoint was configured — but the code had four ways to reach that state and
only one of them was the user's fault. The fix makes the reason specific, derives the hosted
endpoint from the dashboard URL, refuses to treat undeployed placeholder hosts as deployments, and
probes loopback even when a public backend URL is stored.

---

## 4. Incident deep-dive: "Backend unavailable"

### 4.1 The symptom, exactly as the popup rendered it

> **PhishBrain** — zero-day defence — **Backend unavailable**
>
> No scan engine is reachable. No local backend is running and no hosted endpoint is configured.
> Start the backend (`uvicorn app.main:app --port 8000`) or deploy the dashboard and paste its URL
> in settings.
>
> *No scan result yet for this tab* — This page may not have been scanned yet, or it was skipped
> because it is an internal browser page, was added to your allowlist, or had not finished loading.
> Use "Rescan this page" below to analyse the current URL now.
>
> **Rescanning…**  **Set up dashboard**

Three separate things are visible in that one panel, and each has a different cause:

1. **Red badge** → `findReachableBackend()` returned `null` *and* the hosted probe failed.
2. **"Set up dashboard"** instead of "Open Dashboard" → no usable dashboard origin was resolved.
3. **Stuck "Rescanning…"** → the rescan message found no engine to talk to.

### 4.2 Investigation trail

| Step | Command / inspection | Finding |
| --- | --- | --- |
| 1 | `nslookup phishbrain007.app 1.1.1.1` | **Non-existent domain** |
| 2 | `nslookup api.phishbrain007.app 1.1.1.1` | **Non-existent domain** |
| 3 | RDAP lookup on the domain | no registration record → the deploy runbook's domain is a *plan*, not a deployment |
| 4 | port checks on 8000 / 8080 | nothing listening — the previously started stack had been stopped |
| 5 | `docker compose ps` / logs | stack stopped (earlier compose restart attempts had timed out) |
| 6 | read `extension/src/services/api.ts` defaults | `DEFAULT_CLOUD_SCAN_URL = ""`, `DEFAULT_CLOUD_EMAIL_URL = ""` |
| 7 | read `extension/src/lib/hosted.ts` resolution order | hosted endpoint derives from the **dashboard origin**; loopback origins are rejected by design |
| 8 | read `popup.tsx` status branches | three distinct messages exist; the one shown is the "nothing configured at all" branch |

### 4.3 The four root causes

**R1 — Nothing was running (the proximate cause).**
The dev build defaults to `http://127.0.0.1:8000` (backend) and `http://127.0.0.1:8080`
(dashboard). With both stopped, there was genuinely no engine. The panel was telling the truth.

**R2 — A shipped default pointed at a host that was never deployed.**
Older builds shipped `https://www.phishbrain07.app/api/public/scan` (note `07`, not `007`) and
`phishbrain007.lovable.app`. One has no DNS record; the other answers 404. A stored value pointing
there produced a permanent red panel — *including on a machine whose local backend was perfectly
healthy* — and an "Open Dashboard" button that led to Firefox's "Server Not Found". These hosts are
now blacklisted (`PLACEHOLDER_HOSTS`) and reported as *"still the old placeholder"* instead of being
fetched.

**R3 — Two URLs had to agree.**
The hosted endpoints `/api/public/scan` and `/api/public/email-scan` are **served by the dashboard
itself**. Asking the user to type the dashboard origin *and* the live-scan URL was a standing
source of "the fallback is unreachable", because the two could silently diverge. Resolution order is
now: explicit non-default URL → dashboard origin → shipped default.

**R4 — A release build ignored the backend on this machine.**
A production build bakes a public API origin. A developer running the FastAPI stack locally had
every scan sent to the internet, and the popup announced "Backend unavailable" while
`127.0.0.1:8000` was answering. The extension now tries the configured base **and** loopback
(literal `127.0.0.1`, because a hosts file that maps `localhost` to `::1` makes a healthy IPv4
uvicorn look dead), and says so in the popup:

> Using the backend on this computer (127.0.0.1:8000). The Backend URL in settings points elsewhere
> and was not reachable.

A fifth, smaller defect was found on the way: probing an **empty** endpoint with `fetch("")`
resolves against the popup's own `chrome-extension://` origin and answers 200, which made a
completely unconfigured install report "Hosted fallback". `probeHosted()` now returns
`{reachable: false}` for an empty URL, and Options refuses to probe a blank field.

### 4.4 The fix, file by file

| File | Change |
| --- | --- |
| `extension/src/lib/hosted.ts` **(new)** | Single source of truth for hosted endpoints: `isPlaceholderHostname`, `configuredDashboardOrigin`, `isStaleDashboardUrl`, `publicOrigin`, `probeHosted`, `resolveHostedScan`, `resolveHostedEmail`, `analysisDeepLink`, `describeSource`. |
| `extension/src/services/api.ts` | `PRODUCTION_*` vs `DEVELOPMENT_*` defaults chosen at build time; `LOOPBACK_BACKEND_URL`, `isLoopbackUrl`, `backendCandidates`, `findReachableBackend`; empty hosted defaults; `requireEndpoint()` turns a missing endpoint into a configuration error, not a network error. |
| `extension/src/background/service-worker.ts` | Both fallbacks (`analyzeUrlCloud`, `analyzeEmailCloud`) receive `resolveHostedScan/Email(settings).url`; local calls go through the candidate list. |
| `extension/src/popup/popup.tsx` | Four-state badge (`checking` / `online` / `fallback` / `offline`), a *stale placeholder* branch, a *loopback engine in use* notice, deep-linked "Open Dashboard", automatic scan of an unscanned tab, and 1.5 s polling until the provisional result becomes final. |
| `extension/src/options/options.tsx` | "Test local backend" probes the same candidate list the worker uses; "Test hosted fallback" probes the *resolved* endpoint and distinguishes "HTTP 404 — domain resolves but routes are not deployed" from "domain does not resolve"; the live-scan field shows what it will actually use and why. |
| `extension/tests/hosted.test.ts` **(new)** | 26 tests over placeholder detection, loopback rejection, resolution order, deep links and empty-endpoint probing. |
| `extension/tests/defaults.test.ts`, `api.test.ts` | 10 + 14 tests for build defaults, candidate order and endpoint guards. |

### 4.5 What the user needs to do on this machine

The panel is correct: no engine is configured. Any **one** of these makes it green:

```bash
# A. Full pipeline (recommended for a demo)
cd backend && venv/Scripts/python.exe -m uvicorn app.main:app --port 8000

# B. Everything, including Postgres/Valkey/Ollama
docker compose up -d --build

# C. Dashboard + hosted fallback
bun install && bun dev          # serves the dashboard on http://localhost:8080
```

> **Known gap (R5).** Option C alone does **not** make the extension scan: the hosted endpoint is
> derived from `configuredDashboardOrigin()`, which deliberately rejects loopback origins, so a
> dashboard-only local setup resolves to *no* hosted endpoint. Today the workable local path is A or
> B. Allowing `http://localhost:8080` as a fallback candidate when the local backend is down is a
> small, well-scoped follow-up (see §12).

### 4.6 Honest status of this incident

- **Diagnosed:** yes, with DNS/RDAP/port evidence.
- **Fixed in code:** messaging, derivation, placeholder rejection, loopback probing, empty-probe
  false positive — verified by 201 passing extension tests and a clean typecheck.
- **Verified end-to-end (a real scan through the popup):** **no** — no engine was running, and the
  dashboard dev-server start was interrupted. This is a limitation of the session, not a claim of
  success.
- **Still open:** the production defaults in `extension/src/services/api.ts` still name
  `phishbrain007.app`, which has **no DNS record** as of 2026-10-28. A release build therefore ships
  an unreachable API origin. Either register/deploy that domain or point the constants at the real
  deployment before publishing a store build.

---

## 5. Engineering decisions and rationale (ADR-style)

| # | Decision | Why | Cost accepted |
| --- | --- | --- | --- |
| D1 | Four deterministic layers + weighted score | Each layer is independently explainable and testable; no single rule can dominate. | More code, more failure paths to disclose. |
| D2 | Local LLM (Ollama) instead of a hosted model | Privacy is architectural; model lifecycle becomes configuration. | 32–48 s per verdict; needs a bounded, degraded fallback. |
| D3 | CatBoost for the pre-filter | Handles high-cardinality categorical URL signals with little tuning; trains in seconds; one portable `.cbm`. | Lexical-only view; must be disclosed and weighted low (15 %). |
| D4 | Pre-filter weight capped at 0.5, default 0.15 | A lexical model must never outvote corroborated multi-layer evidence. | Some true positives score lower until another layer fires. |
| D5 | LLM adjustment clamped to ±15 | The model may interpret, not overrule, the evidence. | A correct but contrarian LLM cannot rescue a bad layer score. |
| D6 | Pre-filter excluded unless a **trained** artifact exists | The rule-based fallback is derived from layer risks; blending it back would double-count and inflate every score. | Fresh clones report `ml.deterministic_fallback`. |
| D7 | Time-ordered zero-day split | Random splits leak the future into training and flatter the model. | Recall drops to a defensible 0.8633 rather than a prettier number. |
| D8 | Two named gate tiers (`strict`, `triage`) | "Passed" means nothing without saying what it certifies. | Publicly admits `strict` FAIL. |
| D9 | Playwright for the visual layer | Needs what a user *sees* (CSS, images, fonts), not raw HTML. | Chromium is heavy; render must be admission-gated. |
| D10 | Region-by-region perceptual comparison | A single hash distance is brittle to layout shifts; regions survive small differences. | More reference data; bot-walled references must be excluded. |
| D11 | SSE instead of a long POST | 80–90 % of wall time is the LLM; five seconds of real evidence shouldn't wait 50. | A second endpoint and a provisional-score contract. |
| D12 | Degradation is data, not an error | A scan that skips a layer should still be usable and *still* say so. | Every consumer must render `degraded`. |
| D13 | Dashboard serves its own `/api/public/*` scan routes | A deployment can scan with no backend and no VM. | Reduced score — which must be labelled. |
| D14 | Hosted endpoint derived from the dashboard origin | The endpoints ship *inside* the dashboard; two URLs was one too many. | Explicit overrides must still win, carefully. |
| D15 | Loopback always probed | The most common real setup is a developer with a healthy local stack and a shipped public default. | One refused connection per check on a stranger's device (milliseconds). |
| D16 | Placeholder hosts never fetched | Turning a configuration problem into a network error produces a permanent, misleading red panel. | A small, explicit blacklist to maintain. |

---

## 6. Verification and numbers

### 6.1 Test suites — re-run 2026-10-28

```text
backend  : 254 passed, 1 warning in 28.36 s   (23 test modules)
extension: 201 passed (15 files) in 52.38 s
typecheck: tsc --noEmit → exit 0
```

**Backend coverage by module (test counts):**

| Module | Tests | Module | Tests |
| --- | --- | --- | --- |
| `test_prefilter_gate.py` | 29 | `test_typosquatting.py` | 9 |
| `test_target_normalization.py` | 28 | `test_scoring.py` | 8 |
| `test_email_analysis.py` | 26 | `test_scan_gates.py` | 7 |
| `test_cors_origins.py` | 20 | `test_visual_retention.py` | 6 |
| `test_ssrf_guard.py` | 19 | `test_api.py` | 6 |
| `test_page_fetch_and_digest.py` | 16 | `test_visual_thumbnail.py` | 5 |
| `test_visual_branding.py` | 14 | `test_visual_capture.py` | 4 |
| `test_prefilter_features.py` | 13 | `test_unresolved_host.py` | 4 |
| `test_llm_validator.py` | 13 | `test_stream.py` | 4 |
| `test_domain_intelligence.py` | 13 | `test_url_features.py` | 3 |
|  |  | `test_llm_budget.py` | 3 |
|  |  | `test_prompt_sanitization.py` | 2 |
|  |  | `test_db_url.py` | 2 |

**Extension coverage (15 files, 201 tests):** `hosted` 26 · `logic` 25 · `alerts` 24 ·
`email-parser` 23 · `visual` 20 · `api` 14 · `popup-report` 12 · `region-similarity` 12 ·
`defaults` 10 · `visual-retention` 9 · `mail-hosts` 7 · `mailbox-scan` 5 · `reference-gaps` 5 ·
`page-analyzer` 5 · `mail-verdict` 4.

**What the suites pin (i.e. what used to break):** SSRF refusal, CORS for extension origins, SSE
framing, email schema tolerance, scan gates, unresolved hosts, LLM budgets, prompt sanitisation,
screenshot retention/thumbnails, brand-region similarity, alert delivery, and hosted-endpoint
resolution.

### 6.2 Pre-filter gate report (from `ml/evaluation/reports/latest.md`)

Dataset: `data/processed/prefilter_dataset.csv` — 7,959 test rows; time-ordered zero-day split at
`2026-07-02 21:16:31 UTC`; 7,620 same-domain test rows dropped; 13,879 undated rows kept out of the
test set; model `backend/models/prefilter.cbm`; decision threshold 0.5.

| Metric | Value |
| --- | --- |
| Accuracy | 0.8637 |
| Precision | **0.9982** |
| Recall | **0.8633** |
| F1 | 0.9259 |
| ROC-AUC | **0.9443** |
| False positive rate | 0.1091 |
| FPR (benign URLs with a path) | 0.0543 |
| Mean batch latency | 8.711 ms |
| Mean per-sample latency | 0.0011 ms |

Confusion matrix: `TP=6776 FP=12 FN=1073 TN=98`.

**Zero-day detection:** 0.8633 on phishing whose registrable domain was **never seen in training** —
7,849 phishing URLs across **5,294 unseen domains** (7,855 of 7,959 test rows were on unseen
domains). Timestamp coverage 84.9 %.

**Deployment gate — PASSED (tier `triage`):**

| Requirement | Threshold | Observed | Result |
| --- | --- | --- | --- |
| Recall | ≥ 0.85 | 0.8633 | PASS |
| Precision | ≥ 0.90 | 0.9982 | PASS |
| ROC-AUC | ≥ 0.90 | 0.9443 | PASS |
| FPR (all benign) | ≤ 0.1561 (+1.96 SE) | 0.1091 | PASS |
| FPR (benign with a path) | ≤ 0.1561 | 0.0543 | PASS |
| Mean per-sample latency | ≤ 5 ms | 0.0011 ms | PASS |
| **`strict` tier** | precision-grade, decides alone | — | **FAIL** |
| Expected calibration error | recorded | 0.1628 | disclosed |

**The sentence to put on a slide:** *"It clears the bar to be one disclosed signal among several,
and fails the bar to decide alone — and the report says both."*

### 6.3 Latency (4-core CPU, page fetch on)

| Mode | Request | Mean | Breakdown |
| --- | --- | --- | --- |
| Fast | `{"use_llm": false}` | **8.3 s** | fetch ~1.9 s, layers ~0.9 s, screenshot ~5.4 s |
| Full | `{"use_llm": true}` | **~55–62 s** | the above + 32–48 s of `llama3.2` inference |
| Full, unreachable host | any | ~58 s | connect 8.8 s, domain 10.7 s (overlapped), no screenshot, LLM 38 s |

Streaming: `started` 2 s · first layer 3 s · **provisional 5 s** · LLM verdict 47 s. Every response
carries `timings` and `latency_ms`, so "it is slow" is answerable without a profiler.

### 6.4 Manual verification recipes (copy-paste for a demo)

```bash
# 1. dependencies are named, not guessed
curl -s localhost:8000/api/v1/health

# 2. a full scan: model + pre-filter provenance
curl -s -X POST localhost:8000/api/v1/analyze/url -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","fetch_page":true}' \
  | python -c "import json,sys;d=json.load(sys.stdin);print(d['risk_level'],d['threat_score'],d['llm_assessment']['model'],d['prefilter']['model_trained'])"

# 3. the streamed scan
curl -N -X POST localhost:8000/api/v1/analyze/url/stream -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'

# 4. an unregistered host is a REPORT (200), not a 5xx
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8000/api/v1/analyze/url \
  -H 'Content-Type: application/json' -d '{"url":"https://this-domain-does-not-exist-9z8x.test"}'

# 5. deep link renders
curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost:8080/analysis?url=https%3A%2F%2Fexample.com'

# 6. both suites + typecheck
cd backend && venv/Scripts/python.exe -m pytest -q
cd ../extension && npm test && npm run typecheck && npm run check:content
```

---

## 7. Defect log (symptom → cause → fix → evidence)

| # | Symptom | Root cause | Fix | Verified by |
| --- | --- | --- | --- | --- |
| 1 | `hianime.to` refused outright | scheme-less target reached the fetch unnormalised | normalise before the SSRF guard, in both engines | `test_target_normalization.py` (28) |
| 2 | Clean-looking page after a failed fetch | empty webpage layer, nothing in `degraded` | fetch outcome named in the layer; failure is a report, not a 5xx | `test_page_fetch_and_digest.py` (16) |
| 3 | `github.com/login` scored 48/100 for mentioning Google/Microsoft/Amazon in SSO buttons | brand *mentions* were treated as brand *claims* | only a brand presented as the page's own (title/heading) and served from another domain counts | README "How the layers decide"; visual/branding tests |
| 4 | `netflix.com` lost 20 points | "apple" matched inside an `apple-touch-icon` `<link>` tag | markup excluded from text claims | same rule in both engines |
| 5 | Dashboard showed a comparison but no screenshot | captured thumbnail discarded after hashing | return downscaled pixels/wireframe with the report | `test_visual_thumbnail.py` (5) |
| 6 | Screenshots kept forever | no expiry policy | `VISUAL_RETENTION_DAYS` + sweep + clear endpoint | `test_visual_retention.py` (6) |
| 7 | Model passed deployment on a random split | future leaked into training | time-ordered zero-day split + tiered gate | `test_prefilter_gate.py` (29); `latest.md` |
| 8 | Brand comparison measured against a bot-wall page | challenge pages accepted as references | validate real content, retry with a persistent profile, record irrecoverable gaps | `reference-gaps.test.ts` (5) |
| 9 | Blank popup for ~50 s on a full scan | one response waited for the LLM | SSE + provisional score + in-place replacement | `test_stream.py` (4) |
| 10 | Gmail reply with no Reply-To → HTTP 400 | hosted schema required `undefined` while the parser sends `null` | optional fields are `nullish` | `test_email_analysis.py` (26) |
| 11 | Firefox add-on never scanned | `dist/` loaded instead of `dist-firefox/` | separate Firefox artefact + staging script + bundle check | `check-content-bundle.mjs`; extension README F |
| 12 | Permanent "Tried https://www.phishbrain07.app/api/public/scan" | shipped placeholder host, honoured as a user choice | placeholder blacklist + stale-URL branch | `hosted.test.ts` (26) |
| 13 | "Backend unavailable" while `127.0.0.1:8000` was healthy | release build's stored public URL probed alone | candidate list: configured base, then loopback | `api.test.ts` (14) |
| 14 | Unconfigured install reported "Hosted fallback" | `fetch("")` resolved to the extension's own origin → 200 | empty endpoint is a configuration error, never a probe | `hosted.test.ts` |
| 15 | "Open Dashboard" led to "Server Not Found" | dead placeholder parsed as a valid origin | `configuredDashboardOrigin()` returns null for placeholders; popup falls back to "Set up dashboard" | `hosted.test.ts` |
| 16 | Every email in History scored exactly **20/100 SAFE, 84 %** | anchor *text* was fed to `_extract_domain`, which accepts any string, so `Join Superset` became a "host" and every link became a text/href mismatch | a visible label only counts when it actually names a host (`VISIBLE_HOST_RE`); prose yields no claim | `test_newsletter_anchor_text_is_not_a_domain_mismatch` (3 links, score 0) |
| 17 | A clean-sounding email with one link to a fresh typosquat scored **0/100 SAFE** | for `input_type=email` the pipeline ran the email layer only: `url=None` → no URL layer, no domain layer, no page, and no prefilter input | the riskiest link is scored as a destination (URL + domain layers), without opening it | `test_email_links.py` (11) |
| 18 | An innocuous email could be *lowered* by a benign link | layers were averaged, so adding a clean view diluted the message's own evidence (30 → 11) | corroborative evidence only raises: `max(weighted_core, 0.9 × link_risk)` | `test_corroborative_link_evidence_never_lowers_a_verdict` |
| 19 | Link labelled `www.paypal.com` → `example.com` still read SAFE (24) | a brand-named label was scored as an ordinary mismatch | label that names a protected brand's domain and points elsewhere adds 12 more (→ SUSPICIOUS) | `test_a_link_labelled_with_a_brand_domain_is_flagged_beyond_a_plain_mismatch` |
| 20 | Oracle runbook claimed a **4 OCPU / 24 GB** free VM | the Always Free Arm allowance was halved (1,500 OCPU-hours + 9,000 GB-hours/month = 2 OCPU / 12 GB) | runbook corrected, and arm64 wheels verified instead of assumed | `deploy/README.md` §4b |

---

## 8. Presentation kit

### 8.1 Twelve-slide outline with speaker notes

**Slide 1 — Title.**
*PhishBrain: zero-day phishing defence that shows its work.*
Note: one sentence on what it is, one on why privacy is architectural.

**Slide 2 — The problem.**
Black-box scores; every visited URL shipped to somebody else's cloud; zero-day pages that no
blocklist has seen yet.
Note: "87/100" tells a user nothing they can act on or learn from.

**Slide 3 — The idea.**
Four evidence layers + a trained pre-filter + a local LLM + a screenshot comparison, fused into one
explainable score.
Note: the differentiator is *evidence*, not the number.

**Slide 4 — Architecture.**
The §2.2 diagram, three boxes: extension, dashboard, backend.
Note: three deployment shapes; the same extension works with all of them.

**Slide 5 — A scan, end to end.**
The ten numbered steps from §2.4, with the 5 s / 47 s split highlighted.
Note: streaming is not cosmetic — it is the difference between a blank screen and a usable verdict.

**Slide 6 — How the score is built.**
The §2.5 formula + the single-layer floor + the ±15 clamp + the confidence formula.
Note: the pre-filter is capped at 15 % by default and 50 % absolutely.

**Slide 7 — The ML story.**
Zero-day split, 5,294 unseen domains, recall 0.8633, precision 0.9982, ROC-AUC 0.9443, 0.0011 ms per
sample, `triage` PASS / `strict` FAIL.
Note: the honest split is the point; the model is allowed to be one signal, not the judge.

**Slide 8 — The visual layer.**
Playwright render → perceptual hash → region-by-region brand comparison; bot-wall references
rejected; gaps enumerated.
Note: catches clones with no malicious string — the case string matching cannot see.

**Slide 9 — The extension.**
Full report in the popup; in-message card for Gmail/Outlook; badge/banner/notification; SOC webhook;
four-state engine badge.
Note: the popup is a report, not a badge — that is the product decision.

**Slide 10 — Honesty engineering.**
Degradation table: `llm.deterministic_fallback`, `llm.busy`, `llm.timeout`, `ml.deterministic_fallback`,
no-screenshot note, failed fetch, reduced hosted engine.
Note: "a reduced score that looks like a full one is worse than no score."

**Slide 11 — Verification.**
254 backend + 201 extension tests; typecheck clean; the manual recipes; the ML gate table.
Note: quote the commands, not adjectives.

**Slide 12 — Deploy & cost.**
Workers free + always-free VM + tunnel; ~$11/year domain; caveats (idle reclamation, no other free
tier fits a 3B model).
Note: the domain is currently **not registered** — that is a plan, not a running site. Say so.

### 8.2 90-second demo script

1. Open the dashboard `http://localhost:8080`, scan `https://example.com` → point at the
   **provisional** score appearing in ~5 s, then the LLM card landing later.
2. Scan a typosquat / bare host (`hianime.to`) → show normalisation and the URL-layer indicators.
3. Open the report's **pre-filter card** → score, weight 15 %, gate tier `triage`.
4. Open the **visual card** → the captured thumbnail and the brand comparison.
5. Scan an unregistered domain → it returns a **report**, not an error, with `degraded` naming what
   could not run.
6. Open the extension popup on a page → full report; badge, banner, notification; "Open Dashboard"
   lands on `/analysis?url=…`.
7. Dashboard → Settings → clear visual evidence; note the retention policy.

### 8.3 Five-minute spoken track

> Phishing detection today is two things at once: a number you can't inspect, and a copy of every
> URL you visit sitting in somebody else's cloud.
>
> PhishBrain is a local-first answer to both. It looks at a page the way four different experts
> would. The URL expert sees a punycode host, a shortener, a brand token in the wrong place, a
> typosquat. The domain expert asks when the domain was registered, what DNS and TLS say, who the
> registrar is. The page expert sees a password form, an OTP field, an iframe, a favicon, and asks a
> sharper question than "does it mention a brand": does this page *present itself* as that brand
> while being served from a domain that isn't theirs? The email expert compares sender and Reply-To,
> checks for lookalike sender domains, and compares the text of a link with where it actually goes.
>
> On top of that sit two things rules can't express. A CatBoost model trained on lexical features
> contributes fifteen percent of the base score — capped, disclosed, and only when a trained model
> is actually deployed. And a local llama3.2 model reads a bounded digest of the evidence and writes
> a verdict, but its adjustment is clamped to plus or minus fifteen points: it may interpret the
> evidence, never overrule it.
>
> And one thing neither can do: we render the page in Chromium, take a perceptual hash, and compare
> it region by region against known brand login screens. That catches the clone that reuses a clean
> domain and clean HTML and simply *looks* like your bank.
>
> The result is one 0-to-100 score with its evidence attached — plus a confidence value, a list of
> what could not run, and a SOC event ready to forward. SAFE below 30, SUSPICIOUS to 65, HIGH_RISK
> above.
>
> Two numbers I'd point at. On a time-ordered zero-day split — 5,294 domains the model had never
> seen — the pre-filter catches 86 percent of phishing at 99.8 percent precision, in about a
> microsecond per sample. It passes the gate as a triage signal and fails it as a standalone
> decision, and the report says exactly that. The second number is five seconds: the deterministic
> verdict is on screen in about five seconds, and the model's verdict replaces it in place at
> forty-seven. That is why the scan is streamed.
>
> Nothing leaves your infrastructure. No Safe Browsing, no VirusTotal, no OpenAI. That's not a
> policy, it's the architecture.

### 8.4 Q&A / viva defence

**Q: Why not just use Google Safe Browsing or VirusTotal?**
A: Three reasons. Privacy — the analysis would mean shipping every visited URL to a third party.
Coverage — blocklists are retrospective; a domain registered this morning is invisible to them, and
that is precisely the zero-day case. Explainability — an API verdict is a boolean you cannot audit
or teach from.

**Q: Your recall is 86 %. Isn't that low?**
A: It is the honest number on a time-ordered split with domains removed from training, which is the
condition that matters in the field. It also is not the only signal: the pre-filter is 15 % of the
score, re-checked by four layers and an LLM. We deliberately publish that it fails the *strict*
tier and passes the *triage* tier rather than tuning the threshold until a slide looks better.

**Q: Why clamp the LLM to ±15?**
A: A generative model can be confidently wrong in a way that is hard to falsify after the fact.
Clamping keeps the deterministic evidence authoritative and makes the LLM's role interpretation,
not adjudication. The model still contributes its written assessment and key indicators.

**Q: How do you stop prompt injection from the page you're analysing?**
A: Page text is passed as data, never as instructions; the digest is bounded and labelled; the
output is validated by a Pydantic schema that rejects a hallucinated shape; and there is a dedicated
prompt-injection fixture in the dashboard plus `test_prompt_sanitization.py`.

**Q: Why CatBoost rather than a neural model?**
A: High-cardinality categorical URL features, very little tuning, trains in seconds on a laptop, and
exports a single portable `.cbm` that runs inside a request at ~1 µs per sample. A transformer would
cost latency and add a runtime dependency for a signal that is only 15 % of the score.

**Q: What happens when Ollama is down or busy?**
A: The scan still completes. `llm.deterministic_fallback` (or `llm.busy`, `llm.timeout`) is recorded
and the deterministic verdict stands. The report says which happened — it never pretends the model
spoke.

**Q: How does this scale on one small VM?**
A: Admission gates: `MAX_CONCURRENT_LLM_SCANS` and `MAX_CONCURRENT_VISUAL_SCANS` default to 1, and
extra requests queue for `SCAN_QUEUE_TIMEOUT_SECONDS` (20 s) before degrading to a labelled
deterministic verdict. Chromium and the 3B model are both CPU-bound; without a ceiling, concurrent
visitors make *every* scan miss its deadline.

**Q: Isn't screenshot capture a privacy problem?**
A: It is opt-in, runs on the user's own device/browser, can be stored as an edge-only wireframe
instead of pixels, expires under `VISUAL_RETENTION_DAYS` (default 7, 0 = keep none), and can be
cleared in one click. The backend can be configured to store no readable copy at all.

**Q: Why does the dashboard have its own scanner?**
A: So a deployment can work with no VM and no Python: the Worker does a real fetch with a redirect
chain, DNS-over-HTTPS, RDAP age and DOM analysis. It is explicitly reduced — no CatBoost, no LLM, no
Playwright — and the report banner names the engine that answered.

**Q: What was the hardest bug?**
A: The class of bugs where the system is confidently wrong rather than broken: a failed fetch that
looked like a clean page; a bot-wall capture that poisoned a brand reference; a model that passed a
gate only because the split leaked the future. Each fix was less about code and more about making
the system disclose what it did not know.

**Q: What is not finished?**
A: The public domain. `phishbrain007.app` has no DNS record as of 2026-10-28, so the runbook is a
plan, not a deployment, and release builds currently ship an unreachable default API origin. Locally,
a dashboard-only setup also cannot feed the extension's hosted fallback (loopback origins are
rejected by design), which is the next small fix.

**Q: How do I know the numbers are real?**
A: They are reproducible in this repository: `pytest -q` gives 254 passed, `npm test` gives 201,
`ml/evaluation/reports/latest.md` and `train_gate.md` contain the split description and gate table,
and §6.4 lists the curl commands.

---

## 9. Report-ready material

### 9.1 Abstract (150 words)

Phishing defence is typically opaque and cloud-dependent: a score with no evidence, produced by
shipping every visited URL to a third party. This project presents PhishBrain, a local-first
detection platform that fuses four deterministic evidence layers — URL structure, domain
registration and infrastructure, rendered-page semantics, and email headers and links — with a
CatBoost lexical pre-filter, a locally hosted large language model and a perceptual-hash comparison
against brand login screens. Each component is weighted, disclosed and degradable: missing evidence
is reported rather than hidden. On a time-ordered zero-day split covering 5,294 domains unseen in
training, the pre-filter achieves 0.863 recall at 0.998 precision and 0.944 ROC-AUC, while serving
as a 15 % contributor to a score that a renderer, four layers and an LLM corroborate. Results stream
in five seconds, with the model verdict replacing them in place.

### 9.2 Methodology section (draft)

The system is evaluated at three levels. **Unit and integration level**, 455 automated tests pin the
behaviours that previously failed: SSRF refusal, target normalisation, CORS for extension origins,
SSE framing, email-schema tolerance, screenshot retention and brand-region similarity. **Model
level**, the pre-filter is trained on a curated phishing/benign corpus and evaluated on a
time-ordered split with a cutoff timestamp; test rows whose registrable domain appears in training
are removed, and undated rows are excluded from the test set rather than assigned a date. Detection
is reported on phishing URLs whose domain was never observed in training, with precision, recall,
ROC-AUC, false-positive rate (overall and on path-bearing benign URLs), per-sample latency, and
expected calibration error. Deployment is gated on tiered thresholds, and a candidate that misses
them leaves the deployed artifact untouched and writes its rejection reasons to a report.
**System level**, end-to-end latency is measured per phase for LLM and non-LLM paths, and every
response carries per-phase timings so regressions are attributable.

### 9.3 Results section (draft)

Across 7,959 test rows, the pre-filter reached 0.8637 accuracy, 0.9982 precision, 0.8633 recall,
0.9259 F1 and 0.9443 ROC-AUC, with a 0.1091 false-positive rate (0.0543 on benign URLs containing a
path) and 0.0011 ms per-sample inference. Zero-day detection — restricted to the 7,849 phishing URLs
across 5,294 domains unseen during training — was 0.8633. The model passed the triage gate and
failed the strict gate, and both verdicts are published in the evaluation report alongside a 0.1628
expected calibration error. End-to-end, a deterministic scan completes in 8.3 s on a four-core CPU
and a full scan with the 3B local model in 55–62 s; streaming exposes a labelled provisional verdict
at 5 s and the model verdict at 47 s. The full backend suite (254 tests) and extension suite (201
tests) pass, and the extension typechecks cleanly.

### 9.4 Limitations and ethics

- The pre-filter is lexical only; it cannot see page content and is deliberately weighted at 15 %.
- Absolute recall is bounded by dataset composition; the benign test sample is small (110 rows), so
  the gate is evaluated with a standard-error tolerance and that tolerance is disclosed.
- The LLM is a 3B model on CPU: useful for interpretation, not an authority; its adjustment is
  clamped.
- Visual comparison depends on a local reference set; brands that cannot be captured behind bot
  walls are enumerated as a known gap rather than silently missing.
- This is a research and teaching system. It should not be the only defence behind a real security
  decision.
- No third-party threat intelligence is used; that is a privacy property and a coverage limitation,
  stated together.

### 9.5 Future work

1. Register/deploy the public domain (or repoint `PRODUCTION_*`) so a store build works out of the
   box.
2. Let a loopback dashboard origin serve the hosted fallback, so dashboard-only development scans.
3. Calibrate the pre-filter (current ECE 0.1628) so its probability can be read literally.
4. Grow the benign evaluation sample to tighten the false-positive confidence interval.
5. Add a temporal drift monitor: re-run the gate on a rolling window and alarm when recall decays.
6. Expand brand references with a reviewable capture pipeline (the gap list is already testable).

---

## 10. Ops cheatsheet

```bash
# --- full stack -------------------------------------------------------------
cp .env.example .env                     # set POSTGRES_PASSWORD
docker compose up -d --build             # dashboard :8080, API :8000
docker compose logs -f backend
curl -s localhost:8000/api/v1/health     # database / cache / ollama

# --- local dev --------------------------------------------------------------
cd backend && venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000
bun install && bun dev                   # dashboard on :8080
ollama serve && ollama pull llama3.2:3b  # optional LLM

# --- dashboard-only (Node/Bun server build) ---------------------------------
NITRO_PRESET=node-server bun run build
PORT=8080 HOST=0.0.0.0 bun .output/server/index.mjs

# --- extension --------------------------------------------------------------
cd extension
npm ci
npm test && npm run typecheck && npm run check:content
npm run build          # dist/         Chrome/Edge
npm run build:firefox  # dist-firefox/ Firefox (never load dist/ in Firefox)
npm run zip:firefox    # AMO upload / self-signed XPI
VITE_PHISHBRAIN_BACKEND_URL=https://api.example.app \
VITE_PHISHBRAIN_DASHBOARD_URL=https://example.app npm run build

# --- ML ---------------------------------------------------------------------
python scripts/data/download_data.py --confirm
python scripts/data/fetch_benign_urls.py --confirm
python scripts/data/prepare_dataset.py
python ml/training/train_prefilter.py     # gated: deploys only on a pass
python ml/evaluation/report.py

# --- tests ------------------------------------------------------------------
cd backend && venv/Scripts/python.exe -m pytest -q          # 254
cd extension && npx vitest run                              # 201
```

**Ports.** 8080 dashboard · 8000 API · 5432 Postgres · 6379 Valkey · 11434 Ollama.
**Config knobs that matter.** `PREFILTER_WEIGHT` (0.15), `SAFE_THRESHOLD` (30),
`SUSPICIOUS_THRESHOLD` (65), `LLM_TIMEOUT_SECONDS` (150), `MAX_CONCURRENT_LLM_SCANS` (1),
`MAX_CONCURRENT_VISUAL_SCANS` (1), `SCAN_QUEUE_TIMEOUT_SECONDS` (20), `RETENTION_DAYS` (30),
`VISUAL_RETENTION_DAYS` (7), `VISUAL_SCREENSHOT_MODE`, `STORE_RAW_EMAIL` (false).

---

## 11. Glossary

| Term | Meaning here |
| --- | --- |
| **Layer** | One independent body of evidence (URL, domain, webpage, email) with its own risk score, indicators and raw evidence. |
| **Pre-filter** | The CatBoost lexical model that contributes a bounded, disclosed share of the base score. |
| **Triage tier** | A gate tier certifying a model as fit to be one signal among several, not to decide alone. |
| **Provisional score** | A clearly labelled score computed from deterministic layers before the LLM verdict arrives. |
| **Degraded** | A list of capabilities that could not run for this analysis (LLM down, screenshot blocked, DNS failure…). |
| **SSRF guard** | Refusal of targets that resolve to loopback/private/link-local addresses before any fetch. |
| **RDAP** | Registration Data Access Protocol — the structured successor to WHOIS, used for domain age and registrar. |
| **Perceptual hash** | A compact fingerprint of an image used to compare layouts without storing pixels. |
| **Region similarity** | Comparing a screenshot region by region against a brand reference, rather than one global distance. |
| **SSE** | Server-Sent Events; how a scan streams `started → layers → prefilter → provisional → llm → final`. |
| **MV3** | Chrome's Manifest V3 extension platform (`background.service_worker`); Firefox uses `background.scripts`. |
| **SOC event** | A structured record (`event_id`, `severity`, `indicators`, `degraded`, pre-filter contribution) ready for a SIEM/webhook. |
| **Hosted fallback** | The dashboard's own `/api/public/scan` endpoints, used when no local backend is reachable; reduced, and labelled as such. |
| **Placeholder host** | An undeployed default (`phishbrain07.app`, `phishbrain007.lovable.app`) that must never be treated as a deployment. |

---

## 12. Index, current state, and open items

### 12.1 Key files (click-through in the editor)

| Concern | File |
| --- | --- |
| Pipeline | `backend/app/services/pipeline.py` |
| Scoring | `backend/app/scoring/engine.py` |
| SSRF / normalisation | `backend/app/core/security.py` |
| Concurrency gates | `backend/app/core/concurrency.py` |
| HTTP API | `backend/app/api/v1/routes.py` |
| Dashboard report UI | `src/components/phishbrain/AnalysisReport.tsx` |
| Reduced server engine | `src/lib/phishbrain/live.server.ts` |
| Public scan routes | `src/routes/api/public/scan.ts`, `email-scan.ts` |
| Extension worker | `extension/src/background/service-worker.ts` |
| Extension API defaults | `extension/src/services/api.ts` |
| Hosted resolution | `extension/src/lib/hosted.ts` |
| Popup / report | `extension/src/popup/popup.tsx`, `PopupReport.tsx` |
| Options | `extension/src/options/options.tsx` |
| Email parsing | `extension/src/content/email-parser.ts`, `mail-body.ts`, `mail-links.ts` |
| ML gate | `ml/training/train_prefilter.py`, `ml/evaluation/reports/*.md` |
| Deploy runbook | `deploy/README.md` |
| Everything explained | `workingexplaination.txt` |

### 12.2 Current repository state (2026-10-28)

- **Branch:** `main`, 8 commits, HEAD `af403f3`.
- **Working tree:** 54 tracked files modified (+4,243 / −988) and 30 new paths — the hardening wave
  (§3.10) plus the engine-resolution fix (§4.4). **Nothing is committed yet.**
- **Running services:** none. The dashboard dev server start was interrupted; the compose stack is
  stopped. That is why the popup shows the red panel.
- **Domain:** `phishbrain007.app` and `api.phishbrain007.app` return NXDOMAIN from 1.1.1.1.

### 12.3 Open items, in priority order

1. **Run an engine** (backend or compose), then perform one real end-to-end scan and confirm the
   popup turns green — the fix has unit coverage but no live end-to-end proof.
2. **Resolve the public endpoint story.** Either register `phishbrain007.app` and deploy per
   `deploy/README.md`, or change `PRODUCTION_BACKEND_URL` / `PRODUCTION_DASHBOARD_URL` to the real
   deployment. Today a release build ships an unreachable API origin.
3. **Allow a loopback dashboard origin as a hosted candidate**, so `bun dev` alone can serve scans
   (dashboard-only mode is otherwise unusable from the extension).
4. **Commit the working tree** in reviewable slices (email surface, Firefox packaging, backend
   hardening, engine resolution) rather than one 4k-line commit.
5. **Calibrate the pre-filter** (ECE 0.1628) and grow the benign evaluation sample beyond 110 rows.

---

## 13. Session log — 28 Oct 2026, second session (email scoring)

### 13.1 The report

The dashboard History showed every analysed email with the same verdict: **20/100,
SAFE, 84 % confidence, top indicator "2 link(s) have visible text domain mismatched with
actual href"** — for `notifications@joinsuperset.com`, `noreply@redditmail.com` and
`noreply@notify.cloudflare.com` alike, with link counts of 2, 40 and 8. Question asked:
*is it even parsing the email?*

### 13.2 What was actually happening

Two independent defects, and they hid each other.

**a. The text was parsed; the score was noise.** `analyze_email` does read subject and body
(urgency, threat, credential, financial and prize vocabularies, Reply-To/display-name spoofing,
SPF/DKIM/DMARC). None of those newsletters contained pressure language, so the only signal left was
the link check — and that check was wrong. The extension sends `text|href` pairs; the backend ran
`_extract_domain()` on the *text*, and that function is deliberately permissive (it accepts an
address, a URL, or a bare host and falls back to "whatever was passed" as the host). So
`Join Superset` became the host `join superset`, `View in browser` became `view in browser`, and
every link in every newsletter was counted as a text/href mismatch. Reproduced in one call:

```
analyze_email(sender='notifications@joinsuperset.com', subject='Your weekly digest',
              body='Here is what happened this week…',
              links=['Join Superset|https://joinsuperset.com/dashboard',
                     'View in browser|https://mail.joinsuperset.com/view/abc',
                     'Unsubscribe|https://joinsuperset.com/unsubscribe'])
→ score 20.0, mismatched_links 3, indicators ['3 link(s) have visible text domain mismatched…']
→ _extract_domain('Join Superset') == 'join superset'
```

That single +20 was the entire score, and `compute_layer_weighted_score` over one available layer
returns that layer unchanged — hence the identical 20 for unrelated senders.

**b. An email scan examined no destination.** `POST /api/v1/analyze/email` calls
`run_analysis("email", sender, email_fields=…)` with no `url`. In the pipeline that means: no URL
layer, no domain layer, no page fetch, no screenshot, and `_prefilter_features(layers, None)` — so
everything the project is proud of (typosquat detection, domain age, homographs, the CatBoost
pre-filter) was **skipped for messages**. A message reading "Please review the attached invoice"
and pointing one link at `paypa1-support.top` scored **0/100 SAFE**. That is the same class of bug
the project already fixed for pages ("a failed fetch must not look like a clean page"): *not looked
at* was being reported as *nothing found*.

**c. The tests could not have caught it.** `test_link_text_domain_mismatched_with_href_is_flagged`
passed `https://www.paypal.com/login|https://evil-collector.top/login` — an **href|href** pair. The
extension never sends that shape; it sends **text|href**. The unit test and the real caller disagreed
about the data format, and only the real caller was wrong.

### 13.3 What changed

| File | Change | Why |
| --- | --- | --- |
| `backend/app/analyzers/email/analyzer.py` | `_domain_in_text()` gated by `VISIBLE_HOST_RE`; labels only count when they name a host | prose is the *absence* of a claim, not a conflicting one |
| same | brand-named label pointing elsewhere adds 12 on top of the 20 | "you are going to paypal.com" is the construction phishing kits use; a vague mismatch is not |
| same | evidence now records `body_chars`, `subject_chars`, `links_total`, `links_with_visible_text`, `brand_labelled_links`, `mismatched_link_examples`, plus a `notes` line when no body arrived | answers "did it even read the message?" inside the report instead of in a support thread |
| `backend/app/analyzers/email/links.py` *(new)* | scores every http(s) href with the URL layer, picks the **worst** one, guards its host with the SSRF guard, marks the layer `corroborative` | one malicious link must not hide behind twenty benign ones |
| `backend/app/services/pipeline.py` | email scans gain `url` + `domain` layers for that destination; domain lookups run concurrently with a 4 s cap; the link URL is passed to the pre-filter | real evidence for messages, without a page fetch |
| `backend/app/scoring/engine.py` | corroborative layers can only raise: `max(weighted_core, 0.9 × link_risk)` | adding a *clean* link must never make a suspicious message look safer |
| `backend/tests/test_email_links.py` *(new)*, `tests/test_email_analysis.py` | 15 new tests | pin the prose case, the worst-link choice, the SSRF refusal, the brand label, the monotonicity rule, and the pipeline wiring |
| `README.md`, `deploy/README.md` | rules documented; Oracle free-tier figures corrected; arm64 support verified package by package | docs must not claim what the code does not do |

**Deliberate non-change:** the link is **not opened**. Fetching it server-side would report the
message as read to its sender (tracking pixels and redirects) and the reader has not clicked it yet,
so the destination is scored from strings only and the report says the page itself was not examined.

### 13.4 Verification (2026-10-28, after the change)

```
backend   269 passed  (was 254; +15 net new)
extension 201 passed, tsc --noEmit clean  (unchanged — no extension code touched)
```

Measured through the real interface — `POST /api/v1/analyze/email` on the running uvicorn:

| Message | Before | After |
| --- | --- | --- |
| Newsletter, prose labels, benign links | 20 SAFE | **0 SAFE**, layers `email 0 / url 0 / domain 0`, note explains the link was not opened |
| Innocuous prose + link to `paypa1-support.top` | 0 SAFE | **91.22 HIGH_RISK** (`Suspicious TLD .top`, `typosquat l→1`, `does not resolve`, prefilter 98) |
| `www.paypal.com` label → `example.com` | 20 SAFE | **34.43 SUSPICIOUS** (`Link labelled as paypal.com points at example.com`) |
| Same message with a *clean* link | — | score unchanged, never reduced (test-pinned) |

### 13.5 Hosting it for free — the answer given

`api.phishbrain007.app` still does not exist (NXDOMAIN), so the question "how do I host this for
free" is answered in `deploy/README.md`, with the corrected numbers:

| Option | Free? | Fits the full engine? | Verdict |
| --- | --- | --- | --- |
| **Own machine + Cloudflare quick tunnel** (`cloudflared tunnel --url http://127.0.0.1:8000`) | yes, no card, no quota | yes | fastest real `https://` URL; dies when the machine sleeps, URL changes each restart |
| **Oracle Cloud Always Free A1** — 2 OCPU / 12 GB (1,500 OCPU-hours + 9,000 GB-hours/month), 200 GB block storage, 10 TB egress | yes, card for identity, idle reclamation | yes | the only 24/7 free host that fits; "out of host capacity" is normal, retry across ADs |
| **Cloudflare Workers alone** | yes | no (no Chromium/CatBoost/Ollama) | the dashboard plus a reduced scan; already how `/api/public/*` works |
| Render 512 MB · Koyeb 512 MB · Fly/Railway · GCP e2-micro 1 GB · AWS 6-month credits · HF Docker (paid) | "free" but 512 MB / sleeping / ephemeral / expiring | no | none can hold Ollama + Chromium + Postgres |

arm64 was checked rather than assumed: `catboost==1.2.7` ships `manylinux2014_aarch64` wheels (query
PyPI directly), Playwright 1.47 ships Linux arm64 Chromium for Debian 12 / Ubuntu 22.04+ and
`docker/Dockerfile.backend` is `python:3.11-slim-bookworm`, and Ollama's installer maps `aarch64` to
`ollama-linux-arm64`. The one rule: never add `platform: linux/amd64` to the compose file — emulated
Chromium turns a 2 s scan into a minute.

---

## 14. Session log — 29 Oct 2026 (latency, screenshots, navigation, hosting)

### 14.1 "Open Dashboard" and "Settings" both opened Settings

`popup.tsx` resolved its dashboard URL through `configuredDashboardOrigin()`, which rejects loopback
addresses on purpose (it is the helper that derives the *hosted* scan endpoint, and a public origin is
required there). A development build stores `http://127.0.0.1:8080`, so the resolved value was the
empty string, `openDashboard()` took its "nothing configured" branch, and both buttons landed on
`options.html`.

Fix: `dashboardOpenTarget(...)` / `openableOrigin(...)` in `lib/hosted.ts` keep a local origin (the
deployed one still wins), and the popup only falls back to Settings when nothing usable is
configured. The popup also states the local dashboard it will open. Evidence: 3 new tests in
`extension/tests/hosted.test.ts`; `tsc --noEmit` clean; 204 extension tests pass.

### 14.2 The model owned the latency — measured, then cut

`timings` showed the model at 49 of 51 s for a scan whose deterministic half took 2 s. Root cause was
arithmetic, not a bug: `llama3.2:3b` generates ~5 tokens/s on 2–4 cores and prefills ~20–48 tokens/s,
so 60–120 output tokens + a ~450-token prompt is 20–45 s whatever the code does. Four waste paths
were removed:

| Change | Why |
| --- | --- |
| `LLM_SKIP_WHEN_DECISIVE` (new, default on) | the adjustment is clamped to ±15; when the base score cannot cross a boundary, the model is skipped and the report says `llm.not_needed` (exempt from the confidence penalty, explained in the prose) |
| `LLM_NUM_PREDICT` 320 → **160** | a complete verdict measured 82 tokens; 320 was ~47 s in the worst case |
| prompt ~40 % smaller + bounded JSON evidence | instruction tokens are paid before the first output token exists |
| retry no longer re-sends the page text | a rejected output costs a *second* full generation; the retry is now schema + failure only |

Instrumentation added because "slow" was previously undiagnosable: each generation logs
`prompt_tokens`, `eval_tokens`, `prompt_ms`, `gen_ms`, `done_reason`, and a rejected output logs a
warning (an invisible retry was doubling scans). Measured: `example.com` 49 s → 34.5 s of model time;
a decided verdict now finishes in ~11 s total; an email scan 49 s → 22 s on an idle box.

### 14.3 Screenshots: they capture, and now they cannot outlive their budget

Verified end to end on the live API: the webpage layer returns `screenshot_data_url` (9.6 KB
thumbnail), `visual_similarity_score`, and the brand-comparison notes, and `normalizeServerResult`
carries them into `visual.screenshot_thumbnail`, which the popup and the dashboard both render.
A failed fetch or an unresolved host correctly captures *nothing* and says why.

Two defects found while verifying: (a) `page.screenshot()` had Playwright's own 30 s default on top
of the navigation timeout, so one stuck page could hold a Chromium for 60 s — longer than the
caller's 30 s budget, which means the thread outlived its scan and its browser was never closed. Both
paths now set `set_default_timeout()` and bound the capture explicitly below the caller's budget.
(b) The 60 s `visual.timeout` was reproduced only on a memory-starved box (1.4 GB free of 16 GB with
Ollama + Docker Desktop + two browsers); freeing the unused containers restored 6–13 s captures.

### 14.4 Two backends on one port (the "backend works properly" trap)

The Compose stack's `backend` container held `0.0.0.0:8000`/`[::]:8000` while the host `uvicorn`
held `127.0.0.1:8000`. `localhost:8000` therefore reached the **container** (an image built before
these fixes, budget 150 s) and hung, while `127.0.0.1:8000` reached the fixed host server. That is
exactly how the dashboard ends up on "DEMO FALLBACK ON" while the API looks healthy from a terminal.
Resolved for this machine with `docker compose stop backend postgres valkey ollama` (the host server
uses SQLite, the in-memory cache and the native Ollama, so the containers were dead weight and their
WSL VM was holding ~1.8 GB). Undo with `docker compose start <service>`.

### 14.5 Open defect: the CatBoost prefilter is miscalibrated

The deployed `models/prefilter.cbm` (trained 2026-09-23, gate tier `triage`, calibration `identity`)
scores obviously benign URLs as phishing: `example.com` **97/100**, `google.com` **84/100**,
`github.com/login` 64/100. At `PREFILTER_WEIGHT=0.15` that adds ~13–15 points to every clean target —
which is why benign scans cluster around 15–21/100 instead of 0–5, and why the decisive-skip band is
rarely reachable in practice. This is a training-data problem, not a scoring bug: retraining or
recalibrating is the fix, and it is the single highest-value ML item left.

---

## Appendix A — Evidence captured on 2026-10-28

```text
$ nslookup phishbrain007.app 1.1.1.1
*** one.one.one.one can't find phishbrain007.app: Non-existent domain

$ nslookup api.phishbrain007.app 1.1.1.1
*** one.one.one.one can't find api.phishbrain007.app: Non-existent domain

$ cd backend && venv/Scripts/python.exe -m pytest -q
254 passed, 1 warning in 28.36s

$ cd extension && npx vitest run
Test Files  15 passed (15)
     Tests  201 passed (201)
  Duration  52.38s

$ cd extension && npm run typecheck
tsc --noEmit          # exit 0

$ git log --oneline
af403f3 scan: stream each stage so a result appears in seconds, not after the LLM
85c9cd8 docs: fix the self-host deploy path and document the new evidence surfaces
8bfff51 scripts: retry bot-walled brand captures and record the gaps that persist
1875a70 extension: explainable report, high-risk alerts, and a visual comparison
9e46c66 dashboard: surface prefilter and visual evidence, and let users clear stored screenshots
ab80a4e ml: evaluate the prefilter on an honest time split and gate deployment on it
5f62703 backend: normalize bare hosts, report fetch failures, and keep visual evidence honest
b10d200 Initial commit: PhishBrain self-hosted phishing analysis platform

$ git diff --stat | tail -1
54 files changed, 4243 insertions(+), 988 deletions(-)
```

---

*Generated as a working dossier. If a number here disagrees with the code, the code wins — re-run
§6.4 and update this file.*
