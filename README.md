# PhishBrain 🧠

PhishBrain is an advanced, privacy-first phishing detection system that uses a multi-layered approach to analyze suspicious content. It combines traditional heuristics, machine learning (CatBoost), and local Large Language Models (LLMs) to provide transparent and explainable risk assessments.

## Architecture

```text
                                  +-------------------+
                                  | Browser Extension |
                                  +---------+---------+
                                            |
                                            v
    +---------------------------------------+---------------------------------------+
    |                                FastAPI Backend                                |
    |  +-------------------+        +-------------------+        +-------------------+ |
    |  |   ML Prefilter    | <----> |  Analysis Engine  | <----> |   LLM Analyzer    | |
    |  |    (CatBoost)     |        |   (Scoring Logic) |        |     (Ollama)      | |
    +----------+-----------+        +---------+---------+        +---------+---------+
               |                              |                           |
               v                              v                           v
    +-------------------+        +-------------------+        +-------------------+
    |      Valkey       |        |    PostgreSQL     |        |      Ollama       |
    |      (Cache)      |        |    (History)      |        |     (Llama 3.1)   |
    +-------------------+        +-------------------+        +-------------------+
```

## Features

- **Multi-Layer Analysis**: Evaluates emails, URLs, domain reputation, and visual webpage features.
- **Explainable AI**: Provides detailed reasoning for every risk score, not just a binary result.
- **Privacy-First**: Designed to run entirely locally. No data is sent to third-party APIs.
- **Hybrid Scoring**: Combines fast CatBoost pre-filtering with deep LLM reasoning.
- **Real-time Extension**: Instant analysis of the current browsing context.

### How the layers decide

Only claims score, not coincidences. A page with a credential form is flagged as brand
impersonation when it _presents itself_ as a brand — the brand name in its title or a heading —
and is served from a domain that is not that brand's. A page that merely links to other
companies is not: `github.com/login` was previously scored 48/100 SUSPICIOUS purely for
mentioning "google", "microsoft" and "amazon" in its SSO buttons and footer. Body mentions are
still recorded in the evidence, and the LLM's page digest separates `brands_claimed` from
`brand_mentions_in_body`, so the model is not invited to make the same mistake.

## Quickstart

### Using Docker (Recommended)

1. Clone the repository.
2. Ensure you have Docker and Docker Compose installed.
3. Run:
   ```bash
   docker compose up -d
   ```
4. The frontend will be available at `http://localhost:8080` and the backend API at `http://localhost:8000`.

_Note: The first run will pull the Llama 3.1 model (approx. 4.7GB) via Ollama, which may take some time depending on your connection._

### Local Development

**Backend:**

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:**

```bash
bun install
bun dev          # dashboard at http://localhost:8080
```

**Run the built site (production server):**

```bash
bun run build
PORT=8080 bun .output/server/index.mjs   # same entry point the Docker image uses
```

`vite preview` does **not** serve this app: the build targets Nitro's `cloudflare-module` preset,
so the only entry points are `.output/server/index.mjs` (bun/node, used by `docker/Dockerfile.frontend`)
or `npx wrangler --cwd .output dev` for a Cloudflare deploy.

### What happens to what you type

- `hianime.to`, `example.com/login`, `//example.com`, `https:/example.com` — all normalised to an
  absolute URL (`https://…)` before the SSRF guard runs, by both the dashboard and the backend
  (`normalize_url_input` in `backend/app/core/security.py`). A bare hostname is the most natural
  way to name a site and is not a security decision, so it is no longer refused with
  "Scheme '' is not allowed". `javascript:`, `data:` and `file:` are still rejected, by name.
- If the host does not answer, the report says so in words — "the connection attempt timed out —
  the host is unreachable from this network" — instead of a bare `webpage.fetch_failed` code, and
  the screenshot/brand-clone phase is skipped, because there is no rendered page to compare. The
  URL, domain, ML pre-filter and LLM layers still run and are still reported.
- Unreachable hosts fail fast: the page fetch caps the TCP connect attempt at 8 s instead of
  letting the whole per-layer budget expire.

## API Reference

| Endpoint                     | Method | Description                                                 |
| ---------------------------- | ------ | ----------------------------------------------------------- |
| `/api/v1/analyze`            | POST   | Submits content (URL/Email) for full multi-layer analysis.  |
| `/api/v1/analyze/url/stream` | POST   | Same scan, streamed as Server-Sent Events (see below).      |
| `/api/v1/history`            | GET    | Retrieves a paginated list of previous analysis results.    |
| `/api/v1/health`             | GET    | Returns the system status and connectivity to sub-services. |

### Progressive results (why a scan no longer feels like a 60 s hang)

The local LLM is 80-90% of a full scan, so waiting for one response meant staring at nothing
for a minute while information that already existed at 5 s sat unsent. `POST
/api/v1/analyze/url/stream` reports each stage as it completes instead:

| Event            | When                    | Payload                                                                 |
| ---------------- | ----------------------- | ----------------------------------------------------------------------- |
| `started`        | immediately             | the normalised target                                                   |
| `layer`/`layers` | as each layer finishes  | `url`, then `domain` + `webpage` evidence                               |
| `prefilter`      | after the ML pre-filter | score, method, calibration                                              |
| `provisional`    | before the LLM runs     | a **labelled** score over the deterministic layers only                 |
| `llm`            | when the verdict lands  | the LLM assessment (and the webpage layer, now carrying the screenshot) |
| `final`          | at the end              | the same payload as the non-streaming endpoint                          |

Measured on the reference box for an uncached `example.com` scan: `started` at 2 s, first
layer at 3 s, **provisional score at 5 s**, LLM verdict at 47 s. The dashboard renders the
provisional report immediately (banner: "PROVISIONAL — ... the on-device LLM reasoning step
is still running") and replaces it in place when the verdict arrives. A refused target is
still a plain 4xx with the same body as the non-streaming endpoint, so a refusal is never
mistaken for a stalled stream.

A streaming _cache hit_ resolves immediately and skips the intermediate events, since the
finished result already exists.

### Scan latency, and how to make it faster

Measured on a 4-core CPU-only box, page fetch on, over repeated scans:

| Mode                   | Request                       | Mean                  | Breakdown                                                                         |
| ---------------------- | ----------------------------- | --------------------- | --------------------------------------------------------------------------------- |
| Fast                   | `{"use_llm": false}`          | **8.3 s** (7.6-8.7 s) | fetch ~1.9 s, layers ~0.9 s, screenshot ~5.4 s                                    |
| Full                   | `{"use_llm": true}` (default) | **~55-62 s**          | the above plus 32-48 s of local `llama3.2` inference                              |
| Full, unreachable host | any                           | ~58 s                 | connect 8.8 s, domain 10.7 s (overlapped with the fetch), no screenshot, LLM 38 s |

Every response carries `timings` (per phase) and `latency_ms`, so "it is slow" is answerable
without profiling. The local LLM is 80-90% of a full scan and runs on the CPU: `llama3.2`
measured 5.3-5.9 tokens/s generation and ~39 tokens/s prefill here, so a 600-token prompt plus
an 80-token answer is ~30 s of the scan on its own. `use_llm: false` is the supported fast path
for bulk work and pre-filter-only triage. The backend warms the model in the background at
startup (`LLM_WARMUP_ON_STARTUP`), which removes the ~15-30 s first-scan penalty after a
restart; `LLM_KEEP_ALIVE` keeps it resident between scans. For interactive use the dashboard
streams the scan instead (see _Progressive results_ above), so the deterministic verdict is
on screen in ~5 s even when the LLM needs a further 45 s.

What made the difference (each was a measured fix, not a guess):

| Fix                                                                                | Effect                                                                                                                |
| ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Domain lookups (RDAP/DNS/TLS) start _before_ the page fetch is awaited             | removes min(fetch, domain) ≈ 1-9 s from every scan                                                                    |
| No screenshot when the page fetch failed                                           | removes ~26 s of CPU and a misleading "visual: unavailable"                                                           |
| 8 s connect cap on the fetch                                                       | an unreachable host fails in 8 s instead of 21 s                                                                      |
| Accept the model's own vocabulary (`"Phishing"`, `80` for 0.8) instead of retrying | removes a second ~30 s inference on most scans, and stops discarding a real model verdict for the rules-only fallback |

## ML Pipeline

The CatBoost prefilter is trained offline and loaded by the backend at startup from
`backend/models/prefilter.cbm`. No model is bundled with this repo: until you train one,
every analysis reports `ml.deterministic_fallback` and the prefilter is deliberately left
out of the threat score.

1. **Download Data**: `python scripts/data/download_data.py --confirm` (opt-in public feeds)
2. **Collect benign deep URLs**: `python scripts/data/fetch_benign_urls.py --confirm`
   Adds real, path-bearing benign URLs from the Internet Archive. Skipping this step lets
   the model learn “URL has a path ⇒ phishing” and flag ordinary pages.
3. **Prepare Dataset**: `python scripts/data/prepare_dataset.py`
4. **Train Prefilter**: `python ml/training/train_prefilter.py`
   Training is **gated**: the candidate is scored on a leakage-free, time-ordered split and
   only written to `backend/models/prefilter.cbm` if it clears the bar in
   `ml/evaluation/gate.py`. A rejected run leaves the previously deployed model untouched and
   writes the reasons to `ml/evaluation/reports/train_gate.md`.
5. **Evaluate**: `python ml/evaluation/report.py`
   Writes `ml/evaluation/reports/latest.{json,md}` including both tier verdicts.

### Which gate tier the model passed — and what that means

There are two bars, named rather than silently tuned (`ml/evaluation/gate.py`):

| Tier     | What it certifies                                          | Used for                                                              |
| -------- | ---------------------------------------------------------- | --------------------------------------------------------------------- |
| `strict` | Precision-grade: fit to decide alone                       | Short-circuiting the pipeline without the later layers                |
| `triage` | Fit to be one disclosed signal among several (the default) | The 15%-weighted prefilter, whose verdict every other layer re-checks |

A purely lexical model does not reach `strict` on the public feeds — measured on the honest
split, the lowest threshold satisfying the false-positive ceiling reaches ~0.79 recall — so
holding deployment to that bar only ever produces an unvalidated leftover artifact and a
permanently red CI job. The default `triage` bar is enforced instead, and **every** report
carries both verdicts. Promote a model with `--gate-tier strict` when it is genuinely ready.

The gate also reports the false-positive rate against a ceiling widened by 1.96 standard
errors of the _measured_ benign sample (110 rows today, so ±5.6pp). That tolerance is printed
next to the threshold and shrinks by itself as benign data grows, so a candidate is never
rejected over a difference smaller than the measurement's own noise.

### The deployed model says what it is

`backend/models/prefilter.cbm.meta.json` and every analysis response carry the model's
provenance, so a score can be audited without training anything:

- `gate.tier`, `gate.passed`, `gate.strict_passed` — which bar it cleared (and which it did not)
- `split`/`split_mode`/`zero_day` — the split its metrics were measured on
- `metrics` — the honest held-out numbers, plus `decision_threshold` and the calibration used
- per-scan `prefilter.gate_tier`, `gate_passed`, `prefilter.decision_threshold`,
  `score_above_threshold`, `split`, `trained_at`

Two optional switches exist for the probability score and the operating point
(`--calibrate`, `--select-threshold`) and are **off by default**: with today's class mix every
available held-out slice is phishing-heavy, so a fitted map is driven by that mix rather than
by production traffic (a random slice measured worse: FPR@0.5 0.11 → 0.31; the time-tail slice
was degenerate because recent benign data is absent). They become the right fix once benign
coverage of the observation window improves.

See `ml/README.md` for the feature contract and a full explanation of the gate.

## Browser Extension Installation

```bash
cd extension
bun install
bun run build          # writes extension/dist (Chrome/Edge manifest)
bun run test           # 70 unit tests (includes the popup report)
```

**Chrome / Edge / Brave**

1. Go to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select `extension/dist`.

**Mozilla Firefox**

The Firefox package is a separate build artefact because the manifest differs (MV3 with
`background.scripts` instead of a service worker):

```bash
cd extension
bun run build && bun run zip:firefox   # -> extension/phishbrain-extension-firefox.zip
```

1. Open **`about:debugging#/runtime/this-firefox`**.
2. Click **Load Temporary Add-on…** and pick either
   `extension/phishbrain-extension-firefox.zip` (Firefox accepts a packaged `.zip`/`.xpi`) or the
   unzipped folder's `manifest.json`. Trust it when asked.
3. The add-on appears as **PhishBrain007**; pin it from the toolbar's extensions menu.
   Temporary add-ons are removed when Firefox closes — for a permanent install, submit the same
   zip to https://addons.mozilla.org/developers/ (free) or self-sign it:
   `npx web-ext sign --source-dir extension/dist --artifacts-dir . --api-key … --api-secret …`.

The package is validated with Mozilla's own linter (`npx web-ext lint --source-dir dist
--self-hosted`): **0 errors, 0 notices**. The remaining warnings are seven
`UNSAFE_VAR_ASSIGNMENT` notices from inside the bundled React DOM (this project's own source
contains no `innerHTML`) and one Android-only minimum-version note. The manifest declares its
data collection (`browsingActivity`, `websiteContent`), which Firefox 140+ requires for new
submissions.

Set the backend URL in the extension Options page (default `http://127.0.0.1:8000`). With the
**“Fall back to hosted live scans”** toggle on (default) and no local backend, the extension uses
your hosted `…/api/public/scan` and `…/api/public/email-scan` endpoints automatically.

### What the toolbar popup shows

The popup is a full, explainable report — not just a badge. For the current tab it renders the
verdict (risk level, `n/100` threat score, confidence, latency, analysis ID), the deduplicated
**“Why this verdict”** indicators, the complete assessment text, a **layer-by-layer breakdown**
(URL structure, Domain & DNS, Page content, Email context) with each layer's risk and raw
evidence, the **ML pre-filter** card (whether CatBoost was consulted, its score, weight, gate
tier and decision threshold), the **local LLM** assessment (model, classification,
confidence, reasoning summary), the **visual / brand-clone** result (with the captured screenshot
and the matched brand's reference side by side, plus the edge-map overlay, per-region similarity
heatmap and comparison score), the recommended action, and any degraded layers. Demo results are
clearly labelled `DEMO DATA`.

### Alerts

Three signals fire on a detection, all configurable from the Options page:

- **Toolbar badge** — `OK` / `!` / `!!` with a colour and a hover title carrying the score.
- **In-page warning banner** on `SUSPICIOUS`/`HIGH_RISK` pages above your threshold, with
  _View Detailed Analysis_, _Go Back_ and _Proceed Anyway_ (which adds the host to your allowlist).
- **Desktop notification** on `HIGH_RISK`, so a hit reaches you even while you are on another tab
  (disabled by setting banner mode to _silent_; requires the `notifications` permission declared
  in both manifests).

Set `alertWebhookUrl` to also POST every high-risk detection to a SOC/SIEM or email relay.

## Deploying with 100% open-source infrastructure

Everything PhishBrain needs is FOSS: Docker/Podman, PostgreSQL, Valkey, Ollama, FastAPI, Bun. No SaaS accounts, no paid APIs.

### 1. Single host (recommended)

Any Linux box or VPS (Hetzner, OVH, or your own hardware) with 4 CPU / 8 GB RAM (16 GB if you run Llama 3.1 8B comfortably):

```bash
git clone <your-repo> phishbrain && cd phishbrain
cp .env.example .env          # edit secrets, weights, thresholds
docker compose up -d --build  # or: podman-compose up -d --build
docker compose logs -f backend
```

Services: `frontend` :8080, `backend` :8000, `postgres`, `valkey`, `ollama` (pulls Llama 3.1 on first boot, ~4.7 GB).

### 2. Put it behind a free TLS reverse proxy

Caddy (open source, automatic Let's Encrypt certs) — add a `Caddyfile`:

```text
phishbrain.example.com {
    handle /api/* { reverse_proxy backend:8000 }
    handle        { reverse_proxy frontend:8080 }
}
```

and a service in `docker-compose.yml`:

```yaml
caddy:
  image: caddy:2-alpine
  ports: ["80:80", "443:443"]
  volumes:
    - ./Caddyfile:/etc/caddy/Caddyfile
    - caddy_data:/data
  depends_on: [backend, frontend]
```

Nginx + Certbot works equally well if you prefer it.

### 3. Kubernetes (K3s) for multi-node

- Install [K3s](https://k3s.io) (Apache-2.0) on your nodes.
- Convert the compose file with `kompose convert`, or write plain manifests.
- Run Postgres via the CloudNativePG operator, Valkey as a StatefulSet, Ollama as a Deployment with a GPU node selector and a PVC for models.
- Expose with Traefik (bundled with K3s) + cert-manager for TLS.

### 4. GPU acceleration (optional)

Install the NVIDIA container toolkit and add to the `ollama` service:

```yaml
deploy:
  resources:
    reservations:
      devices:
        - { driver: nvidia, count: 1, capabilities: [gpu] }
```

Swap `OLLAMA_MODEL` to `llama3.1:8b-instruct-q4_K_M` on smaller machines, or `mistral` / `qwen2.5` — all open weights.

### 5. Hardening checklist

- Change `POSTGRES_PASSWORD`, keep Postgres/Valkey off public ports (no `ports:` mapping).
- Keep `STORE_RAW_EMAIL=false` and short `RETENTION_DAYS` / `VISUAL_RETENTION_DAYS` for privacy
  compliance; set `VISUAL_RETENTION_DAYS=0` (or `VISUAL_SCREENSHOT_MODE=off`) to store no screenshots
  at all.
- Restrict CORS to your dashboard origin and your extension ID.
- Back up with `pg_dump` on a cron; snapshot the `ollama_data` volume to avoid re-pulling models.
- Optional observability: Prometheus + Grafana + Loki, all open source.

### 6. Dashboard-only deploy

The dashboard is a TanStack Start app and can run anywhere Node/Bun runs.

The default build target is a **Cloudflare Worker** (a `fetch` handler), which does _not_ serve
under `bun .output/server/index.mjs` — it exits immediately. Build with the Node server preset:

```bash
bun install
NITRO_PRESET=node-server bun run build      # writes .output/server/index.mjs (a real HTTP server)
PORT=8080 HOST=0.0.0.0 bun .output/server/index.mjs
```

Verified: after a `node-server` build, `/analysis`, `/history` and `/settings` all return `200`.
To deploy the Worker target instead, build with the default preset and use `npx wrangler deploy`
(`.output/nitro.json` records the preset and the preview/deploy commands).

## Academic & Ethics Note

PhishBrain is a research tool developed for academic and educational purposes. It is designed to demonstrate the feasibility of local-first phishing detection. It does not utilize any proprietary APIs (like Google Safe Browsing or OpenAI) to ensure complete data sovereignty. Users should use this tool responsibly and not rely solely on it for critical security decisions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## PhishBrain007 — custom domain, alerts, email analysis and screenshots

### 1. Publish on your own domain (`www.phishbrain07.app`)

1. Publish the project in Lovable (slug `phishbrain007`) — it goes live at `https://phishbrain007.lovable.app`.
2. Buy/own `phishbrain07.app`, then in Lovable open **Project Settings → Domains → Connect domain** and add
   both `phishbrain07.app` and `www.phishbrain07.app`. Set DNS at your registrar:
   - `A  @    185.158.133.1`
   - `A  www  185.158.133.1`
   - `TXT _lovable  <value shown in the connect dialog>`
3. Wait for verification + automatic TLS. Your public API surface is then:
   - `https://www.phishbrain07.app/api/public/scan` — POST `{"url": "..."}` (live page scan)
   - `https://www.phishbrain07.app/api/public/email-scan` — POST sender/subject/body + links
     (email-layer analysis; the first link is live-scanned server-side). Both are defined in
     `src/routes/api/public/` and ship inside the dashboard deploy.
4. The extension already ships with both URLs as defaults
   (`extension/src/services/api.ts` — `DEFAULT_CLOUD_SCAN_URL`, `DEFAULT_CLOUD_EMAIL_URL`) and both
   manifests list the domains in `host_permissions`. Rebuild with `cd extension && bun run build`.
5. Firefox: `cd extension && bun run build && bun run zip:firefox`, then upload
   `extension/phishbrain-extension-firefox.zip` at https://addons.mozilla.org/developers/ (free).
   Chrome/Edge users load `extension/dist` unpacked, or sign the same code for the Web Store.

### 2. Real-time alerts

Options → **Real-time alerts (opt-in)**: enable it and paste a webhook URL (Slack workflow, n8n,
email relay, SIEM). Every detection at or above your banner threshold is POSTed as a JSON SOC event
(`analysis_id`, `url`, `domain`, `threat_score`, `risk_level`, `indicators`, `recommended_action`).
It is off by default, so nothing leaves the browser unless the user opts in.

### 3. Screenshot / brand-clone analysis

There are two independent visual paths:

**Client-side (recommended, works everywhere incl. Firefox with no backend).**
Options → **Screenshot & visual clone analysis (opt-in)**. The extension captures the visible tab
with `tabs.captureVisibleTab`, computes a 64-bit perceptual hash on-device
(`extension/src/background/phash.ts` — same format as the Python backend) and compares it against
`extension/data/reference_hashes.json`, which ships with 16 real brand-login fingerprints and is
bundled into the add-on as `reference_hashes.json` (Adobe is a documented, testable gap — see below).
A layout match on a non-official domain adds a “possible
visual clone” indicator and re-scores the result. A **downscaled thumbnail of the exact screenshot**
the verdict was scored on is kept with the result and shown in the toolbar popup's _Visual /
brand-clone analysis_ card, so the evidence is visible rather than only scored. When the brand is
matched, the popup shows the captured page **side by side with the bundled reference** for that
brand (`extension/data/reference_thumbnails.json`, written by the same generator). Options → **Stored
screenshot style** can render the thumbnail as a **wireframe** — black-on-white layout edges — which
keeps the page's structure while dropping colour and legible text, so evidence can be shown without
retaining a readable copy of the page. Screenshots never leave the device. Because brand
pages drift and browsers render differently, the detector re-learns each brand's fingerprint when
you visit its genuine login page (same engine = accurate matches).

Regenerate the fingerprints any time with the installed Chrome (no Docker, no Python):

```bash
bun scripts/data/generate_reference_hashes.ts   # writes extension/data/reference_hashes.json + reference_thumbnails.json
BRANDS="paypal,google" bun scripts/data/generate_reference_hashes.ts   # capture a subset
CAPTURE_ATTEMPTS=3 bun scripts/data/generate_reference_hashes.ts       # retry bot-walled brands more times
```

Captures that are uniform _or_ near-blank (bot walls, cookie interstitials) are rejected, so a
degenerate screenshot is never shipped as a brand's reference. A rejected capture also **drops any
stale entry from a previous run** — otherwise a brand whose capture is now correctly refused would
keep an old, equally-useless hash and the file would claim a reference that was never captured.

Each brand is retried with a realistic browser identity — `AutomationControlled` disabled, `en-US`
locale, and a **persistent `--user-data-dir` profile** so consent cookies earned on the first attempt
are replayed on the next, which is what gets past most interstitials. Persistent failures are not
silent: the run writes `extension/data/reference_capture_report.json` and lists the brands it could
not capture, and any brand that fails without a matching entry in
`extension/data/known_reference_gaps.json` is flagged as an undocumented failure.

`known_reference_gaps.json` is the curated list of brands that genuinely cannot be captured from a
headless browser — currently **Adobe**, whose homepage and sign-in page both answer a
near-blank bot wall. `extension/tests/reference-gaps.test.ts` keeps it honest: a documented gap must
not also ship a reference or a thumbnail (the stale-entry bug above), every gap must carry a reason,
a status and a mitigation, and every shipped hash must be a valid 64-bit pHash. If Adobe is ever
captured for real, removing the gap entry makes the test pass again.

**Server-side (optional, deeper).** The self-hosted backend can still screenshot with Playwright and
compare inside `backend/app/analyzers/webpage/visual.py`. Seed it with the same file by running the
Python generator inside the Docker image:

```bash
python scripts/data/generate_reference_hashes.py   # Playwright captures; same output file
```

The backend also returns a downscaled data URL of the screenshot it compared, which the dashboard's
_Visual analysis_ card renders, so backend and extension show the same evidence. Control it with
`VISUAL_SCREENSHOT_MODE`: `pixels` (default, downscaled JPEG), `wireframe` (edge-only PNG — layout
without colour or readable text), or `off` (nothing leaves the server). `VISUAL_SCREENSHOT_MAX_WIDTH`
(default 480) caps the size.

**Structural comparison, not just a hash distance.** When a brand reference is available the popup
no longer stops at a single perceptual-hash distance. Both images are reduced to edge maps (layout
without colour or text), normalised to a common grid, and compared region by region
(`extension/src/lib/region-similarity.ts`): the card shows the two edge maps **overlaid** — amber
where only this page has structure, blue where only the reference does, white where they agree — a
per-region **similarity heatmap** (8×5 cells, red→green, each cell the Dice overlap of that region's
edges), and a single comparison score below the side-by-side screenshots. That turns “distance 24”
into a picture of _where_ the pages line up and where they do not.

### 3b. Visual-evidence retention

A stored screenshot is the most sensitive artefact PhishBrain keeps, so it is purged on its own,
shorter clock than the analysis it belongs to:

- `VISUAL_RETENTION_DAYS` (default `7`) — how long a stored screenshot is kept. After that the
  **image is dropped while the analysis record, score and indicators are kept**. `0` means “store
  none”: every sweep strips screenshots immediately.
- The sweep runs at startup and every `VISUAL_PURGE_INTERVAL_MINUTES` (default `360`), and can be
  disabled with `VISUAL_AUTO_PURGE_ENABLED=false`. The same startup pass now also enforces
  `RETENTION_DAYS` for analyses — which had been configured but never actually applied.
- **One-click “Clear all visual evidence”** exists in both surfaces:
  - Dashboard → _Settings → Privacy & data_ → `POST /api/v1/visual-evidence/clear`.
  - Extension → _Options → Screenshot & visual clone analysis_ → **Clear all visual evidence**
    (removes stored thumbnails from every result and forgets the learned brand fingerprints).

  Both keep the analyses themselves; only the images go. `GET /api/v1/visual-evidence/policy` reports
  the active window so the dashboard shows the real configured value. The extension shows its own
  retention field (`visualRetentionDays`, default 7) and a live count of what is stored.

Note: brand pages change over time (consent banners, A/B tests) and hash distances across browser
engines are noisier than within one engine — treat visual matches as one evidence layer among many,
not as a standalone verdict.

### 4. Email analysis

- Dashboard: `/analysis` now has a **Email message** tab — paste From / Reply-To / display name /
  subject / body. Sender-domain mismatch, brand impersonation, urgency and credential-request
  language are scored, and the first link in the body is fetched live for URL, domain and webpage
  evidence.
- Extension: on Gmail and Outlook Web the content script parses the open message (sender,
  reply-to, display name, subject, body, links; SPF/DKIM/DMARC are marked “not available from
  browser context” — they can only be verified by a mail server) and re-runs whenever you open a
  conversation (SPA-aware: hash/navigation changes + a light DOM poll). The scan first tries the
  local backend's `/api/v1/analyze/email`; with the hosted fallback enabled it posts to
  `…/api/public/email-scan` instead, so email analysis works with nothing but the published
  dashboard. Results appear in the toolbar badge, the popup, and as a banner when the score
  crosses your threshold.
