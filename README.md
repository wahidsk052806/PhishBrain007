# PhishBrain 🧠

Privacy-first, explainable phishing detection for web pages, URLs and email. Four deterministic
layers (URL, domain, page, email) are combined with a **CatBoost pre-filter**, a **local LLM
verdict** and a **rendered-screenshot brand-clone comparison** into one 0–100 threat score that
carries its own evidence.

Nothing leaves your infrastructure: no Google Safe Browsing, no OpenAI, no third-party API.

---

## Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quickstart](#quickstart)
- [API](#api)
- [How a score is produced](#how-a-score-is-produced)
- [ML pipeline (CatBoost pre-filter)](#ml-pipeline-catboost-pre-filter)
- [Browser extension](#browser-extension)
- [Firefox: temporary and permanent install](#firefox-temporary-and-permanent-install)
- [Deployment](#deployment)
- [Verify it yourself](#verify-it-yourself)
- [Troubleshooting](#troubleshooting)
- [Documentation map](#documentation-map)

---

## Architecture

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

Three ways to run it, and all three are supported:

| Shape | What runs where | Full pipeline? |
| --- | --- | --- |
| **Docker Compose** on one box | dashboard + backend + Postgres + Valkey + Ollama | ✅ everything |
| **Dashboard on Cloudflare Workers**, backend on any Linux VM behind a tunnel | static/SSR dashboard, full backend at `api.<your-domain>` | ✅ everything (recommended for a public site) |
| **Dashboard alone** | Workers/Nitro only | ❌ reduced: real fetch, DNS-over-HTTPS, RDAP, DOM — no CatBoost, no LLM, no Playwright |

Runner-up detail for all three: [`deploy/README.md`](deploy/README.md).

## Features

- **Four evidence layers** — URL structure, domain registration/DNS/TLS, rendered page (forms,
  credential fields, brand mismatch, favicon), and email (sender/Reply-To mismatch, lookalike
  domains, display-name spoofing, link text vs destination, and the destination itself scored by the
  URL/domain layers).
- **CatBoost pre-filter** — a trained lexical model contributing a disclosed 15% of the base score.
- **Local LLM verdict** — `llama3.2:3b` through Ollama on CPU; structured JSON, never raw
  chain-of-thought, with a labelled deterministic fallback when the model is unavailable.
- **Screenshot / brand-clone evidence** — Playwright renders the page, a perceptual hash is compared
  against a local reference set, and the captured thumbnail travels with the report.
- **Explainable everywhere** — every layer ships its raw evidence; every result is exportable as
  JSON/CSV and as a SOC event.
- **Progressive results** — the deterministic verdict is on screen in ~5 s; the LLM verdict replaces
  it in place when it lands.
- **Extension that needs no setup** — a production build ships the deployed API/dashboard origins,
  so an install on a stranger's device scans immediately.

### How the layers decide

Only claims score, not coincidences. A page with a credential form is flagged as brand
impersonation when it *presents itself* as a brand — in its title or a heading — **and** is served
from a domain that is not that brand's. A page that merely links to other companies is not:
`github.com/login` used to score 48/100 SUSPICIOUS purely for mentioning "google", "microsoft" and
"amazon" in SSO buttons. Body mentions stay in the evidence, and the LLM digest separates
`brands_claimed` from `brand_mentions_in_body` so the model is not invited to repeat the mistake.

The same rule is implemented in both engines, so `netflix.com` reports **SAFE, single digits** in
the backend *and* in the built-in scanner (it previously matched "apple" inside an
`apple-touch-icon` `<link>` tag and lost 20 points for markup).

Email links are judged the same way — on claims, not coincidences. The visible label only counts as
a destination claim when it *names a host* (`www.paypal.com`), never when it is prose (`Join
Superset`, `View in browser`); otherwise every newsletter produced a "text/href mismatch" and
unrelated messages all settled on the same 20/100. On top of that, the riskiest link in the message
is scored as a destination by the URL and domain layers, so an innocuous message with one link to a
fresh typosquat is now HIGH_RISK instead of SAFE. The link is scored from strings and never opened —
reading it server-side would tell the sender the message was read, so the destination's own content
is disclosed as not examined rather than guessed at. Link evidence is *corroborative*: it can raise
an email's verdict, and a clean link can never lower it.

## Quickstart

### Docker (recommended)

```bash
git clone <your-repo> phishbrain && cd phishbrain
cp .env.example .env               # set POSTGRES_PASSWORD and anything you want to tune
docker compose up -d --build
docker compose logs -f backend
```

Dashboard <http://localhost:8080> · API <http://localhost:8000/api/v1/health>.
First boot pulls `llama3.2:3b` (~2 GB) — that pull and the backend read the **same**
`OLLAMA_MODEL`, so they cannot disagree.

### Local development

```bash
# backend (Python 3.12 — 3.13 has no wheels for CatBoost / y-py)
cd backend
python -m venv venv
venv/Scripts/python.exe -m pip install -r requirements.txt        # Windows
# source venv/bin/activate && pip install -r requirements.txt     # macOS / Linux
venv/Scripts/python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# dashboard + extension (in another terminal, from the repo root)
bun install && bun dev            # http://localhost:8080

# extension
cd extension && npm ci && npm run build      # dist/ (Chrome/Edge)
```

Ollama is optional: without it every scan reports `llm.deterministic_fallback` and the deterministic
verdict stands. To include the model, run `ollama serve` and `ollama pull llama3.2:3b`.

### Running it in VS Code

Open the folder that contains `backend/`, then use **three terminals** (the full command-by-command
version, including the PowerShell/shell variants and every error message with its fix, is in
[`deploy/README.md`](deploy/README.md) and [`workingexplaination.txt`](workingexplaination.txt)):

| Terminal | Command | Serves |
| --- | --- | --- |
| 1 | `ollama serve` (once) | model server on `:11434` |
| 2 | `cd backend && venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000` | API on `:8000` |
| 3 | `bun dev` | dashboard on `:8080` |

### What happens to what you type

`hianime.to`, `example.com/login`, `//example.com`, `https:/example.com` are all normalised to an
absolute URL before the SSRF guard runs, in both the dashboard and the backend. A bare hostname is
how people name a site, not a security decision. `javascript:`, `data:` and `file:` are still
refused by name.

An unreachable host fails **fast** (8 s connect cap), is reported as a report — not a 5xx — and
skips the screenshot phase, because there is no rendered page to compare. The URL, domain,
pre-filter and LLM layers still run and are still reported.

## API

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/v1/analyze/url` | POST | Full URL/page analysis |
| `/api/v1/analyze/url/stream` | POST | Same scan, streamed as Server-Sent Events |
| `/api/v1/analyze/page` | POST | Analysis with a client-side DOM summary |
| `/api/v1/analyze/email` | POST | Email-layer analysis |
| `/api/v1/analysis/{id}` | GET | One stored report |
| `/api/v1/history` | GET | Paginated history |
| `/api/v1/alerts` | GET | Detections at/above the threshold |
| `/api/v1/feedback` | POST | Analyst verdict on an analysis |
| `/api/v1/export/{id}` | GET | JSON/CSV export |
| `/api/v1/health` | GET | Status of database, cache and Ollama |
| `/api/v1/config` | GET | Weights, thresholds, model name, brands |

`POST /api/v1/analyze/url` body:

```json
{ "url": "https://example.com/login", "fetch_page": true, "use_llm": true }
```

`use_llm: false` is the supported fast path (~8 s instead of ~55–60 s) for bulk work and
pre-filter-only triage.

### Progressive results

| Event | When | Payload |
| --- | --- | --- |
| `started` | immediately | normalised target |
| `layer`/`layers` | per layer | URL, then domain + webpage evidence |
| `prefilter` | after the pre-filter | score, method, calibration |
| `provisional` | before the LLM | a **labelled** score over deterministic layers |
| `llm` | verdict ready | LLM assessment + webpage layer (now carrying the screenshot) |
| `final` | end | identical to the non-streaming response |

Measured on a 4-core CPU box for an uncached `example.com`: `started` 2 s, first layer 3 s,
**provisional score 5 s**, LLM verdict 47 s. The dashboard renders the provisional report
immediately and replaces it in place.

### Latency (4-core CPU, page fetch on)

| Mode | Request | Mean | Breakdown |
| --- | --- | --- | --- |
| Fast | `{"use_llm": false}` | **8.3 s** | fetch ~1.9 s, layers ~0.9 s, screenshot ~5.4 s |
| Full, verdict already fixed | `{"use_llm": true}` | **~11 s** | the fast path; the model is skipped (`llm.not_needed`) because ±15 cannot cross a risk boundary |
| Full | `{"use_llm": true}` | **~35–48 s** (was 55–62 s) | the above + 20–40 s of `llama3.2` inference |
| Full, unreachable host | any | ~20 s | connect 8.8 s, domain 10.7 s (overlapped), no screenshot, no model if the score is decided |

The model's share is arithmetic on CPU: `llama3.2:3b` generates at ~5 tokens/s and
prefills at ~20–48 tokens/s on 2–4 cores, so a 60–120-token JSON verdict cannot
finish faster than ~15 s. What changed in this release is the waste around it —
a bounded generation cap, a ~40 % smaller prompt, no re-sent page text on a
retry, and no model call at all when its bounded ±15 adjustment provably cannot
move the verdict. See `deploy/README.md` §4d for the measurements and the knobs.

Every response carries `timings` (per phase) and `latency_ms`, so "it is slow" is answerable
without a profiler. The measured fixes that got it here: domain lookups start *before* the fetch
is awaited; no screenshot when the fetch failed (saves ~26 s); an 8 s connect cap; and accepting
the model's own vocabulary (`"Phishing"`, `80` for 0.8) instead of paying for a second inference.

## How a score is produced

```text
layers  = 0.30·url + 0.30·domain + 0.20·webpage + 0.20·email      (weights normalised from config)
score   = (1 − 0.15)·layers + 0.15·catboost                     (PREFILTER_WEIGHT = 0.15)
LLM     = a bounded adjustment (±) plus a written assessment
verdict = SAFE (<30) · SUSPICIOUS (30–65) · HIGH_RISK (≥65)
```

The pre-filter's share is deliberately capped below 0.5 so a lone lexical score cannot drag a clean
multi-layer analysis into SUSPICIOUS on its own. The LLM cannot invent indicators: it receives the
deterministic evidence and returns a structured verdict (`verdict`, `phishing_likelihood`,
`confidence`, `key_indicators`, `reasoning_summary`, `recommended_action`, `score_adjustment`).
Untrusted page text is passed as data, never as instructions — the prompt-injection sample in the
dashboard exercises exactly that.

### When a layer cannot run

A scan never fails because a layer is missing; it discloses it:

| Situation | Report says |
| --- | --- |
| Ollama down / model missing / unparsable output | `llm.deterministic_fallback` + rules-only assessment |
| Model slot busy (`MAX_CONCURRENT_LLM_SCANS`) | `llm.busy` — deterministic verdict stands |
| Verdict already fixed by the layers (±15 cannot cross a boundary) | `llm.not_needed` + "Local model: not consulted" — a decision, not a fault |
| Model exceeded `LLM_TIMEOUT_SECONDS` | `llm.timeout` |
| Playwright missing or render blocked | screenshot note inside the visual card |
| Host answered 404/5xx | "no page was served — an error body is the server's own notice" |
| DNS failure | report with URL/domain/pre-filter evidence, not an error |
| No trained CatBoost model | `ml.deterministic_fallback`; pre-filter left out of the score |

## ML pipeline (CatBoost pre-filter)

The model is trained offline and loaded at startup from `backend/models/prefilter.cbm`. **No model
is bundled with this repo** — until you train one, every analysis reports
`ml.deterministic_fallback` and the pre-filter is deliberately excluded from the score.

```bash
python scripts/data/download_data.py --confirm        # opt-in public feeds
python scripts/data/fetch_benign_urls.py --confirm    # real benign URLs with paths
python scripts/data/prepare_dataset.py
python ml/training/train_prefilter.py                 # gated: only deploys if it clears the bar
python ml/evaluation/report.py                        # ml/evaluation/reports/latest.{json,md}
```

Skipping step 2 is the classic mistake: without path-bearing benign URLs the model learns
"URL has a path ⇒ phishing" and flags ordinary pages.

**Two gate tiers**, named rather than silently tuned:

| Tier | Certifies | Used for |
| --- | --- | --- |
| `strict` | precision-grade, fit to decide alone | short-circuiting later layers |
| `triage` (default) | fit to be one disclosed signal among several | the 15%-weighted pre-filter |

A rejected candidate leaves the deployed model untouched and writes its reasons to
`ml/evaluation/reports/train_gate.md`. Every response also carries provenance — `gate.tier`,
`gate.passed`, `split`, `metrics`, `decision_threshold`, `score_above_threshold`, `trained_at` — so
a score can be audited without training anything. Feature contract and gate maths:
[`ml/README.md`](ml/README.md).

## Browser extension

Manifest V3, React popup, Shadow-DOM UI, no remote code. Two manifests: `manifest.json` (Chrome/Edge,
`background.service_worker`) and `manifest.firefox.json` (`background.scripts` + explicit
`data_collection_permissions`, required by Firefox 140+).

```bash
cd extension
npm ci
npm test                 # 201 unit tests
npm run typecheck
npm run build            # dist/            — Chrome/Edge
npm run build:firefox    # dist-firefox/    — the Firefox flavour
npm run zip:firefox      # phishbrain-extension-firefox.zip  (AMO / self-hosting)
npm run zip:chrome       # phishbrain-extension-chrome.zip
```

The Firefox bundle is a **separate artefact** on purpose: loading `dist/` in Firefox produces
`Error processing background.service_worker` and an add-on whose worker never starts, so nothing is
scanned. Always load `dist-firefox/`.

### Chrome / Edge / Brave

1. `chrome://extensions/`
2. Enable **Developer mode** (top right).
3. **Load unpacked** → select `extension/dist`.

### What it does

- Scans every page you open, and every message you open on Gmail / Outlook Web (sender, Reply-To,
  display name, subject, body, `text|href` link pairs, quoted-content flag).
- **Toolbar badge** `OK` / `!` / `!!` with score in the tooltip.
- **In-page banner** on SUSPICIOUS/HIGH_RISK pages: *View Detailed Analysis*, *Go Back*,
  *Proceed Anyway* (allowlists the host).
- **In-message verdict card** inside Gmail/Outlook instead of a page banner (a banner there covered
  the message header and offered to allowlist the mailbox itself).
- **Desktop notification** on HIGH_RISK, so a hit reaches you from another tab.
- **Opt-in SOC/SIEM webhook** for every detection at/above your threshold, with the delivery result
  shown back in Options.

The popup is a full report, not a badge: verdict, score, confidence, latency, ID, deduplicated
"why", every layer with raw evidence, the pre-filter card (score, weight, gate tier), the LLM
assessment, the visual/brand-clone card with the captured screenshot, the recommended action and any
degraded layers. Opening it on an unscanned tab starts the scan and shows a quick deterministic
verdict first.

### Configuration

Everything lives in the Options page, persisted with `storage.local` in both browsers:

| Setting | Default (production build) | Meaning |
| --- | --- | --- |
| Backend URL | `https://api.phishbrain007.app` | full pipeline |
| Dashboard URL | `https://phishbrain007.app` | report links; hosted endpoints are derived from it |
| Fall back to hosted live scans | on | `/api/public/scan` on the dashboard origin |
| Auto-scan | on | scan pages as you browse |
| Warning threshold | 50 | banner/notification cut-off |
| Allowlist | empty | domains never scanned |
| Screenshots | off (opt-in) | capture the visible tab for the visual layer |
| Real-time alerts | off (opt-in) | POST SOC events to your webhook |

A **development build** (`npm run dev`, `vite build --mode development`, the test suite) defaults to
`http://127.0.0.1:8000` / `http://127.0.0.1:8080` instead. A release build can override either with
`VITE_PHISHBRAIN_BACKEND_URL` / `VITE_PHISHBRAIN_DASHBOARD_URL`:

```bash
VITE_PHISHBRAIN_BACKEND_URL=https://api.example.app \
VITE_PHISHBRAIN_DASHBOARD_URL=https://example.app \
npm run build:firefox
```

### "Open Dashboard" opens the report, not the home page

After a scan, the popup button, the banner's *View Detailed Analysis* and the mail card's *Open full
report* all link to `<dashboard>/analysis?url=<scanned page>`. The dashboard re-runs the pipeline for
that address through whichever engine the browser can reach, so the report you land on includes the
screenshot, pre-filter and model verdict — including for results that came from the hosted fallback,
whose analysis ids no backend has ever stored.

## Firefox: temporary and permanent install

The complete version, with the pre-flight checks and Mozilla's own validator, is in
[`extension/README.md`](extension/README.md#install-in-firefox). Short form:

**Temporary (lasts until Firefox closes — for testing):**

1. `cd extension && npm ci && npm run build:firefox`
2. Open `about:debugging#/runtime/this-firefox`.
3. **Load Temporary Add-on…** → pick `extension/dist-firefox/manifest.json`
   (the `.zip` works too) → **Open**.
4. Pin **PhishBrain007** from the extensions menu and open any `https://` page.

**Permanent (survives restarts, installs on any device):**

1. `npm run build:firefox && npm run zip:firefox`
2. Sign it — either
   - **AMO (free, listed or unlisted):** <https://addons.mozilla.org/developers/> → *Submit a New
     Add-on* → upload `phishbrain-extension-firefox.zip`; or
   - **Self-signed XPI (free):** create AMO API keys, then
     `npx web-ext sign --source-dir dist-firefox --api-key … --api-secret …`
3. Install the signed `.xpi`: Firefox opens it from `file://`, or serve it over HTTPS. AMO-signed
   builds update themselves (`browser_specific_settings.gecko.update_url` for self-hosted).
4. Fleet/lab machines: `policies.json` with `ExtensionSettings → installation_mode:
   force_installed` and your signed XPI URL.

An unsigned `.zip`/`.xpi` can only ever be a temporary install — Firefox has no "trust this
permanently" switch, which is why signing is the step that makes it permanent.

## Deployment

Everything about the public, zero-cost target — `phishbrain007.app` on Cloudflare Workers with the
full pipeline on an Oracle Always Free VM behind a Cloudflare Tunnel — is in
[`deploy/README.md`](deploy/README.md): domain, Worker deploy, VM, tunnel, compose, verification,
rate limiting and backups.

### Single host with Compose

Any Linux box / VPS with 4 CPU and 8 GB RAM (16 GB for an 8B model):

```bash
cp .env.example .env
docker compose up -d --build
```

Services: `frontend` :8080, `backend` :8000, `postgres`, `valkey`, `ollama`. Verified end to end:
`/api/v1/health` reports `database`, `cache` and `ollama` all `ok`, a live `netflix.com` scan returns
a SAFE verdict **with** an LLM assessment and a screenshot comparison, and the result is persisted
(so History and Alerts are populated).

### Hardening checklist

- Change `POSTGRES_PASSWORD`; publish no `ports:` for Postgres/Valkey (the prod compose publishes
  none at all and reaches the backend through a Cloudflare Tunnel).
- Size `MAX_CONCURRENT_LLM_SCANS` / `MAX_CONCURRENT_VISUAL_SCANS` to the host. The Chromium render
  and the model are both CPU-bound; with no ceiling, concurrent visitors make *every* scan miss its
  deadline. Extra requests queue for `SCAN_QUEUE_TIMEOUT_SECONDS`, then return the deterministic
  verdict labelled `llm.busy` / `visual.busy`.
- Keep `STORE_RAW_EMAIL=false` and short `RETENTION_DAYS` / `VISUAL_RETENTION_DAYS`. On a shared
  box, `VISUAL_RETENTION_DAYS=0` and `VISUAL_SCREENSHOT_MODE=wireframe` keep the comparison visible
  without storing a readable copy of a stranger's page.
- Restrict `CORS_ORIGIN_REGEX` to your dashboard origin plus the extension schemes
  (`chrome-extension://`, `moz-extension://`); loopback and RFC 1918 are allowed by default.
- Back up with `pg_dump` on a cron and snapshot the `ollama_data` volume.
- Put a rate limit on `/api/` at the edge (one free Cloudflare WAF rule is enough).

### Dashboard-only build

The default build target is a Cloudflare Worker. For a Node/Bun server build:

```bash
NITRO_PRESET=node-server bun run build        # writes .output/server/index.mjs
PORT=8080 HOST=0.0.0.0 bun .output/server/index.mjs
```

`vite preview` does not serve this app. A dashboard-only deployment scans with the reduced server
engine and says so in the report banner.

## Verify it yourself

```bash
# 1. the API is up and names every dependency
curl -s localhost:8000/api/v1/health

# 2. a full pipeline scan (screenshot + pre-filter + LLM)
curl -s -X POST localhost:8000/api/v1/analyze/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","fetch_page":true}' \
  | python -c "import json,sys; d=json.load(sys.stdin); print(d['risk_level'], d['threat_score'], d['llm_assessment']['model'], d['prefilter']['model_trained'])"

# 3. the same scan, streamed
curl -N -X POST localhost:8000/api/v1/analyze/url/stream \
  -H 'Content-Type: application/json' -d '{"url":"https://example.com"}'

# 4. an unregistered host is a REPORT (200), not a 5xx
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8000/api/v1/analyze/url \
  -H 'Content-Type: application/json' -d '{"url":"https://this-domain-does-not-exist-9z8x.test"}'

# 5. the dashboard serves the analysis route with a deep link
curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost:8080/analysis?url=https%3A%2F%2Fexample.com'

# 6. the test suites
cd backend && venv/Scripts/python.exe -m pytest -q
cd ../extension && npm test && npm run typecheck && npm run check:content
cd .. && ./node_modules/.bin/tsc --noEmit
```

A healthy full scan shows `llm_assessment.model` naming the model (`llama3.2`) and
`prefilter.model_trained: true` when a trained model is deployed.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Report says `LLM unavailable … deterministic rule-based evidence only` while `/health` says `ollama: ok` | `OLLAMA_MODEL` names a tag that was never pulled (`llama3.2:3b` vs `llama3.2`) | `ollama list`, then pull exactly what `OLLAMA_MODEL` says (the compose init script does this) |
| Every scan re-loads the model / first scan very slow | model evicted between scans | keep `LLM_KEEP_ALIVE=30m`, `LLM_WARMUP_ON_STARTUP=true` |
| `llm.busy` under load | single model slot on a small box | expected; raise `MAX_CONCURRENT_LLM_SCANS` only with the CPU to back it |
| Visual card says "unavailable" | Playwright browsers not installed, or the page 404'd | `python -m playwright install chromium`; a 404 has no page to compare |
| Popup says "Backend unavailable" | backend down *and* hosted endpoint unreachable | start the backend, or fix the Dashboard URL |
| Popup says "Hosted fallback" | no local backend, hosted scan answered | correct for a hosted-only install |
| Firefox: nothing is scanned | `dist/` loaded instead of `dist-firefox/` | `npm run build:firefox`, load `dist-firefox/manifest.json` |
| Firefox: add-on disappears after restart | temporary install | sign the package (AMO or `web-ext sign`) |
| Dashboard: "backend ok" but reduced layers | the browser reached a different backend host | Settings → Backend URL; the report banner names the engine that answered |
| `vite preview` shows nothing | wrong preset | use `.output/server/index.mjs` or `wrangler` |

## Documentation map

| File | What it covers |
| --- | --- |
| [`workingexplaination.txt`](workingexplaination.txt) | **Everything**: technologies and why, request workflows, scoring, data model, security, failure modes, file map |
| [`deploy/README.md`](deploy/README.md) | Zero-cost public deployment on `phishbrain007.app` |
| [`extension/README.md`](extension/README.md) | Extension build, store submission, source packaging for review |
| [`ml/README.md`](ml/README.md) | Pre-filter feature contract and the deployment gate |
| [`AGENTS.md`](AGENTS.md) | Repository conventions for automated contributors |

## Academic & Ethics Note

PhishBrain is a research and teaching tool demonstrating local-first phishing detection. It uses no
proprietary threat API, and it should not be the only defence behind a real security decision.

## License

MIT — see [LICENSE](LICENSE).
