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

## Quickstart

### Using Docker (Recommended)

1. Clone the repository.
2. Ensure you have Docker and Docker Compose installed.
3. Run:
   ```bash
   docker compose up -d
   ```
4. The frontend will be available at `http://localhost:8080` and the backend API at `http://localhost:8000`.

*Note: The first run will pull the Llama 3.1 model (approx. 4.7GB) via Ollama, which may take some time depending on your connection.*

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
bun dev
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/analyze` | POST | Submits content (URL/Email) for full multi-layer analysis. |
| `/api/v1/history` | GET | Retrieves a paginated list of previous analysis results. |
| `/api/v1/health` | GET | Returns the system status and connectivity to sub-services. |

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
4. **Train Prefilter**: `python scripts/data/train_prefilter.py`
   Training is **gated**: the candidate is scored on a held-out split and only written to
   `backend/models/prefilter.cbm` if it clears the minimum bar in `ml/evaluation/gate.py`.
   A rejected run leaves the previously deployed model untouched and writes the reasons to
   `ml/evaluation/reports/train_gate.md`.
5. **Evaluate**: `python scripts/data/evaluate.py`
   Writes `ml/evaluation/reports/latest.{json,md}` including the gate verdict.

See `ml/README.md` for the feature contract and a full explanation of the gate.

## Browser Extension Installation

```bash
cd extension
bun install
bun run build
```

1. Open Chrome / Edge / Brave and go to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select `extension/dist`.
4. Firefox: `cd extension && bun run build && bun run zip:firefox`, then load
   `extension/phishbrain-extension-firefox.zip` via
   `about:debugging#/runtime/this-firefox` (development) or submit it to
   https://addons.mozilla.org/developers/ (permanent, free).

Set the backend URL in the extension Options page (default `http://127.0.0.1:8000`). With the
**“Fall back to hosted live scans”** toggle on (default) and no local backend, the extension uses
your hosted `…/api/public/scan` and `…/api/public/email-scan` endpoints automatically.

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
- Keep `STORE_RAW_EMAIL=false` and a short `RETENTION_DAYS` for privacy compliance.
- Restrict CORS to your dashboard origin and your extension ID.
- Back up with `pg_dump` on a cron; snapshot the `ollama_data` volume to avoid re-pulling models.
- Optional observability: Prometheus + Grafana + Loki, all open source.

### 6. Dashboard-only deploy

The dashboard is a TanStack Start app and can run anywhere Node/Bun runs:

```bash
bun install && bun run build
VITE_API_URL=https://phishbrain.example.com bun .output/server/index.mjs
```



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
`data/reference_hashes.json`, which ships with 10 real brand-login fingerprints and is bundled into
the add-on as `reference_hashes.json`. A layout match on a non-official domain adds a “possible
visual clone” indicator and re-scores the result. Screenshots never leave the device. Because brand
pages drift and browsers render differently, the detector re-learns each brand's fingerprint when
you visit its genuine login page (same engine = accurate matches).

Regenerate the fingerprints any time with the installed Chrome (no Docker, no Python):

```bash
bun scripts/data/generate_reference_hashes.ts   # writes data/reference_hashes.json
```

**Server-side (optional, deeper).** The self-hosted backend can still screenshot with Playwright and
compare inside `backend/app/analyzers/webpage/visual.py`. Seed it with the same file by running the
Python generator inside the Docker image:

```bash
python scripts/data/generate_reference_hashes.py   # Playwright captures; same output file
```

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
