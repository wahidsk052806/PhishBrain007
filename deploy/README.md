# Deploying PhishBrain on `phishbrain007.app` (zero-cost, open source)

This is the runbook for putting **this** repository on the public internet so that

- the extension works on **any device** with no setup (it ships knowing where its
  backend is),
- the dashboard is reachable at `https://phishbrain007.app`,
- the **full** analysis runs for every user — Playwright screenshot/brand
  comparison, the CatBoost pre-filter and the Ollama LLM verdict, not the reduced
  serverless path.

Everything below is FOSS or a free tier. What is **not** free is the domain name
itself — see the cost table.

---

## 1. What goes where

| Host                     | Serves                                              | Runs on                                        | Cost                     |
| ------------------------ | --------------------------------------------------- | ---------------------------------------------- | ------------------------ |
| `phishbrain007.app`      | Dashboard (TanStack Start Worker) + `/api/public/*` | Cloudflare Workers free plan                   | $0                       |
| `www.phishbrain007.app`  | same Worker                                         | Cloudflare Workers free plan                   | $0                       |
| `api.phishbrain007.app`  | FastAPI + Playwright + CatBoost + Ollama + Postgres | One always-free Linux VM                       | $0                       |
| Extension                | Popup, banner, in-message verdict                   | Chrome Web Store / Firefox AMO / Edge add-ons  | $0 (Firefox/Edge), $5 once (Chrome) |

Why the split: a Worker cannot run Chromium, a Python native model or a 2 GB LLM.
The Worker dashboard is the face of the project and the fast fallback; the VM is
the analysis engine. The extension prefers the VM (`Backend URL`), and falls back
to `<dashboard>/api/public/scan` when the VM is unreachable — that fallback is
deliberately labelled in the UI as missing the LLM/pre-filter/screenshot layers.

### Which free shape to pick

| If you… | Do this | What you get | What you give up |
| --- | --- | --- | --- |
| need a public API **today**, or the box just has to survive a demo/viva | **§4a** — this machine + a Cloudflare quick tunnel | full engine through a real `https://` URL in ~5 minutes, no card, no quota | the URL changes on restart and dies when the laptop sleeps |
| want it up 24/7 for other people | **§4b** — Oracle Always Free A1 (2 OCPU / 12 GB) | full engine, stable hostname, self-hosted Postgres | card for identity, regional capacity lottery, idle reclamation |
| only need the dashboard / a reduced scan, and no Python at all | **§3** — Workers alone | fetch + DNS + RDAP + DOM signals, free forever on the free plan | no CatBoost, no LLM, no Playwright screenshot |

Nothing else on the market is free *and* permanent for a 2–12 GB Docker workload
(carried-over limits for every provider I checked are in the caveats below).

**Cost reality (checked October 2026):**

| Item                                                    | Cost                                                                 |
| ------------------------------------------------------- | -------------------------------------------------------------------- |
| `.app` domain at Cloudflare Registrar (at cost)          | ≈ **$11/year** — the only unavoidable spend; skip it if you own it    |
| Cloudflare Workers free plan (100k requests/day)         | $0, no card required                                                  |
| Custom domain on a Cloudflare-managed zone              | $0                                                                    |
| Cloudflare Tunnel (`cloudflared`) on any plan            | $0                                                                    |
| Cloudflare free rate-limiting rule (1 rule, 10 s window) | $0                                                                    |
| Oracle Cloud Always Free Arm VM (2 OCPU / 12 GB)         | $0 (card for identity verification; see the caveat below)             |
| Firefox AMO submission                                  | $0                                                                    |
| Chrome Web Store developer registration                 | **$5 one-time** (not per extension)                                   |
| Edge Add-ons submission                                 | $0                                                                    |

Two honest caveats, because they decide whether "zero cost" survives contact
with reality:

1. **Oracle may reclaim idle Always Free instances.** Their policy is public:
   instances with low CPU/network/memory over a seven-day window can be
   reclaimed, and the Arm allowance has shrunk over time (older guides say
   4 OCPU / 24 GB; Oracle's current Always Free page documents **1,500
   OCPU-hours and 9,000 GB-hours per month**, i.e. 2 OCPU / 12 GB running
   continuously, split across one or two A1 VMs). 12 GB is still plenty for this
   stack. Section 9 adds a keepalive and an off-platform backup; if the VM is
   ever reclaimed you lose the machine, not the project — `git pull` +
   `docker compose up` rebuilds it.
2. **No free tier other than Oracle's fits this workload.** Render's free web
   services are 512 MB and sleep after 15 minutes with an ephemeral disk, Fly.io
   and Railway no longer have a free Docker tier, Koyeb's free instance is
   512 MB with no volumes, Google's free `e2-micro` has 1 GB RAM (less than the
   3B model needs), AWS's new-account offer is credits for six months rather than
   a permanent instance, and Hugging Face Spaces needs a paid plan for Docker and
   loses its volume. If Oracle gives you no capacity, the honest cheap fallback
   is a €4–6/month 4 GB VPS (Hetzner/OVH), not a free tier.
3. **A laptop is a legitimate host.** If you only need the API reachable for a
   demo, judging session or grading, run the same stack on your own machine and
   expose it through a Cloudflare quick tunnel — free, no card, no VM quota. See
   §4a; the only difference from the VM path is that the machine must be awake.

---

## 2. Domain and zone (10 minutes)

1. Register (or transfer) `phishbrain007.app` at
   [Cloudflare Registrar](https://dash.cloudflare.com) — at-cost pricing, no
   markup.
2. Add it as a **zone** in Cloudflare and point the registrar's nameservers at
   the two Cloudflare nameservers it shows you.
3. Wait for the zone to report **Active**. `.app` is on the HSTS preload list, so
   plain `http://` will never work — that is correct and expected; both Workers
   and the Tunnel terminate TLS for you.

Nothing else is needed here: the dashboard and the API get their DNS records in
the next two sections.

---

## 3. Dashboard on Workers (15 minutes)

The dashboard is already a Worker build (see `README.md` → Part 2.C). From the
repository root:

```bash
bun install
VITE_PHISHBRAIN_BACKEND_URL=https://api.phishbrain007.app \
  bun run build                     # writes .output/server/wrangler.json
node -e "console.log(require('./.output/nitro.json').preset)"   # cloudflare-module
npx wrangler login
npx wrangler deploy                 # -> https://<worker>.<you>.workers.dev
```

`VITE_PHISHBRAIN_BACKEND_URL` is what makes the **public site** use the full engine instead
of its serverless one: without it the dashboard's default backend is `http://localhost:8000`,
which on a visitor's machine means their own computer, so every visitor silently got the
reduced scan. With it, the Analyze page, History and Alerts all talk to
`api.phishbrain007.app` (CatBoost + Ollama + screenshots). A visitor can still override the
address on the Settings page, and the override only lives in their browser.

Attach the domain: **Workers & Pages → your worker → Settings → Domains &
Routes → Add custom domain** → `phishbrain007.app`, and again for
`www.phishbrain007.app`. Cloudflare creates the DNS records and the certificate.

Verify the fallback scan API that ships inside the Worker:

```bash
curl -s -X POST https://phishbrain007.app/api/public/scan \
  -H "content-type: application/json" -d '{"url":"https://example.com"}' | head -c 300
```

You want `"threat_score"` and a `layers` object. This path is fast and free; it is
what keeps the extension useful when the VM is down or restarting.

---

## 4a. No VM at all: your own machine behind a Cloudflare Tunnel (5 minutes)

This is the fastest way to get a real `https://…` API that the extension and a
hosted dashboard can call, and it costs nothing. It is also how you test the
deployment before spending an evening on Oracle capacity.

**Windows (this repository's development environment).** The stack is already
running locally (`docker compose up -d`, or `uvicorn app.main:app` for API-only):

```powershell
# 1. The API must be listening on a host port (dev compose publishes 8000).
curl.exe -s http://127.0.0.1:8000/api/v1/health

# 2. Install cloudflared once (winget), then open a quick tunnel.
winget install --id Cloudflare.cloudflared
cloudflared tunnel --url http://127.0.0.1:8000
```

cloudflared prints a `https://<random>.trycloudflare.com` URL. That URL is the
backend: put it in the extension's **Options → Backend URL** and it scans through
the full engine. No CORS change is needed — the backend already allows
`chrome-extension://*` and `moz-extension://*` origins (`CORS_ORIGIN_REGEX`).

**Linux/macOS:** identical, `cloudflared` from the distro package or a release
binary.

**Every layer still runs** — this is the part people ask about. A tunnel is a
reverse proxy for HTTP: it forwards the request to the same API process, which
does the same work it does on `127.0.0.1`. Nothing is disabled by being behind a
tunnel. The Playwright screenshot is taken by the machine running the backend,
not by the caller, so a scan issued from another computer still returns the
rendered page and the brand comparison; Playwright and Chromium must be
installed *there* (`playwright install chromium`, which the Docker image already
does). Two things do differ from a local-only setup:

- **Latency** gains the tunnel's round trip (tens of milliseconds) plus whatever
  your upload bandwidth costs for the ~10 KB screenshot thumbnail. Irrelevant
  next to the model's 20–40 s.
- **Reachability**: a page that only exists on your LAN, or a site that blocks
  your ISP, is fetched from *your* network — same as the local path, different
  from a cloud VM.

Caveats, stated plainly: a quick-tunnel URL changes every restart, it is
unauthenticated while it is up (anyone with the URL can scan through your
machine), and it dies with the process. Keep the window open, and add the
rate-limiting rule in §8 if the URL leaves your hands. For a stable name
(`https://api.phishbrain007.app`) create a **named** tunnel in Zero Trust and
point it at `http://localhost:8000` — same commands as §5, minus the VM.

### 4c. Everything else that claims to be free (checked October 2026)

Oracle is not the only option, but it is the only one that is both free *and*
always-on with enough RAM for this stack. The table is what each provider's own
pricing/docs page said this month; the "fits?" column is about *this* workload
(FastAPI + Playwright + CatBoost ≈ 0.7–1.5 GB, plus ~2 GB if you also run
Ollama).

| Provider | What is actually free | Fits this stack? |
| --- | --- | --- |
| **Northflank Sandbox** | up to **$20/month of resources**, 2 services + 1 database, no sleeping, public `*.code.run` HTTPS | **Best managed option.** The smallest plan is 0.5 vCPU / 1 GB at $12/month, so the API alone fits the allowance — a database and Chromium at the same time do not. Card may be required at signup. |
| **Google Cloud e2-micro** | one non-preemptible `e2-micro` in `us-west1`/`us-central1`/`us-east1`, 1 GB RAM, 30 GB-month disk, 1 GB/month egress | **No** for the model or Chromium; the API with `use_llm: false` fits, barely. |
| **Google Cloud Run** | 2M requests, 180k vCPU-s, 360k GiB-s/month, scale-to-zero, 60-minute max request | **Yes with cold starts**, and Chromium works inside the container. `min-instances=1` (no cold start) is **billed** (~$11/month idle for 1 vCPU / 0.7 GiB) — not free. The filesystem is in-memory, so Postgres must live elsewhere. |
| **GitHub Codespaces** (Free) | 120 core-hours + 15 GB-month storage, i.e. ~60 wall-clock hours on the 2-core machine; public port URLs need no auth | **No** as hosting: it stops after 30 minutes idle, and it is a development environment, not a server. Useful for *building* the image. |
| **Hugging Face Spaces** | CPU Basic 2 vCPU / 16 GB, 50 GB non-persistent disk, sleeps after 48 h idle | **No**: Docker Spaces need a paid plan on a free personal account (Oct 2026), the disk is wiped, and a Space is public. |
| **Azure free account** | $200 for 30 days + 750 h/month of B1s (1 vCPU / 1 GiB) for **12 months**, new customers only | **No**: 1 GiB, and it expires after a year (Bv1 is also end-of-life). |
| **AWS Free plan** | accounts created after 15 Jul 2025: **6 months or credits**, not 12 months of a free VM; `t3.micro` is 1 GiB | **No**: expires, and 1 GiB is too small. |
| **Koyeb** | 1 free service: 512 MB, 0.1 vCPU, scales to zero after 1 h, no volumes; free Postgres limited to 5 active hours | **No**: below the API's own footprint. |
| **Render** | 512 MB web services that sleep after 15 minutes; free Postgres expires after 30 days | **No**. |
| **Railway** | 30-day $5 trial, then $1/month credit; ~0.5 GB RAM per service | **No**. |
| **Fly.io** | no verifiable new-account free allowance this month | **No**. |

If you want a permanent host and none of the free rows fit, the honest cheap
answer is still a €4–6/month 2–4 GB VPS (Hetzner CX22, OVH VPS-1). What you are
buying is not CPU — it is *not being reclaimed* and a real support channel.

---

## 4d. Where the scan time goes, and how to shorten it

On CPU the model is the scan. Measured on the 2-core/16 GB development machine
(Oct 2026), one scan of `example.com` with the page fetch on:

| Phase | Warm, idle box | Notes |
| --- | --- | --- |
| URL + domain lookups | 1–3 s | overlapped with the fetch |
| Page fetch | 1–6 s | 8 s connect cap |
| Screenshot + brand comparison | 2–8 s | Chromium cold launch is the floor; it times out inside its own budget so a stuck page cannot hold a browser |
| `llama3.2:3b` verdict | **20–45 s** | ~5 tokens/s generation, ~20–48 tokens/s prompt processing on 2 cores |

That last row is the whole problem, and it is arithmetic rather than a bug: a
3B model on 2–4 CPU cores produces tokens at ~5/s, so a 60–120-token JSON
verdict costs 12–25 s *minimum*, plus 8–25 s to read the prompt. Four levers —
all of them taken here — are the only ones that exist without a GPU:

1. **Don't ask when the answer cannot change.** The model's contribution is
   clamped to ±15 points. If the deterministic base score is so low that even
   +15 stays under the SAFE ceiling (30), or so high that −15 stays HIGH_RISK,
   the verdict is already fixed and the model is skipped. The report says
   `llm.not_needed` and explains why; it is not a failure and is not counted
   against confidence. Disable with `LLM_SKIP_WHEN_DECISIVE=false`.
2. **Bound the generation.** `LLM_NUM_PREDICT=160` (a complete verdict measured
   82 tokens; the previous 320 was ~47 s of generation in the worst case).
3. **Shrink the prompt.** The instruction block lost ~40 % of its tokens and the
   evidence is bounded JSON instead of a `str()` of a dict, and a retry no
   longer re-sends the page text it has already read.
4. **Make it visible.** Every generation logs `prompt_tokens`, `eval_tokens`,
   `prompt_ms`, `gen_ms`, `done_reason`, and a rejected output logs that a retry
   is about to be paid for — a retry is a second full generation and doubles the
   wait. Watch for `done_reason: length`: that means the cap cut the JSON.

What *doesn't* help, and was measured rather than guessed: running the
screenshot and the model at the same time (both are CPU-bound; on 4 cores it
made the pair ~30 s slower, which is why they run in sequence), and a larger
context window (4096 → 2048 changed nothing).

If scans must feel instant, run the fast path: the extension already does a
`use_llm: false` pass first (URL, domain, page, pre-filter — about a second) and
replaces it when the model answers. `curl -d '{"url":"…","use_llm":false}'`
is the same thing by hand.

## 4b. Oracle Cloud Always Free VM (30 minutes, mostly waiting)

Oracle Cloud → Compute → Instances → Create:

- **Image:** Ubuntu 24.04 (aarch64)
- **Shape:** `VM.Standard.A1.Flex`, **2 OCPU / 12 GB** (the current Always Free Arm
  allowance — 1,500 OCPU-hours + 9,000 GB-hours; older guides say 4/24 and will
  fail with a quota error), 200 GB block storage
- **Networking:** the default VCN is fine. Remove the inbound rules you do not
  need — this deployment needs **only SSH (22)**, and only from your own IP. The
  API is reached through the Tunnel, so there is no 80/443 to open.
- Add your SSH key, create, wait for **Running**.

If you get *"Out of host capacity"*: try the other availability domains, another
home region, or simply retry over a few hours — it is a supply problem, not a
configuration problem.

Then:

```bash
ssh ubuntu@<public-ip>

# 4 GB swap: the LLM plus Chromium will otherwise hit the OOM killer on the
# 12 GB shared with Postgres, the page cache and the image build.
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Docker Engine + compose plugin (official convenience script)
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh
sudo usermod -aG docker $USER && newgrp docker   # or log out and back in

docker run --rm hello-world                      # sanity check (arm64 image)
```

**Why arm64 is not a gamble here.** Verified against the packages this repo pins:
`catboost==1.2.7` publishes `manylinux2014_aarch64` wheels (checked on PyPI, so
nothing compiles from source), `playwright==1.47` ships Linux arm64 Chromium for
Debian 12 / Ubuntu 22.04+ — and `docker/Dockerfile.backend` is already
`python:3.11-slim-bookworm`, i.e. Debian 12 — and Ollama's installer maps
`aarch64` to `ollama-linux-arm64` with a CPU-only build. `opencv-python-headless`,
`pandas`, `numpy`, `scikit-learn`, `psycopg[binary]` and `python-Levenshtein` all
have arm64 wheels too. The one shape that does **not** work is an amd64-only
image forced through emulation: do not add `platform: linux/amd64`, which makes
Chromium and CatBoost run under QEMU and turns a 2 s scan into a minute.

Clone the repository somewhere that survives reboots:

```bash
sudo mkdir -p /opt && sudo chown $USER /opt
git clone <your-fork-url> /opt/phishbrain
cd /opt/phishbrain
```

---

## 5. Cloudflare Tunnel (10 minutes)

Zero Trust → **Networks → Tunnels → Create a tunnel** → *Cloudflared* → name it
`phishbrain-api` → copy the token it prints (`eyJh…`).

Add a **Public hostname** on the tunnel:

| Subdomain | Domain             | Path | Service                |
| --------- | ------------------ | ---- | ---------------------- |
| `api`     | `phishbrain007.app` | —    | `http://backend:8000`  |

That hostname is resolved inside the compose network, so the API never listens on
a public port and there is no certificate to renew. Cloudflare creates the `api`
DNS record automatically.

---

## 6. Start the stack

```bash
cd /opt/phishbrain/deploy
cp env.production.example .env
nano .env      # POSTGRES_PASSWORD, TUNNEL_TOKEN; check CORS_ORIGIN_REGEX
docker compose -f compose.prod.yml up -d --build
docker compose -f compose.prod.yml logs -f backend
```

The first boot is slow on purpose: the Ollama container pulls `llama3.2:3b`
(~2 GB) and the backend warms the model (`LLM_WARMUP_ON_STARTUP=true`). Expect
5–15 minutes on a fresh VM. When it is done you should see the retention sweep
and the startup warm-up log lines, and the container healthchecks flip to
`healthy`:

```bash
docker compose -f compose.prod.yml ps
```

`deploy/compose.prod.yml` deliberately differs from the development compose file:
no `frontend` container (the dashboard is on Workers), **no published ports**, a
1 GB `/dev/shm` for Chromium, restart policies, log rotation and CPU-layer
admission gates.

---

## 7. Verify — not just "it is running"

Run these from your laptop, not the VM, so you test the public path.

**a. Health, through the Tunnel:**

```bash
curl -s https://api.phishbrain007.app/api/v1/health
```

`status: ok` with `database`, `cache` and `ollama` all `ok`. A `degraded` ollama
entry means the model is still pulling — wait and retry.

**b. Deterministic scan (fast, no model):**

```bash
curl -s -X POST https://api.phishbrain007.app/api/v1/analyze/url \
  -H "content-type: application/json" \
  -d '{"url":"https://example.com","use_llm":false,"fetch_page":true}' | head -c 400
```

**c. The full pipeline — this is the one that proves "all requirements":**

```bash
curl -s -X POST https://api.phishbrain007.app/api/v1/analyze/url \
  -H "content-type: application/json" \
  -d '{"url":"https://example.com","use_llm":true,"fetch_page":true}' \
  | python -c "import json,sys; r=json.load(sys.stdin); print(r['threat_score'], r['risk_level']); print('degraded:', r['degraded']); print('visual:', json.dumps(r['layers']['webpage']['evidence'].get('visual_similarity_score'))); print('llm:', (r['layers'].get('llm') or {}))"
```

On the free 2 OCPU / 12 GB Arm box this takes **90–150 s**. A correct result has:

- `degraded` free of `llm.*` and `visual.*` codes,
- a `visual_similarity_score` (or a `visual_indicators` entry explaining a
  legitimate miss),
- an LLM verdict in the result (`degraded` would say `llm.timeout` otherwise).

**d. SSRF guard still refuses the private internet:**

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.phishbrain007.app/api/v1/analyze/url \
  -H "content-type: application/json" -d '{"url":"http://127.0.0.1:8000"}'
```

Expect `400`. If that returns a result, stop and fix the guard before sharing the
URL.

**e. CORS for the extension (both engines):**

```bash
for origin in chrome-extension://abc moz-extension://abc; do
  curl -s -o /dev/null -w "$origin -> %{http_code} " -X OPTIONS \
    https://api.phishbrain007.app/api/v1/analyze/url \
    -H "Origin: $origin" -H "Access-Control-Request-Method: POST"
  curl -s -D - -o /dev/null -X OPTIONS https://api.phishbrain007.app/api/v1/analyze/url \
    -H "Origin: $origin" -H "Access-Control-Request-Method: POST" | grep -i access-control-allow-origin
done
```

Both must answer `200` **and** echo the origin. `CORS_ORIGIN_REGEX` in
`deploy/.env` is what controls this — it allows `chrome-extension://*` and
`moz-extension://*` plus your dashboard origin, and refuses everything else. (The
backend's built-in default now covers `moz-extension://` too; before that change a
deployed backend accepted the extension on Chrome and refused it on Firefox.)

---

## 8. Rate limiting (do this before sharing the URL)

The analyze routes are unauthenticated on purpose (an extension cannot keep a
secret), and each request makes your VM fetch a URL a stranger chose. The free
plan gives you **one** rate-limiting rule, so spend it on the expensive paths:

Cloudflare → your zone → **Security → WAF → Rate limiting rules → Create**:

- Expression: `(http.request.uri.path matches "^/api/")`
- Requests: **20** per **10 seconds**, counting by IP
- Action: **Block**, timeout **10 seconds**

One full scan is one request; the extension sends at most two per page/message
(quick pass + full pass), so 20/10 s per IP never bothers a real user and stops a
script. Everything else (the dashboard, its `/api/public/*` routes) is served by
Workers and does not touch the VM.

Then apply the admission gates that ship in this repo (they are already in
`deploy/env.production.example`):

```
MAX_CONCURRENT_LLM_SCANS=1
MAX_CONCURRENT_VISUAL_SCANS=1
SCAN_QUEUE_TIMEOUT_SECONDS=20
```

What that buys you: a bounded number of scans run the CPU-bound layers, the rest
queue for 20 s and then finish with the deterministic layers, reporting
`llm.busy` / `visual.busy` in `degraded`. Before this, three simultaneous visitors
made **every** scan miss its deadline and the server looked broken while it was
merely overloaded.

---

## 9. Build the extension for this deployment

The published build must not default to `127.0.0.1`, or a stranger's install
scans nothing. Bake your origins in at build time:

```bash
cd extension
npm ci
VITE_PHISHBRAIN_BACKEND_URL=https://api.phishbrain007.app \
VITE_PHISHBRAIN_DASHBOARD_URL=https://phishbrain007.app \
npm run build:firefox          # dist/ + dist-firefox/ (Firefox manifest)
npm run check:content          # runs the built content script in jsdom
```

(PowerShell: `$env:VITE_PHISHBRAIN_BACKEND_URL="https://api.phishbrain007.app"` on
its own line, then `npm run build:firefox`.)

- **Chrome/Edge/Brave:** `npm run build` → load `extension/dist` unpacked, or
  `npm run zip:chrome` for the store.
- **Firefox:** `npm run build:firefox` → `extension/dist-firefox/manifest.json`.
  Never point Firefox at `dist/manifest.json`; it declares a service worker
  Firefox does not start.

The dashboard build needs the same origin (`VITE_PHISHBRAIN_BACKEND_URL`, see step 3), so
the site and the extension agree on one engine.

Verify on a clean profile (this is the whole point of the exercise):

1. Open any ordinary site → the toolbar badge changes and the popup shows a
   verdict whose header reads **Backend online** (not *Hosted fallback*).
2. Open Gmail → the verdict card appears in the reading pane; open another
   message → the card follows it without a reload.
3. Stop the VM (`docker compose stop backend`) and rescan → the popup falls back
   to the Worker path and says so. Start it again → back to the full engine.

Publishing (permanent installs for other people):

```bash
npm run zip:firefox     # addons.mozilla.org, free
npm run zip:source      # AMO asks for sources of the bundled build
npm run zip:chrome      # Chrome Web Store, $5 one-time developer registration
```

The Chrome ID is stable across uploads once Google issues it; the backend allows
any `chrome-extension://`/`moz-extension://` origin, so no per-ID configuration
is required.

---

## 10. Keeping it alive

**Keepalive** — Oracle reclaims Always Free instances that look idle. A real user
base is enough; for a quiet one, scan something on a schedule (this also keeps the
model and the cache warm):

```bash
crontab -e
# every 10 minutes: health (cheap) — keeps network + process active
*/10 * * * * curl -fsS https://api.phishbrain007.app/api/v1/health >/dev/null
# every 30 minutes: one real deterministic scan — keeps CPU demonstrably in use
*/30 * * * * curl -fsS -X POST https://api.phishbrain007.app/api/v1/analyze/url \
  -H "content-type: application/json" -d '{"url":"https://example.com","use_llm":false}' >/dev/null
```

**Backups** (the only state that matters is Postgres; the model volume can be
re-pulled):

```bash
0 3 * * * cd /opt/phishbrain/deploy && docker compose -f compose.prod.yml exec -T postgres \
  pg_dump -U phishbrain phishbrain | gzip > /opt/backups/phishbrain-$(date +\%F).sql.gz
```

Copy those off the VM periodically (any free object store or your own machine).

**Updates:**

```bash
cd /opt/phishbrain && git pull
cd deploy && docker compose -f compose.prod.yml up -d --build
curl -fsS https://api.phishbrain007.app/api/v1/health
```

**Housekeeping:** `docker system prune -af --filter until=72h` monthly, and watch
`df -h` — Ollama models plus Playwright browsers are a few GB.

**Privacy defaults for a shared box** (already in `deploy/env.production.example`):
`VISUAL_RETENTION_DAYS=0`, `STORE_RAW_EMAIL=false`, `VISUAL_SCREENSHOT_MODE=wireframe`.
You are storing other people's email contents and screenshots of pages they
visited; the default here is to keep as little as the analysis needs.

---

## 11. What one free VM can actually serve

Measured on the documented reference host (4 vCPU / 8 GB, CPU-only):

| Stage                                  | Time          |
| -------------------------------------- | ------------- |
| Deterministic layers (URL/domain/DOM)  | 1–3 s         |
| Screenshot + brand comparison          | 8–15 s        |
| LLM verdict (llama3.2:3b, warm)        | 30–100 s      |
| **One full scan**                      | **~1.5–2 min** |

With one model slot that is roughly **30–40 full scans per hour**, or a few hundred
deterministic verdicts. That is a demo/research budget, not a product for a
thousand daily users. The extension is built for this: the quick deterministic
pass lands in about a second and is labelled provisional, and the model verdict
replaces it when a slot frees up.

Scaling levers, roughly in order of effort:

1. `OLLAMA_MODEL=qwen2.5:1.5b` or `llama3.2:1b` — 2–4× faster, less accurate.
2. `MAX_CONCURRENT_LLM_SCANS=2` **only** with 8+ vCPU.
3. A second VM behind Cloudflare load balancing (paid) or a queue.
4. Keep the LLM for trusted users and set `use_llm:false` for public traffic; the
   deterministic layers plus CatBoost still produce a verdict in ~2 s.

---

## 12. Troubleshooting

| Symptom                                   | Cause / fix                                                                                                                     |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `502` from `api.phishbrain007.app`        | Backend container unhealthy → `docker compose -f compose.prod.yml logs backend`; check `/api/v1/health` on the VM itself.         |
| Health says `ollama: degraded`            | Model still pulling. `docker compose logs ollama`. First pull is ~2 GB.                                                          |
| Every scan reports `llm.timeout`          | Model not resident or box oversubscribed: keep `OLLAMA_KEEP_ALIVE=30m`, raise `LLM_TIMEOUT_SECONDS`, or lower the model size.     |
| Every scan reports `visual: unavailable`  | Chromium failed to launch. The image is `debian bookworm`, where Playwright ships arm64 Chromium — rebuild the image, check `shm_size: 1gb`, and `docker compose exec backend python -m playwright install --dry-run chromium`. |
| `llm.busy` / `visual.busy` in `degraded`  | Working as designed: more concurrent scans than the box can run, the queue timed out. Not an error.                              |
| Extension: *Backend unavailable*          | CORS origin missing (see 7e), a typo in `Backend URL`, or the URL has no `https://`.                                            |
| Worker dashboard 404 on the custom domain | The domain was not added under the Worker's **Domains & Routes**.                                                               |
| `Out of host capacity` on Oracle          | Try another availability domain/region, or retry later.                                                                          |

---

## Files in this directory

| File                       | Purpose                                                                 |
| -------------------------- | ----------------------------------------------------------------------- |
| `compose.prod.yml`         | Production stack: Postgres, Valkey, Ollama, backend, Cloudflare Tunnel. |
| `env.production.example`   | Every setting that matters for a public deployment, commented.          |
| `README.md`                | This runbook.                                                           |
