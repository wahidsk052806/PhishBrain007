# PhishBrain Browser Extension

MV3 extension (Chrome/Edge/Brave **and** Firefox 109+) providing real-time
phishing/scam detection:

- **Automatic page scanning** — every http(s) page you visit is analysed
  (URL + domain age/RDAP + live fetch + HTML signals) and scored 0–100.
- **Automatic email scanning** — on Gmail and Outlook Web the open message is
  parsed (sender, reply-to, display name, subject, body, links) the moment it
  is opened (SPA-aware: it re-checks on navigation, not just page load) and
  analysed for sender-mismatch, brand impersonation, urgency and credential
  requests. SPF/DKIM/DMARC cannot be verified from browser context and are
  reported as such.
- **Warning banner** — results above your threshold inject an isolated
  Shadow-DOM banner with *Go back / Proceed anyway / View details*.
- **Opt-in screenshot / visual clone analysis** — captures the visible tab
  and compares its layout fingerprint against known brand login pages,
  entirely on-device (no backend, works in Firefox). Visiting a genuine brand
  login once teaches the detector your browser's rendering for sharper
  matches.
- **Opt-in real-time alerts** — POST every high-risk detection to a webhook
  (Slack / n8n / email relay / SIEM) as a JSON SOC event.

## Endpoints it talks to

The extension tries the **Backend URL** first (default `http://127.0.0.1:8000`
— the self-hosted FastAPI stack). When that is offline and **“Fall back to
hosted live scans”** is on (default), it uses the hosted endpoints:

| Purpose        | Default URL                                   |
|----------------|-----------------------------------------------|
| URL/page scan  | `https://www.phishbrain07.app/api/public/scan`       |
| Email analysis | `https://www.phishbrain07.app/api/public/email-scan` |

Both are plain `POST /json` routes served by the published dashboard
(`src/routes/api/public/*`) — no server to rent.

## Build

```bash
cd extension
bun install
bun run build
bun run test      # 46 unit tests
bun run typecheck
```

This runs three Vite builds (popup/options, background, content) into `dist/`,
copies both `manifest.json` (Chrome) and `manifest.firefox.json` (Firefox) in,
and bundles `data/reference_hashes.json` as `dist/reference_hashes.json` for
the visual layer.

## Configuration (Options page)

- **Backend URL** — self-hosted PhishBrain (default `http://127.0.0.1:8000`)
- **Dashboard URL** — where “View details” opens (set this to your hosted
  dashboard, e.g. `https://www.phishbrain07.app`)
- **Live scan URL** + **Email live-scan URL** — hosted fallbacks
- **Fall back to hosted live scans** toggle
- Auto-scan toggle, banner mode & threshold, allowlisted domains
- **Screenshot & visual clone analysis (opt-in)** toggle
- **Real-time alerts (opt-in)** webhook

## Load in Chrome / Edge (MV3)

1. `bun run build`
2. Go to `chrome://extensions`, enable **Developer mode**
3. **Load unpacked** → select `extension/dist`

## Load in Firefox (temporary, for development)

1. `bun run build && bun run zip:firefox`
2. Go to `about:debugging#/runtime/this-firefox`
3. **Load Temporary Add-on…** → select
   `extension/phishbrain-extension-firefox.zip` (a zip whose `manifest.json`
   is the Firefox flavour; Firefox accepts the zip directly)

Alternative: `cp dist/manifest.firefox.json dist/manifest.json` then load
`dist/manifest.json`. Temporary add-ons are removed when Firefox restarts.

## Submit to Mozilla Add-ons (permanent, free)

```bash
cd extension
bun install && bun run build
bun run zip:firefox        # -> extension/phishbrain-extension-firefox.zip
```

The zip contains the Firefox manifest as `manifest.json` (AMO requirement),
icons, background/content/popup/options and the bundled reference hashes.

1. Create an account at https://addons.mozilla.org/developers/
2. **Submit a new add-on** → *On your own* → upload
   `phishbrain-extension-firefox.zip`
3. Choose **Self-hosted / unlisted** (instant) or **Listed** (public, subject
   to human review — the source repo zip is requested then because the
   extension ships compiled bundles).
4. For the 30-day review window during *unlisted* testing, anyone with the
   download link can install it.

## Development

```bash
bun run dev       # watch build (popup/options only; run full build for bg/content)
bun run test      # vitest run
```

Unit tests cover scan gating, badge/banner decisions, cache freshness, message
parsing, page summary extraction, Gmail/Outlook DOM parsing, API error
handling and the visual pHash/comparison/scoring logic.
