# PhishBrain Browser Extension

MV3 extension (Chrome/Edge/Brave **and** Firefox 140+ desktop, 142+ on
Android) providing real-time
phishing/scam detection:

- **Automatic page scanning** — every http(s) page you visit is analysed
  (URL + domain age/RDAP + live fetch + HTML signals) and scored 0–100.
- **Automatic email scanning** — on Gmail and Outlook Web the open message is
  parsed (sender, reply-to, display name, subject, body, links) the moment it
  is opened, and the mailbox is then polled every 2.5 s so the next message is
  read without a reload or a Rescan click. It re-checks on hash/history
  navigation, on focus and on returning to the tab, and re-analyses a message
  left open every five minutes. An inbox list is never mistaken for an open
  message. SPF/DKIM/DMARC cannot be verified from browser context and are
  reported as such.
- **Warning banner** — results above your threshold inject an isolated
  Shadow-DOM banner with _Go back / Proceed anyway / View details_.
- **In-message verdict card** — on Gmail and Outlook Web the card appears in
  the reading pane above the open message, for cleanand risky mail alike: the
  verdict, score, confidence, the indicators that fired and whether the SOC
  alert was delivered. On a mailbox this replaces the page banner, which used
  to cover the message header and offer "Proceed anyway" — an action that
  would have allowlisted the mailbox itself.
- **Opt-in screenshot / visual clone analysis** — captures the visible tab
  and compares its layout fingerprint against known brand login pages,
  entirely on-device (no backend, works in Firefox). Visiting a genuine brand
  login once teaches the detector your browser's rendering for sharper
  matches.
- **Opt-in real-time alerts** — POST every detection at or above your
  threshold to a webhook (Slack / n8n / email relay / SIEM) as the same JSON
  SOC event the dashboard emits: `event_id`, `event_type`, `severity`,
  `indicators`, `degraded` and the ML pre-filter's contribution, plus
  `collector: "phishbrain-extension"` to say which surface saw it. Delivery has
  a 4-second budget and one retry, **Send test alert** checks a URL before you
  rely on it, and the last delivery's HTTP result is shown under the button —
  a webhook that quietly returns `404` is not the same as a quiet one.

## Building a release for your own deployment

A store build must work on a stranger's machine, where a `Backend URL` of
`127.0.0.1:8000` points at *their* computer. Bake your deployed origins in at
build time:

```bash
VITE_PHISHBRAIN_BACKEND_URL=https://api.example.app \
VITE_PHISHBRAIN_DASHBOARD_URL=https://example.app \
  npm run build:firefox     # or: npm run build
```

Both are optional, because a **release build already ships the deployed
origins**: `https://api.phishbrain007.app` and `https://phishbrain007.app`
(`src/services/api.ts`, chosen from `import.meta.env.PROD`). A development build
— `npm run dev`, `vite build --mode development`, `vitest` — ships the loopback
pair instead, so local work keeps hitting the local stack. A value without a
scheme is ignored rather than shipped. The dashboard origin is also where the
hosted `/api/public/*` fallback is derived from, so this one pair of variables
configures the whole extension. The end-to-end deployment runbook lives in
[`../deploy/README.md`](../deploy/README.md).

## Endpoints it talks to

The extension tries the **Backend URL** first — `https://api.phishbrain007.app`
in a release build, `http://127.0.0.1:8000` in a development build. When that is
offline and **“Fall back to hosted live scans”** is on (default), it uses the
hosted endpoints **derived from the Dashboard URL** (`src/lib/hosted.ts`):

| Purpose        | URL                                     |
| -------------- | --------------------------------------- |
| URL/page scan  | `<Dashboard URL>/api/public/scan`       |
| Email analysis | `<Dashboard URL>/api/public/email-scan` |

Both are plain `POST /json` routes served by the published dashboard
(`src/routes/api/public/*`) — no server to rent. The shipped defaults are **empty
on purpose**: a hard-coded host is either somebody else's deployment or a domain
that no longer resolves, which is exactly the “Backend unavailable … Tried
https://www.phishbrain07.app/api/public/scan” dead end. A stored value pointing
at that old placeholder (or `phishbrain007.lovable.app`) is reported as
_“still the old placeholder”_ rather than fetched.

**Nothing works until one of these is true** (this is what the red popup panel
means):

- the local backend is running (`cd backend && venv/Scripts/python.exe -m uvicorn
app.main:app --port 8000`), or
- the dashboard is deployed and its origin is in **Options → Dashboard URL** —
  free walkthrough in [`../deploy/README.md`](../deploy/README.md).

## Build

TypeScript + React, bundled by Vite. The shipped bundle is transpiled and
minified, so the source has to accompany it — see
[Source code for Mozilla review](#source-code-for-mozilla-review).

| Requirement | Version               | Notes                                                                                                                           |
| ----------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Node.js     | **24.11.1**           | version the published build was made with; Node 22+ works (jsdom 30, used only by the tests, asks for 22.22+/24.15+)            |
| npm         | **11.6.2**            | ships with Node; `npm ci` installs the exact tree from `package-lock.json`                                                      |
| OS          | Windows, macOS, Linux | verified on Windows 11 (Git Bash). No C toolchain, no `zip` binary, no Python: `scripts/*.mjs` use Node's standard library only |

```bash
cd extension
npm ci            # exact dependency versions, nothing compiled natively
npm run build
npm run test      # optional: 190 unit tests (vitest + jsdom)
npm run typecheck
npm run check:content   # after a build: runs the shipped content.js in jsdom
```

`npm run build` runs three Vite configurations in order:

1. `vite.config.ts` — popup + options (React + Tailwind) → `dist/assets/popup.js`,
   `dist/assets/options.js`, the shared React chunk `dist/assets/hosted.js`,
   `dist/assets/hosted.css`; `scripts/flatten-html.mjs` then rewrites the two
   HTML entry points into `dist/popup.html` and `dist/options.html`.
2. `vite.config.background.ts` — MV3 service worker → `dist/background.js`.
3. `vite.config.content.ts` — content script (React banner inside a Shadow DOM)
   → `dist/content.js`, and copies `manifest.json`, `manifest.firefox.json`,
   `icons/`, `data/reference_hashes.json`, `data/reference_thumbnails.json`
   into `dist/`.

Both `vite.config.background.ts` and `vite.config.content.ts` `define`
`process.env.NODE_ENV`. Vite's library mode leaves that expression in the
output, and neither context has a `process`: React's module header evaluated it
first, so the shipped content script died with `ReferenceError: process is not
defined` **before registering a listener**. Gmail then parsed nothing, scanned
nothing and the popup answered “No scan result yet for this tab”. Source,
typecheck and unit tests all pass in that state — `npm run check:content`
evaluates the real bundle and is the check that catches it.

Packaging (all dependency-free):

```bash
npm run build:firefox # -> dist-firefox/ (a copy of dist with the Firefox manifest as manifest.json)
npm run zip:firefox   # -> phishbrain-extension-firefox.zip (manifest.firefox.json renamed manifest.json)
npm run zip:chrome    # -> phishbrain-extension-chrome.zip  (manifest.json)
npm run zip:source    # -> phishbrain-extension-source.zip  (source archive for AMO review)
```

## Source code for Mozilla review

**Answer “Yes” to AMO's generator/bundler question.** Vite transpiles the
TypeScript/JSX, minifies each entry point into one file, and Tailwind emits
`assets/hosted.css`, so the add-on ships generated code and the source must be
uploaded with it.

Upload `phishbrain-extension-source.zip` — produced by `npm run zip:source` — in
the **Upload source code** field. It contains inputs only:

- `src/` — every TypeScript/React file, none of them transpiled
- `tests/` — 190 vitest cases covering scoring, e-mail parsing, pHash matching
  and webhook delivery (optional to the build)
- `scripts/` — the packagers (`zip-dist.mjs`, `zip-source.mjs`, `zip-writer.mjs`)
  and the HTML flattener
- `data/` — the checked-in reference pHash set and thumbnails the visual layer
  compares against, plus the curated gap list
- `manifest.json`, `manifest.firefox.json`, `package.json`, `package-lock.json`,
  `tsconfig.json`, `vite.config*.ts`, `vitest.config.ts`, `icons/`, this README

It contains no `node_modules`, no `dist/` and no built zip; `npm ci && npm run
build` regenerates `dist/` from those sources. React, Vite, Tailwind and every
transitive dependency are installed from npm at the versions pinned in
`package-lock.json` — no third-party code is vendored into `src/`.

The reference pHash data is data, not generated code: it was captured once by a
maintainer-only Playwright script and committed, so the build never downloads
or regenerates anything and the add-on executes no remote code.

## Configuration (Options page)

- **Backend URL** — self-hosted PhishBrain (default `http://127.0.0.1:8000`)
- **Dashboard URL** — where “View details” opens (set this to your hosted
  dashboard, e.g. `https://www.phishbrain07.app`)
- **Live scan URL** + **Email live-scan URL** — hosted fallbacks
- **Fall back to hosted live scans** toggle
- Auto-scan toggle, banner mode & threshold, allowlisted domains
- **Screenshot & visual clone analysis (opt-in)** toggle
- **Real-time alerts (opt-in)** webhook, with a **Send test alert** button and
  the last delivery's outcome shown beneath it

## When it scans, and why the popup answers in about a second

- **Triggers.** A full page load, an SPA URL change (listening only for
  `status: complete` left YouTube/X/GitHub showing the verdict of the page they
  first loaded), a tab activation once its cached result is older than five
  minutes, and the tab in front when the browser starts or the add-on is
  installed/updated.
- **Two passes per scan.** Pass one is deterministic — URL, domain, pre-filter,
  no page fetch and no model — and is shown immediately, labelled **Quick
  verdict** (measured ~1–4 s). Pass two fetches the page, runs the
  screenshot/brand comparison and the local LLM verdict, then replaces the
  first result. Only pass two alerts, notifies or shows the warning banner, so
  a provisional score can never fire a webhook.
- **The popup starts the scan itself** when a tab has no cached result, and
  polls while a scan is running instead of showing “No scan result yet” and
  waiting for a click.
- **A mailbox keeps scanning.** The content script re-reads the open message
  whenever the fingerprint (sender, subject, body, links) changes, when the tab
  is focused or becomes visible again (at most once every 30 s, so switching
  windows is cheap), and unconditionally every five minutes. The worker drops
  a scan whose message has since been replaced, so a slow verdict for the
  previous message can never overwrite the one on screen.

## Load in Chrome / Edge (MV3)

1. `npm run build`
2. Go to `chrome://extensions`, enable **Developer mode**
3. **Load unpacked** → select `extension/dist`

## Install in Firefox

Firefox will only load an add-on permanently if Mozilla has signed it. That is
why there are exactly two ways to a permanent install (B and C below) and one
way to test (A).

> **Never point Firefox at `extension/dist/manifest.json`.** That is the Chrome
> manifest: it declares `background.service_worker`, which Firefox does not
> support, so the add-on loads with `Error processing background.service_worker`
> and its background page never starts — nothing is scanned and no verdict ever
> appears. The Firefox flavour is `dist-firefox/` (one Firefox manifest, renamed
> to `manifest.json`, produced by `npm run build:firefox`).

### A. Temporary install (about 5 minutes, for testing)

Temporary add-ons are the fastest way to try a build. They last until Firefox
quits, so use them for checking behaviour, not for daily use.

```bash
cd extension
npm ci
npm run build:firefox        # writes dist/ and stages dist-firefox/
npm test                     # 201 tests, optional but fast confidence
```

1. Open a new tab and go to `about:debugging#/runtime/this-firefox`.
2. Under **Temporary Extensions** (Firefox 130+: **This Firefox**), press
   **Load Temporary Add-on…**.
3. Select `extension/dist-firefox/manifest.json` — or, if you prefer a single
   file, run `npm run zip:firefox` first and select
   `extension/phishbrain-extension-firefox.zip`. Firefox accepts either.
4. Open the puzzle-piece **Extensions** menu, find **PhishBrain007**, and click
   the pin so the toolbar icon stays visible.
5. Open any `https://` page. Within a second or two the toolbar badge shows
   `OK`, `!` or `!!`, and the popup shows the full report.
6. After changing code, rebuild and press **Reload** on the add-on's card in
   `about:debugging`; a full Firefox restart is not needed.
7. When you close Firefox the add-on — and its settings — disappear. That is
   expected, not a bug.

### B. Permanent install by publishing on AMO (free, recommended)

Mozilla signs it, users install it from a normal link, and updates arrive by
themselves on every device.

```bash
cd extension
npm ci
npm run build:firefox
npm run zip:firefox        # -> extension/phishbrain-extension-firefox.zip
npm run zip:source         # -> extension/phishbrain-extension-source.zip
```

The package contains the Firefox manifest as `manifest.json` (AMO's
requirement), icons, background/content/popup/options and the bundled reference
hashes. Because those bundles are machine-generated, AMO also asks for the
source archive — see [Source code for Mozilla review](#source-code-for-mozilla-review).

1. Create an account at <https://addons.mozilla.org/developers/>.
2. **Submit a New Add-on** → _On your own_ (you are uploading a package) →
   choose `phishbrain-extension-firefox.zip`.
3. Choose a channel:
   - **Unlisted / self-distributed** — signed immediately, no public listing, and
     the download link works on any device. Good for a lab or a course.
   - **Listed** — public in the add-on store. Human review can take days, and the
     reviewer will ask for `phishbrain-extension-source.zip` because the shipped
     code is compiled.
4. Copy the resulting install link (`…/firefox/downloads/latest/<slug>`). That
   link *is* the permanent installer: open it in any Firefox, on any machine.
5. Ship an update by uploading a build with a higher `"version"` in
   `manifest.firefox.json`; installed copies update automatically within a day.

### C. Permanent install without a public listing (self-signed XPI)

Signing still goes through AMO, but nothing is published. The `.xpi` you get is
installable forever on release Firefox.

1. Sign in at AMO → **Tools → Manage API Keys** → **Create new API key**.
   Copy the key (user id, looks like `user:12345:67`) and the secret.
2. From `extension/`:

   ```bash
   npx web-ext sign \
     --source-dir dist-firefox \
     --channel unlisted \
     --api-key "user:12345:67" \
     --api-secret "…" \
     --artifacts-dir signed
   ```

3. `signed/` now holds `<gecko-id>-<version>.xpi` (here
   `phishbrain@extension.local-1.0.0.xpi`).
4. Install it on any device by opening the file in Firefox
   (`File → Open File…`), or serve it over HTTPS with
   `Content-Type: application/x-xpinstall` and link to it.
5. Distribute updates the same way, and optionally point
   `browser_specific_settings.gecko.update_url` at an
   [update manifest](https://extensionworkshop.com/documentation/manage/updating-your-extension/)
   so installed copies offer the new build.

An **unsigned** zip/xpi cannot be installed permanently on release Firefox —
`xpinstall.signatures.required` is only honoured in Nightly, Dev Edition and ESR.
Signing is the step that makes an install permanent, not the packaging.

### D. Fleet install (lab machines, an organisation)

With a signed XPI hosted at a stable HTTPS URL, force-install it with an
enterprise policy so no user clicks anything:

```json
{
  "policies": {
    "ExtensionSettings": {
      "phishbrain@extension.local": {
        "installation_mode": "force_installed",
        "install_url": "https://phishbrain007.app/extension/phishbrain.xpi"
      }
    }
  }
}
```

Save as `policies.json` in the Firefox `distribution/` folder — Windows
`C:\Program Files\Mozilla Firefox\distribution\policies.json`, macOS
`/Applications/Firefox.app/Contents/Resources/distribution/policies.json`, Linux
`/usr/lib/firefox/distribution/policies.json` — then restart Firefox.

### E. Post-install check on any device

1. **Options** (right-click the toolbar icon → *Settings*, or
   `about:addons` → PhishBrain007 → Preferences). A release build already points
   at the deployed API and dashboard; nothing needs typing.
2. The popup's status pill should read **Backend online**. **Hosted fallback**
   means the local backend is absent and the hosted scan answered — correct for a
   hosted-only device. **Backend unavailable** means neither answered: check the
   URLs in Options, not the browser.
3. Open a page, wait for the badge, open the popup, then press **Open Dashboard**.
   It opens `<dashboard>/analysis?url=<the page you scanned>`, and that page runs
   the same scan on the backend, so the report includes the screenshot, the
   CatBoost pre-filter and the model verdict.
4. On Gmail, open a message: the verdict card appears in the reading pane and
   *Open full report* goes to the dashboard.

### F. Install-time errors and their fix

| Message | Cause | Fix |
| --- | --- | --- |
| `Error processing background.service_worker` | `dist/` (Chrome manifest) loaded in Firefox | load `dist-firefox/manifest.json` |
| Add-on vanishes after restart | temporary install | sign it (B or C) |
| *This add-on could not be installed because it appears to be corrupt.* | unsigned `.xpi`/`.zip` on release Firefox | sign it with `web-ext sign` |
| AMO: *data_collection_permissions is required* | Firefox 140+ submission | already declared in `manifest.firefox.json`; rebuild, do not hand-edit `dist` |
| AMO asks for source code | compiled bundle | upload `phishbrain-extension-source.zip` |
| Badge never changes | background page did not start (see row 1) or the page is `about:`/`file:` | fix the build; internal pages are never scanned |
| Firefox for Android | temporary add-ons unsupported | install from the AMO link (B); `gecko_android.strict_min_version` is 142 |

## Development

```bash
npm run dev       # watch build (popup/options only; run full build for bg/content)
npm test          # vitest run
```

Unit tests cover scan gating, badge/banner decisions, cache freshness, message
parsing, page summary extraction, Gmail/Outlook DOM parsing, API error
handling and the visual pHash/comparison/scoring logic.
