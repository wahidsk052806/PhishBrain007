#!/usr/bin/env node
/**
 * Stage the **Firefox** flavour of the extension into `dist-firefox/`.
 *
 *   npm run build:firefox   ->  dist (all flavours) + dist-firefox (loadable/signable)
 *
 * Why this exists: `dist/manifest.json` is the Chrome manifest and declares
 * `background.service_worker`, which Firefox does not support. Loading
 * `dist/manifest.json` in `about:debugging` therefore produces a manifest
 * warning ("Error processing background.service_worker") and an add-on whose
 * background page never starts — so nothing is scanned and no verdict appears
 * on Gmail. Signing `--source-dir dist` has the same bug, in a way that only
 * shows up after installation.
 *
 * `dist-firefox/` is a full copy of `dist/` with exactly one manifest: the
 * Firefox one, renamed to `manifest.json`. That is what:
 *   - `about:debugging → Load Temporary Add-on…` should point at,
 *   - `web-ext sign --source-dir` should sign,
 *   - and `zip:firefox` packages (same content, as a zip).
 *
 * Everything is dependency-free and deterministic, so it runs on a clean
 * checkout with only `npm ci` done.
 */
import { cpSync, existsSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const DIST = resolve(ROOT, "dist");
const FIREFOX_MANIFEST = join(DIST, "manifest.firefox.json");
const OUT = resolve(ROOT, "dist-firefox");

if (!existsSync(FIREFOX_MANIFEST)) {
  console.error("dist/manifest.firefox.json is missing — run `npm run build` first.");
  process.exit(1);
}

// Start from a clean directory: a removed file must not linger from an older build.
rmSync(OUT, { recursive: true, force: true });
cpSync(DIST, OUT, { recursive: true });

// Exactly one manifest in the staged add-on, and it is the Firefox one.
rmSync(join(OUT, "manifest.firefox.json"), { force: true });
writeFileSync(join(OUT, "manifest.json"), readFileSync(FIREFOX_MANIFEST));

const manifest = JSON.parse(readFileSync(join(OUT, "manifest.json"), "utf8"));
if (manifest.background?.service_worker) {
  console.error(
    "manifest.firefox.json declares background.service_worker; Firefox needs background.scripts.",
  );
  process.exit(1);
}
if (!manifest.background?.scripts?.includes("background.js")) {
  console.error("manifest.firefox.json is missing background.scripts: [\"background.js\"].");
  process.exit(1);
}
if (!manifest.browser_specific_settings?.gecko?.id) {
  console.error("manifest.firefox.json has no browser_specific_settings.gecko.id — AMO rejects it.");
  process.exit(1);
}

function walk(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

const files = walk(OUT);
const bytes = files.reduce((sum, file) => sum + statSync(file).size, 0);
console.log(
  `Firefox add-on staged: ${relative(ROOT, OUT)}/ — ${files.length} files, ` +
    `${(bytes / 1024).toFixed(0)} KB, id ${manifest.browser_specific_settings.gecko.id}`,
);
console.log("Load it with about:debugging -> Load Temporary Add-on… -> dist-firefox/manifest.json");
