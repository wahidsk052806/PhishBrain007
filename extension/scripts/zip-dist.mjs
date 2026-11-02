#!/usr/bin/env node
/**
 * Package extension/dist into a zip for submission.
 *
 *   node scripts/zip-dist.mjs chrome   -> ../phishbrain-extension-chrome.zip (uses dist/manifest.json)
 *   node scripts/zip-dist.mjs firefox  -> ../phishbrain-extension-firefox.zip
 *                                        (uses dist/manifest.firefox.json renamed manifest.json,
 *                                         which is what Mozilla Add-ons requires)
 *
 * The ZIP writer itself lives in scripts/zip-writer.mjs (dependency-free).
 */
import { mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeZip } from "./zip-writer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(HERE, "..", "dist");

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const flavour = process.argv[2] ?? "chrome";
if (!["chrome", "firefox"].includes(flavour)) {
  console.error("Usage: node scripts/zip-dist.mjs [chrome|firefox]");
  process.exit(1);
}

const outName =
  flavour === "firefox"
    ? resolve(HERE, "..", "phishbrain-extension-firefox.zip")
    : resolve(HERE, "..", "phishbrain-extension-chrome.zip");

// Firefox must ship with a manifest.json that is the Firefox one.
const files = walk(DIST);
const names = files.map((f) => relative(DIST, f).replace(/\\/g, "/"));
if (flavour === "firefox") {
  if (!names.includes("manifest.firefox.json")) {
    console.error("dist/manifest.firefox.json not found — run `npm run build` first.");
    process.exit(1);
  }
}

const entries = [];
for (const name of names.sort()) {
  if (flavour === "firefox" && name === "manifest.firefox.json") continue; // added below as manifest.json
  if (name === "manifest.json" && flavour === "firefox") continue;
  // The Chrome package must not ship the Firefox manifest either. Two
  // manifests in one archive is ambiguous for a store reviewer and for anyone
  // unzipping the package to see which one is live.
  if (flavour === "chrome" && name === "manifest.firefox.json") continue;
  entries.push({ name, data: readFileSync(join(DIST, name.replace(/\//g, "\\"))) });
}
if (flavour === "firefox") {
  entries.push({ name: "manifest.json", data: readFileSync(join(DIST, "manifest.firefox.json")) });
}

mkdirSync(dirname(outName), { recursive: true });
try {
  await writeZip(outName, entries);
} catch (error) {
  if (error.code === "EPERM" || error.code === "EBUSY") {
    // Firefox keeps a handle on the zip while it is loaded as a temporary
    // add-on, so the archive cannot be replaced underneath it.
    console.error(
      `Cannot replace ${outName}: the file is open in another program.\n` +
        (flavour === "firefox"
          ? "If Firefox has it loaded, remove the temporary add-on at about:debugging#/runtime/this-firefox and run this again."
          : "Close it and run this again."),
    );
    process.exit(1);
  }
  throw error;
}
// `entries`, not `files`: a Firefox package swaps two manifests for one, so
// reporting the dist file count overstated the archive by one.
console.log(`Wrote ${outName} (${entries.length} files, flavour=${flavour})`);
