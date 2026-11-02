#!/usr/bin/env node
/**
 * Package the extension's *source* for Mozilla's source-code review.
 *
 *   node scripts/zip-source.mjs  -> ../phishbrain-extension-source.zip
 *
 * AMO asks for this whenever a listed add-on ships generated code. The bundle
 * in ../phishbrain-extension-firefox.zip is produced by Vite (TypeScript +
 * React -> one minified file per entry point), so reviewers get this archive
 * plus the build steps in README.md -> "Building from source".
 *
 * Only inputs are included: no node_modules, no dist/, and no previously built
 * zips. data/reference_hashes.json and data/reference_thumbnails.json ARE
 * included on purpose — they are checked-in inputs to the build, not outputs.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeZip } from "./zip-writer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const OUT = resolve(ROOT, "phishbrain-extension-source.zip");

/** Everything the build reads. Anything else is deliberately left out. */
const INCLUDE = [
  "README.md",
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "vitest.config.ts",
  "vite.config.ts",
  "vite.config.background.ts",
  "vite.config.content.ts",
  "manifest.json",
  "manifest.firefox.json",
  "src",
  "tests",
  "scripts",
  "data",
  "icons",
];

/** Generated on the maintainer's machine; not needed to reproduce the build. */
const EXCLUDE = new Set(["data/reference_capture_report.json"]);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === ".DS_Store" || entry === "Thumbs.db") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const files = [];
for (const entry of INCLUDE) {
  const full = join(ROOT, entry);
  const stat = statSync(full, { throwIfNoEntry: false });
  if (!stat) {
    console.error(`Missing build input: ${entry} — run this from the extension directory.`);
    process.exit(1);
  }
  if (stat.isDirectory()) files.push(...walk(full));
  else files.push(full);
}

const names = files
  .map((f) => relative(ROOT, f).replace(/\\/g, "/"))
  .filter((name) => !EXCLUDE.has(name))
  .sort();

const entries = names.map((name) => ({ name, data: readFileSync(join(ROOT, name)) }));
const bytes = entries.reduce((sum, e) => sum + e.data.length, 0);

await writeZip(OUT, entries);
console.log(`Wrote ${OUT} (${entries.length} files, ${(bytes / 1024).toFixed(0)} KiB of source)`);
