#!/usr/bin/env bun
/**
 * Seed data/reference_hashes.json with perceptual hashes of real brand login
 * pages. Unlike scripts/data/generate_reference_hashes.py (Playwright inside
 * the Docker backend image), this variant:
 *   - needs NO Python packages and NO Playwright browsers,
 *   - drives the Chrome/Edge already installed on this machine headlessly,
 *   - computes the pHash with the EXACT same JS implementation the browser
 *     extension uses (extension/src/background/phash.ts), so the hashes the
 *     add-on compares against are algorithm-identical to the hashes it
 *     computes from captured tabs.
 *
 * Usage (run from the repo root):
 *   bun scripts/data/generate_reference_hashes.ts
 * Optionally point at a specific browser:
 *   CHROME_PATH="/usr/bin/google-chrome" bun scripts/data/generate_reference_hashes.ts
 *
 * The output schema is { "<brand>": "<16 hex chars>" } — the same file the
 * FastAPI backend (backend/app/analyzers/webpage/visual.py) and the extension
 * build (which bundles it into dist/reference_hashes.json) both consume.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { inflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { phashHex, type RawImage } from "../../extension/src/background/phash";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUTPUT_PATH = resolve(HERE, "../../data/reference_hashes.json");
const TMP_DIR = join(HERE, ".tmp-screens");
const VIEWPORT = "1280,800";

const BRAND_LOGIN_PAGES: Record<string, string> = {
  paypal: "https://www.paypal.com/signin",
  microsoft: "https://login.microsoftonline.com/",
  google: "https://accounts.google.com/signin",
  apple: "https://appleid.apple.com/sign-in",
  amazon: "https://www.amazon.com/ap/signin",
  netflix: "https://www.netflix.com/login",
  facebook: "https://www.facebook.com/login",
  instagram: "https://www.instagram.com/accounts/login/",
  linkedin: "https://www.linkedin.com/login",
  dropbox: "https://www.dropbox.com/login",
};

function findChrome(): string | null {
  const candidates: string[] = [];
  if (process.env.CHROME_PATH) candidates.push(process.env.CHROME_PATH);
  const pf = (process.env.PROGRAMFILES ?? "") || "C:\\Program Files";
  const pf86 = (process.env["PROGRAMFILES(X86)"] ?? "") || "C:\\Program Files (x86)";
  const local = process.env.LOCALAPPDATA ?? "";
  const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
  candidates.push(
    join(pf, "Google", "Chrome", "Application", "chrome.exe"),
    join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
    join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
    join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
    join(local, "Google", "Chrome", "Application", "chrome.exe"),
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux", "chrome"),
  );
  for (const c of candidates) {
    if (c && existsSync(c)) return c;
  }
  return null;
}

/* ---------------------------------------------------------------- */
/* Minimal PNG decoder (8-bit, colour types 2/4/6) — enough for      */
/* Chrome's headless screenshots.                                    */
/* ---------------------------------------------------------------- */

function decodePng(buf: Buffer): RawImage | null {
  if (buf.length < 24 || buf.toString("latin1", 1, 4) !== "PNG") return null;
  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  const idat: Buffer[] = [];
  while (offset + 8 <= buf.length) {
    const len = buf.readUInt32BE(offset);
    const type = buf.toString("latin1", offset + 4, offset + 8);
    const data = buf.subarray(offset + 8, offset + 8 + len);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      break;
    }
    offset += 12 + len;
  }
  if (!width || !height || bitDepth !== 8) return null;
  let channels = 0;
  if (colorType === 2) channels = 3;
  else if (colorType === 4) channels = 2; // gray + alpha
  else if (colorType === 6) channels = 4;
  else return null;

  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const out = new Uint8ClampedArray(width * height * 4);

  const paeth = (a: number, b: number, c: number): number => {
    const p = a + b - c;
    const pa = Math.abs(p - a);
    const pb = Math.abs(p - b);
    const pc = Math.abs(p - c);
    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
  };

  const prev = new Uint8ClampedArray(stride);
  for (let y = 0; y < height; y += 1) {
    const filter = raw[y * (stride + 1)];
    const rowStart = y * (stride + 1) + 1;
    const cur = new Uint8ClampedArray(stride);
    for (let x = 0; x < stride; x += 1) {
      const rawByte = raw[rowStart + x];
      const a = x >= channels ? cur[x - channels] : 0;
      const b = prev[x];
      const c = x >= channels ? prev[x - channels] : 0;
      let val = rawByte;
      if (filter === 1) val += a;
      else if (filter === 2) val += b;
      else if (filter === 3) val += Math.floor((a + b) / 2);
      else if (filter === 4) val += paeth(a, b, c);
      cur[x] = val & 0xff;
    }
    for (let x = 0; x < stride; x += 1) prev[x] = cur[x];
    for (let x = 0; x < width; x += 1) {
      const s = x * channels;
      const d = (y * width + x) * 4;
      if (channels === 3) {
        out[d] = cur[s];
        out[d + 1] = cur[s + 1];
        out[d + 2] = cur[s + 2];
        out[d + 3] = 255;
      } else if (channels === 2) {
        out[d] = cur[s];
        out[d + 1] = cur[s];
        out[d + 2] = cur[s];
        out[d + 3] = cur[s + 1];
      } else {
        out[d] = cur[s];
        out[d + 1] = cur[s + 1];
        out[d + 2] = cur[s + 2];
        out[d + 3] = cur[s + 3];
      }
    }
  }
  return { width, height, data: out };
}

/* ---------------------------------------------------------------- */

function capture(url: string, chrome: string, outFile: string): boolean {
  const args = [
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--no-first-run",
    "--disable-extensions",
    "--disable-background-networking",
    "--window-size=" + VIEWPORT,
    "--virtual-time-budget=9000",
    "--screenshot=" + outFile,
    url,
  ];
  const res = spawnSync(chrome, args, { timeout: 60000, encoding: "buffer" });
  if (res.status !== 0) return false;
  if (!existsSync(outFile)) return false;
  return readFileSync(outFile).length > 2000;
}

async function main(): Promise<void> {
  const chrome = findChrome();
  if (!chrome) {
    console.error(
      "No Chrome/Edge found. Install one, or point CHROME_PATH at a chromium binary, then re-run.",
    );
    process.exit(1);
  }
  console.log(`Using browser: ${chrome}`);

  mkdirSync(TMP_DIR, { recursive: true });
  const hashes: Record<string, string> = {};

  for (const [brand, url] of Object.entries(BRAND_LOGIN_PAGES)) {
    const outFile = join(TMP_DIR, `${brand}.png`);
    process.stdout.write(`- ${brand}: ${url} … `);
    const ok = capture(url, chrome, outFile);
    if (!ok) {
      console.log("capture FAILED (bot-wall / timeout / network) — skipped");
      continue;
    }
    try {
      const png = readFileSync(outFile);
      const image = decodePng(png);
      if (!image) {
        console.log("decode FAILED — skipped");
        continue;
      }
      const hash = phashHex(image);
      hashes[brand] = hash;
      console.log(`phash = ${hash}`);
    } catch (err) {
      console.log(`error: ${err instanceof Error ? err.message : String(err)} — skipped`);
    }
  }

  rmSync(TMP_DIR, { recursive: true, force: true });

  // Merge onto the previous file so repeated runs only update captured brands.
  let merged: Record<string, string> = {};
  if (existsSync(OUTPUT_PATH)) {
    try {
      merged = JSON.parse(readFileSync(OUTPUT_PATH, "utf8"));
    } catch {
      merged = {};
    }
  }
  Object.assign(merged, hashes);
  const sorted = Object.fromEntries(Object.entries(merged).sort(([a], [b]) => a.localeCompare(b)));
  writeFileSync(OUTPUT_PATH, JSON.stringify(sorted, null, 2) + "\n");
  console.log(`\nWrote ${Object.keys(sorted).length} reference hashes to ${OUTPUT_PATH}`);
  const missing = Object.keys(BRAND_LOGIN_PAGES).filter((b) => !sorted[b]);
  if (missing.length) {
    console.log(`No hash for: ${missing.join(", ")} (re-run later or add via generate_reference_hashes.py)`);
  }
}

void main();
