#!/usr/bin/env bun
/**
 * Seed the EXTENSION's layout reference file with perceptual hashes of real
 * brand sign-in pages. Unlike scripts/data/generate_reference_hashes.py
 * (Playwright, Python's `imagehash`, writes data/reference_hashes.json for the
 * backend), this variant:
 *   - needs NO Python packages and NO Playwright browsers,
 *   - drives the Chrome/Edge already installed on this machine headlessly,
 *   - computes the pHash with the EXACT same JS implementation the browser
 *     extension uses (extension/src/background/phash.ts).
 *
 * The two files are deliberately separate. Perceptual hashes are only
 * comparable when produced by the same implementation: Python's `imagehash`
 * and the JS port disagree on identical bytes (different resize filter), so a
 * single shared file would silently make every comparison meaningless.
 *
 * Output: extension/data/reference_hashes.json, schema { "<brand>": "<16 hex>" },
 * bundled into dist/reference_hashes.json by the extension build. The
 * extension's PRIMARY brand signal is the page's icon, hashed at runtime by
 * extension/src/background/brand-refs.ts; this layout file is the secondary
 * signal and is optional.
 *
 * Usage (run from the repo root):
 *   bun scripts/data/generate_reference_hashes.ts
 * Optionally point at a specific browser:
 *   CHROME_PATH="/usr/bin/google-chrome" bun scripts/data/generate_reference_hashes.ts
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { deflateSync, inflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { phashHex, type RawImage } from "../../extension/src/background/phash";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUTPUT_PATH = resolve(HERE, "../../extension/data/reference_hashes.json");
/** Optional preview images (brand -> PNG data URL) for the side-by-side view. */
const THUMBS_PATH = resolve(HERE, "../../extension/data/reference_thumbnails.json");
const TMP_DIR = join(HERE, ".tmp-screens");
/**
 * A PERSISTENT Chrome profile, deliberately outside TMP_DIR (which is deleted
 * at the end). Consent banners, "I'm not a robot" interstitials and first-visit
 * redirects set cookies; replaying them on the next run is what actually gets
 * past a bot wall, which a fresh throwaway profile can never do. It also means
 * a brand that walls the first run often succeeds on the second.
 */
const PROFILE_DIR = join(HERE, ".tmp-profile");
/** Per-brand capture outcome of the last run, for the gap test + debugging. */
const REPORT_PATH = resolve(HERE, "../../extension/data/reference_capture_report.json");
/** Brands known to be persistently walled, documented as an honest gap. */
const GAPS_PATH = resolve(HERE, "../../extension/data/known_reference_gaps.json");
const VIEWPORT = "1280,800";
const THUMB_MAX_WIDTH = 160;

/**
 * How many times a bot-walled or degenerate capture is retried. Retries reuse
 * the persistent profile, so the second attempt arrives with whatever cookie
 * or consent state the first one earned. Override with CAPTURE_ATTEMPTS=1 to
 * make a run fail fast (used by the gap-drift check).
 */
const MAX_ATTEMPTS = Math.max(1, Math.min(4, Number(process.env.CAPTURE_ATTEMPTS ?? 2) || 2));

// Same UA the backend fetches with (backend/app/core/config.py FETCH_USER_AGENT):
// brand sites answer headless-looking clients with a bot wall instead of the page.
const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

// Homepage first (stable, rarely behind a bot wall), then the real sign-in page.
// Mirrors BRAND_REFERENCE_URLS in generate_reference_hashes.py.
const BRAND_REFERENCE_URLS: Record<string, string[]> = {
  paypal: ["https://www.paypal.com/", "https://www.paypal.com/signin"],
  microsoft: ["https://www.microsoft.com/", "https://login.microsoftonline.com/"],
  apple: ["https://www.apple.com/", "https://appleid.apple.com/sign-in"],
  google: ["https://www.google.com/", "https://accounts.google.com/signin"],
  amazon: ["https://www.amazon.com/", "https://www.amazon.com/ap/signin"],
  facebook: ["https://www.facebook.com/", "https://www.facebook.com/login"],
  netflix: ["https://www.netflix.com/", "https://www.netflix.com/login"],
  bankofamerica: [
    "https://www.bankofamerica.com/",
    "https://www.bankofamerica.com/online-banking/sign-in/",
  ],
  chase: ["https://www.chase.com/", "https://www.chase.com/digital/online-banking"],
  wellsfargo: [
    "https://www.wellsfargo.com/",
    "https://connect.secure.wellsfargo.com/auth/login/present",
  ],
  dropbox: ["https://www.dropbox.com/", "https://www.dropbox.com/login"],
  linkedin: ["https://www.linkedin.com/", "https://www.linkedin.com/login"],
  instagram: ["https://www.instagram.com/", "https://www.instagram.com/accounts/login/"],
  docusign: ["https://www.docusign.com/", "https://account.docusign.com/"],
  adobe: ["https://www.adobe.com/", "https://auth.services.adobe.com/en_US/sign-in"],
  outlook: ["https://outlook.live.com/", "https://login.live.com/"],
  office365: ["https://www.office.com/", "https://login.microsoftonline.com/"],
};

/** Set BRANDS="paypal,google" to capture a subset (debugging / sweet spot checks). */
function selectedBrands(): [string, string[]][] {
  const filter = (process.env.BRANDS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const entries = Object.entries(BRAND_REFERENCE_URLS);
  if (!filter.length) return entries;
  const picked = entries.filter(([brand]) => filter.includes(brand));
  const unknown = filter.filter((b) => !picked.some(([brand]) => brand === b));
  if (unknown.length) console.log(`Ignoring unknown brand(s): ${unknown.join(", ")}`);
  return picked;
}

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
  else if (colorType === 4)
    channels = 2; // gray + alpha
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

/* ---------------------------------------------------------------- */
/* Minimal PNG encoder (8-bit RGB, filter 0) — enough for a          */
/* downscaled reference thumbnail, so no image library is needed.    */
/* ---------------------------------------------------------------- */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "latin1");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePng(image: RawImage): Buffer {
  const { width, height, data } = image;
  const raw = Buffer.alloc(height * (1 + width * 3));
  let o = 0;
  for (let y = 0; y < height; y += 1) {
    raw[o++] = 0; // filter: none
    for (let x = 0; x < width; x += 1) {
      const i = (y * width + x) * 4;
      raw[o++] = data[i];
      raw[o++] = data[i + 1];
      raw[o++] = data[i + 2];
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: truecolour
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([
    signature,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

/** Nearest-neighbour downscale, which is all a small preview needs. */
function downscale(image: RawImage, maxWidth: number): RawImage {
  if (image.width <= maxWidth) return image;
  const scale = maxWidth / image.width;
  const width = Math.max(1, Math.round(image.width * scale));
  const height = Math.max(1, Math.round(image.height * scale));
  const out = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    const sy = Math.min(image.height - 1, Math.floor(y / scale));
    for (let x = 0; x < width; x += 1) {
      const sx = Math.min(image.width - 1, Math.floor(x / scale));
      const si = (sy * image.width + sx) * 4;
      const di = (y * width + x) * 4;
      out[di] = image.data[si];
      out[di + 1] = image.data[si + 1];
      out[di + 2] = image.data[si + 2];
      out[di + 3] = 255;
    }
  }
  return { width, height, data: out };
}

function pngDataUrl(image: RawImage): string {
  return `data:image/png;base64,${encodePng(downscale(image, THUMB_MAX_WIDTH)).toString("base64")}`;
}

interface CaptureAttempt {
  ok: boolean;
  /** Why the attempt failed, in words the report can carry. */
  reason?: string;
}

/**
 * One screenshot attempt with a realistic, persistent browser identity.
 *
 * Beyond the plain headless flags this sets the things a bot wall actually
 * inspects: `AutomationControlled` is disabled so `navigator.webdriver` is not
 * trivially true, the locale/accept-language are set, and `--user-data-dir`
 * points at the persistent profile so cookies survive between runs. Later
 * attempts get a longer virtual-time budget, because the first thing a
 * consent interstitial does is delay the real page.
 */
function capture(url: string, chrome: string, outFile: string, attempt = 1): CaptureAttempt {
  try {
    mkdirSync(PROFILE_DIR, { recursive: true });
  } catch {
    /* a read-only profile path just means no cookie persistence */
  }
  const args = [
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-blink-features=AutomationControlled",
    "--lang=en-US",
    "--accept-lang=en-US,en;q=0.9",
    "--user-data-dir=" + PROFILE_DIR,
    "--user-agent=" + USER_AGENT,
    "--window-size=" + VIEWPORT,
    `--virtual-time-budget=${9000 + (attempt - 1) * 5000}`,
    "--screenshot=" + outFile,
    url,
  ];
  const res = spawnSync(chrome, args, { timeout: 60000, encoding: "buffer" });
  if (res.status !== 0) {
    const stderr = res.stderr?.toString("utf8") ?? "";
    const tail = stderr.trim().split("\n").filter(Boolean).slice(-1)[0] ?? "";
    return {
      ok: false,
      reason: `chrome exited ${res.status}${tail ? `: ${tail.slice(0, 120)}` : ""}`,
    };
  }
  if (!existsSync(outFile)) return { ok: false, reason: "no screenshot written" };
  if (readFileSync(outFile).length <= 2000) return { ok: false, reason: "screenshot was empty" };
  return { ok: true };
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
  const thumbs: Record<string, string> = {};
  /** Brands attempted in THIS run (so a `BRANDS=` subset never drops others). */
  const attempted = new Set<string>();
  /** Brands that were attempted and produced no acceptable capture. */
  const rejected = new Set<string>();
  const report: Record<string, { status: string; attempts: number; reason?: string }> = {};

  // A capture that produced a uniform (blank / unstyled / error) page hashes
  // to the SAME value for every site — headless Chrome screenshots race the
  // first paint, so this silently happens. Detect it and refuse the capture:
  // shipping such a file makes a blank-ish page "match" every brand.
  const hashOwner = new Map<string, string>();
  const isBlankPage = (image: RawImage): boolean => {
    const data = image.data;
    const first = [data[0], data[1], data[2]];
    for (let i = 0; i < data.length; i += 4) {
      if (
        Math.abs(data[i] - first[0]) > 8 ||
        Math.abs(data[i + 1] - first[1]) > 8 ||
        Math.abs(data[i + 2] - first[2]) > 8
      ) {
        return false;
      }
    }
    return true;
  };

  // A capture can be non-uniform yet still degenerate: a bot wall, a cookie
  // interstitial, or a redirect stub renders as an almost-white page with a
  // line or two of text. Such a capture is not the brand login it claims to
  // be, and shipping it as that brand's reference makes every near-white page
  // "match" the brand. Require a minimum share of pixels outside the modal
  // colour before accepting.
  const hasEnoughContent = (image: RawImage): boolean => {
    const data = image.data;
    const counts = new Map<number, number>();
    for (let i = 0; i < data.length; i += 4) {
      const key = ((data[i] >> 4) << 8) | ((data[i + 1] >> 4) << 4) | (data[i + 2] >> 4);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    let modal = 0;
    for (const count of counts.values()) if (count > modal) modal = count;
    const total = data.length / 4;
    return (total - modal) / total >= 0.03;
  };

  // Captures are slow (a full run is minutes) and browsers get bot-walled, so
  // the file is rewritten after every accepted capture: a killed run keeps
  // everything it had already earned instead of losing the whole batch.
  const persist = (): Record<string, string> => {
    let merged: Record<string, string> = {};
    if (existsSync(OUTPUT_PATH)) {
      try {
        merged = JSON.parse(readFileSync(OUTPUT_PATH, "utf8"));
      } catch {
        merged = {};
      }
    }
    Object.assign(merged, hashes);

    // A capture that failed or came back degenerate must not leave the
    // PREVIOUS run's entry in place. That is exactly how a bot-wall stub
    // survived in this file as "adobe": the new capture was correctly rejected
    // as near-blank, but the merge kept the old, equally-useless hash, so the
    // report claimed an Adobe reference that had never been captured.
    for (const brand of rejected) {
      if (brand in merged) {
        console.log(`Dropping stale reference for "${brand}" — no capture succeeded this run`);
        delete merged[brand];
      }
    }

    // Drop any entry that shares a hash with a different brand: that is the
    // signature of a blank-page capture, and one such entry is enough to make
    // every unrelated page look like that "brand".
    const byHash = new Map<string, string>();
    for (const [brand, hash] of Object.entries(merged)) {
      const owner = byHash.get(hash);
      if (owner && owner !== brand) {
        console.log(`Dropping degenerate reference for "${brand}" (hash shared with "${owner}")`);
        delete merged[brand];
        continue;
      }
      byHash.set(hash, brand);
    }

    const sorted = Object.fromEntries(
      Object.entries(merged).sort(([a], [b]) => a.localeCompare(b)),
    );
    mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
    writeFileSync(OUTPUT_PATH, JSON.stringify(sorted, null, 2) + "\n");
    return sorted;
  };

  // Thumbnails are written incrementally too, for the same reason: a long run
  // that is interrupted keeps the previews it already captured.
  const persistThumbs = (): void => {
    let merged: Record<string, string> = {};
    if (existsSync(THUMBS_PATH)) {
      try {
        merged = JSON.parse(readFileSync(THUMBS_PATH, "utf8"));
      } catch {
        merged = {};
      }
    }
    Object.assign(merged, thumbs);
    for (const brand of rejected) delete merged[brand];
    const sorted = Object.fromEntries(
      Object.entries(merged).sort(([a], [b]) => a.localeCompare(b)),
    );
    mkdirSync(dirname(THUMBS_PATH), { recursive: true });
    writeFileSync(THUMBS_PATH, JSON.stringify(sorted, null, 2) + "\n");
  };

  for (const [brand, urls] of selectedBrands()) {
    attempted.add(brand);
    let captured = false;
    let attemptsUsed = 0;
    let lastReason = "no capture attempted";
    let lastStatus = "failed";

    // Retry the brand's URLs with the persistent profile: a wall that answers
    // the first attempt with a consent interstitial often lets the second
    // through once the cookie it set is replayed.
    urlLoop: for (const url of urls) {
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
        attemptsUsed += 1;
        const outFile = join(TMP_DIR, `${brand}.png`);
        process.stdout.write(`- ${brand}: ${url} (attempt ${attempt}/${MAX_ATTEMPTS}) … `);
        const shot = capture(url, chrome, outFile, attempt);
        if (!shot.ok) {
          lastStatus = "failed";
          lastReason = shot.reason ?? "capture failed";
          console.log(`capture FAILED (${lastReason})`);
          continue;
        }
        try {
          const png = readFileSync(outFile);
          const image = decodePng(png);
          if (!image) {
            lastStatus = "degenerate";
            lastReason = "screenshot could not be decoded";
            console.log("decode FAILED");
            continue;
          }
          if (isBlankPage(image)) {
            lastStatus = "degenerate";
            lastReason = "uniform/blank page";
            console.log("degenerate capture (uniform/blank page)");
            continue;
          }
          if (!hasEnoughContent(image)) {
            lastStatus = "degenerate";
            lastReason = "near-blank page (bot wall or consent interstitial)";
            console.log("degenerate capture (near-blank / bot wall)");
            continue;
          }
          const hash = phashHex(image);
          const owner = hashOwner.get(hash);
          if (owner && owner !== brand) {
            lastStatus = "degenerate";
            lastReason = `phash collides with "${owner}"`;
            console.log(`phash = ${hash} COLLIDES with "${owner}"`);
            continue;
          }
          hashOwner.set(hash, brand);
          hashes[brand] = hash;
          persist();
          // Preview image for the side-by-side view in the extension popup. A
          // very large data URL is dropped rather than bloating the bundle.
          let thumbNote = "";
          try {
            const thumb = pngDataUrl(image);
            if (thumb.length <= 250_000) {
              thumbs[brand] = thumb;
              persistThumbs();
              thumbNote = `, thumbnail ${Math.round(thumb.length / 1024)}KB`;
            } else {
              thumbNote = ", thumbnail too large — skipped";
            }
          } catch {
            thumbNote = ", thumbnail encode failed";
          }
          console.log(`phash = ${hash}${thumbNote}`);
          captured = true;
          break urlLoop;
        } catch (err) {
          lastStatus = "failed";
          lastReason = err instanceof Error ? err.message : String(err);
          console.log(`error: ${lastReason}`);
        }
      }
    }

    if (captured) {
      report[brand] = { status: "captured", attempts: attemptsUsed };
    } else {
      rejected.add(brand);
      report[brand] = { status: lastStatus, attempts: attemptsUsed, reason: lastReason };
      console.log(
        `× ${brand}: no acceptable capture in ${attemptsUsed} attempt(s) — ${lastReason}`,
      );
    }
  }

  rmSync(TMP_DIR, { recursive: true, force: true });

  // Reconcile the run against the documented gaps, so a persistent failure is a
  // recorded, reviewable fact rather than a silent absence.
  let knownGaps: Record<string, { reason?: string }> = {};
  try {
    knownGaps = JSON.parse(readFileSync(GAPS_PATH, "utf8")) as Record<string, { reason?: string }>;
  } catch {
    knownGaps = {};
  }

  const sorted = persist();
  persistThumbs();
  const unresolved = [...rejected].sort();
  const undocumented = unresolved.filter((b) => !(b in knownGaps));
  const resolvedGaps = Object.keys(knownGaps).filter(
    (b) => attempted.has(b) && !rejected.has(b) && Boolean(sorted[b]),
  );

  const reportPayload = {
    generated_at: new Date().toISOString(),
    capture_attempts: MAX_ATTEMPTS,
    brands: report,
    unresolved,
    documented_gaps: Object.keys(knownGaps).sort(),
  };
  mkdirSync(dirname(REPORT_PATH), { recursive: true });
  writeFileSync(REPORT_PATH, JSON.stringify(reportPayload, null, 2) + "\n");

  console.log(`\nWrote ${Object.keys(sorted).length} reference hashes to ${OUTPUT_PATH}`);
  const mergedThumbs = existsSync(THUMBS_PATH)
    ? (JSON.parse(readFileSync(THUMBS_PATH, "utf8")) as Record<string, string>)
    : {};
  console.log(`Wrote ${Object.keys(mergedThumbs).length} reference thumbnails to ${THUMBS_PATH}`);
  console.log(`Wrote capture report to ${REPORT_PATH}`);
  if (unresolved.length) {
    console.log(`\nNo reference captured for: ${unresolved.join(", ")}`);
  }
  if (undocumented.length) {
    console.log(
      `\n⚠ Undocumented capture failures: ${undocumented.join(", ")}\n` +
        "  If these are persistent, add them to extension/data/known_reference_gaps.json " +
        "with a reason; the gap test asserts the file and the shipped references agree.",
    );
  }
  if (resolvedGaps.length) {
    console.log(
      `\n✓ Documented gaps that captured successfully: ${resolvedGaps.join(", ")}\n` +
        "  Remove them from extension/data/known_reference_gaps.json — the gap test will fail " +
        "while a brand is both documented as a gap and shipped as a reference.",
    );
  }
}

void main();
