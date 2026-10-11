#!/usr/bin/env node
/**
 * Package extension/dist into a zip for submission.
 *
 *   node scripts/zip-dist.mjs chrome   -> ../phishbrain-extension-chrome.zip (uses dist/manifest.json)
 *   node scripts/zip-dist.mjs firefox  -> ../phishbrain-extension-firefox.zip
 *                                        (uses dist/manifest.firefox.json renamed manifest.json,
 *                                         which is what Mozilla Add-ons requires)
 *
 * Dependency-free ZIP writer (deflate) so it runs on Windows/macOS/Linux
 * without the `zip` binary.
 */
import { createWriteStream, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(HERE, "..", "dist");

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

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
  console.error('Usage: node scripts/zip-dist.mjs [chrome|firefox]');
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
    console.error("dist/manifest.firefox.json not found — run `bun run build` first.");
    process.exit(1);
  }
}

const encoder = new TextEncoder();
const localParts = [];
const centralParts = [];
let offset = 0;

function addEntry(name, data) {
  const crc = crc32(data);
  const comp = deflateRawSync(data);
  const nameBuf = encoder.encode(name);
  const isDir = data.length === 0 && name.endsWith("/");

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); // local file header signature
  local.writeUInt16LE(20, 4); // version needed
  local.writeUInt16LE(0x0800, 6); // flags: UTF-8
  local.writeUInt16LE(isDir ? 0 : 8, 8); // method: deflate (0 for dirs)
  local.writeUInt16LE(0, 10); // mod time
  local.writeUInt16LE(0, 12); // mod date
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(comp.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);
  local.writeUInt16LE(0, 28); // extra length
  localParts.push(local, nameBuf, comp);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0); // central directory signature
  central.writeUInt16LE(20, 4); // version made by
  central.writeUInt16LE(20, 6); // version needed
  central.writeUInt16LE(0x0800, 8); // flags
  central.writeUInt16LE(isDir ? 0 : 8, 10);
  central.writeUInt16LE(0, 12);
  central.writeUInt16LE(0, 14);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(comp.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBuf.length, 28);
  central.writeUInt16LE(0, 30); // extra
  central.writeUInt16LE(0, 32); // comment
  central.writeUInt16LE(0, 34); // disk
  central.writeUInt16LE(0, 36); // internal attrs
  central.writeUInt32LE(0, 38); // external attrs
  central.writeUInt32LE(offset, 42); // local header offset
  centralParts.push(central, nameBuf);
  offset += local.length + nameBuf.length + comp.length;
}

for (const name of names.sort()) {
  if (flavour === "firefox" && name === "manifest.firefox.json") continue; // added below as manifest.json
  if (name === "manifest.json" && flavour === "firefox") continue;
  // The Chrome package must not ship the Firefox manifest either. Two
  // manifests in one archive is ambiguous for a store reviewer and for anyone
  // unzipping the package to see which one is live.
  if (flavour === "chrome" && name === "manifest.firefox.json") continue;
  const data = readFileSync(join(DIST, name.replace(/\//g, "\\")));
  addEntry(name, data);
}
if (flavour === "firefox") {
  addEntry("manifest.json", readFileSync(join(DIST, "manifest.firefox.json")));
}

const centralSize = centralParts.reduce((s, p) => s + p.length, 0);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0); // end of central directory signature
end.writeUInt16LE(0, 4);
end.writeUInt16LE(0, 6);
end.writeUInt16LE(centralParts.length / 2, 8);
end.writeUInt16LE(centralParts.length / 2, 10);
end.writeUInt32LE(centralSize, 12);
end.writeUInt32LE(offset, 16);
end.writeUInt16LE(0, 20);

mkdirSync(dirname(outName), { recursive: true });
const stream = createWriteStream(outName);
stream.write(Buffer.concat([...localParts, ...centralParts, end]));
stream.end();
stream.on("finish", () => console.log(`Wrote ${outName} (${files.length} files, flavour=${flavour})`));
