/**
 * Dependency-free ZIP (deflate) writer shared by the packagers.
 *
 * Deliberately avoids the `zip` binary and `archiver` so the same script runs
 * on Windows, macOS and Linux with nothing but Node installed.
 */
import { createWriteStream, renameSync, rmSync } from "node:fs";
import { deflateRawSync } from "node:zlib";

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Write `entries` ([{ name, data }], data being a Buffer) into a ZIP archive at
 * `outPath`, preserving the order given. Entry names use forward slashes.
 */
export async function writeZip(outPath, entries) {
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

  for (const { name, data } of entries) addEntry(name, data);

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

  // Stream next to the target, then move it into place. On Windows an
  // on-access antivirus scan of the previous archive can make opening the real
  // path fail with errno -4094 (UNKNOWN), and a half-written zip is worse than
  // a failed build: reviewers upload these files.
  const tmpPath = `${outPath}.tmp`;
  await new Promise((resolve, reject) => {
    const stream = createWriteStream(tmpPath);
    stream.on("error", reject);
    stream.on("finish", resolve);
    stream.end(Buffer.concat([...localParts, ...centralParts, end]));
  });

  for (let attempt = 0; ; attempt += 1) {
    try {
      renameSync(tmpPath, outPath);
      return;
    } catch (error) {
      // Windows refuses to replace a file another process holds open without
      // delete sharing — Firefox does exactly that while the archive is loaded
      // as a temporary add-on. Moving the old file aside still works, so the
      // path gets the new archive and the running add-on keeps its handle.
      try {
        const parked = `${outPath}.old`;
        renameSync(outPath, parked);
        renameSync(tmpPath, outPath);
        try {
          rmSync(parked, { force: true });
        } catch {
          /* the handle is still open; the file goes away when it closes */
        }
        return;
      } catch {
        /* fall through to the retry / real error below */
      }
      if (attempt === 4) {
        rmSync(tmpPath, { force: true });
        throw error;
      }
      // Wait out whatever is still holding the old file.
      await new Promise((resolve) => setTimeout(resolve, 200 * (attempt + 1)));
    }
  }
}
