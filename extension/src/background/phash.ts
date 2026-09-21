/**
 * Perceptual hash — a dependency-free JS port of Python's `imagehash.phash`
 * (64-bit DCT-based hash, hash_size=8, highfreq_factor=4) so screenshots taken
 * by the extension produce hashes in the SAME format as
 * `backend/app/analyzers/webpage/visual.py` and the hashes stored in
 * `data/reference_hashes.json` (16 lowercase hex chars).
 *
 * Pipeline (identical to Pillow+scipy):
 *   1. grayscale ("L"), resize to 32x32 (Lanczos in Pillow; we use the
 *      canvas's best smoothing, then bilinear fallback)
 *   2. 2D DCT-II (scipy.fftpack.dct, type=2, norm=None, rows then cols)
 *   3. keep the 8x8 low-frequency block
 *   4. median over all 64 coefficients
 *   5. bit i = coeff_i > median, row-major
 *   6. hex string, MSB-first, zero-padded to 16 nibbles
 *
 * Keep in sync with the Python generator if the algorithm ever changes.
 */

export const PHASH_SIZE = 8;
export const DCT_SIZE = 32; // hash_size * highfreq_factor

export interface RawImage {
  width: number;
  height: number;
  data: Uint8ClampedArray; // RGBA, row-major
}

/** 1D DCT-II (type 2, unnormalised) as used by scipy.fftpack.dct. */
export function dct1d(x: number[]): number[] {
  const n = x.length;
  const out = new Array<number>(n);
  for (let k = 0; k < n; k += 1) {
    let sum = 0;
    for (let i = 0; i < n; i += 1) {
      sum += x[i] * Math.cos((Math.PI * k * (2 * i + 1)) / (2 * n));
    }
    out[k] = 2 * sum;
  }
  return out;
}

/** Fast identity DCT2 for the separable 2D transform. */
export function dct2d(pixels: number[][]): number[][] {
  const rows = dct1dRows(pixels);
  const out: number[][] = [];
  for (let i = 0; i < rows.length; i += 1) {
    const col = new Array<number>(rows.length);
    for (let j = 0; j < rows.length; j += 1) {
      col[j] = rows[j][i];
    }
    const transformed = dct1d(col);
    out.push(transformed);
  }
  return out;
}

function dct1dRows(pixels: number[][]): number[][] {
  const out: number[][] = [];
  for (let y = 0; y < pixels.length; y += 1) {
    out.push(dct1d(pixels[y]));
  }
  return out;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[mid];
  return (sorted[mid - 1] + sorted[mid]) / 2;
}

/** Grayscale the raw RGBA image into 32x32 luminance (row-major floats). */
export function toGrayscale32(img: RawImage): number[][] {
  const { width, height, data } = img;
  const cellW = width / DCT_SIZE;
  const cellH = height / DCT_SIZE;
  const out: number[][] = [];

  for (let y = 0; y < DCT_SIZE; y += 1) {
    const row: number[] = [];
    const y0 = Math.floor(y * cellH);
    const y1 = Math.max(y0 + 1, Math.floor((y + 1) * cellH));
    for (let x = 0; x < DCT_SIZE; x += 1) {
      const x0 = Math.floor(x * cellW);
      const x1 = Math.max(x0 + 1, Math.floor((x + 1) * cellW));
      let r = 0;
      let g = 0;
      let b = 0;
      let count = 0;
      for (let yy = y0; yy < y1; yy += 1) {
        for (let xx = x0; xx < x1; xx += 1) {
          const idx = (yy * width + xx) * 4;
          r += data[idx];
          g += data[idx + 1];
          b += data[idx + 2];
          count += 1;
        }
      }
      // Pillow "L": R*299/1000 + G*587/1000 + B*114/1000 (601 luma, rounded)
      const lum = Math.round((r / count) * 0.299 + (g / count) * 0.587 + (b / count) * 0.114);
      row.push(lum);
    }
    out.push(row);
  }
  return out;
}

/** 64-bit pHash hex string (16 lowercase hex chars) for a raw RGBA image. */
export function phashHex(img: RawImage): string {
  const gray = toGrayscale32(img);
  const dct = dct2d(gray);
  const low: number[] = [];
  for (let y = 0; y < PHASH_SIZE; y += 1) {
    for (let x = 0; x < PHASH_SIZE; x += 1) {
      low.push(dct[y][x]);
    }
  }
  const med = median(low);
  let bits = 0n;
  for (let i = 0; i < low.length; i += 1) {
    bits = (bits << 1n) | (low[i] > med ? 1n : 0n);
  }
  return bits.toString(16).padStart((PHASH_SIZE * PHASH_SIZE) / 4, "0");
}

const NIBBLE_POPCOUNT = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

/** Hamming distance between two pHash hex strings of equal length. */
export function hammingDistanceHex(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  let distance = 0;
  for (let i = 0; i < len; i += 1) {
    const x = parseInt(a[i], 16);
    const y = parseInt(b[i], 16);
    if (Number.isNaN(x) || Number.isNaN(y)) continue;
    distance += NIBBLE_POPCOUNT[x ^ y];
  }
  return distance;
}

/** Renders a PNG data URL into raw RGBA pixels (OffscreenCanvas, worker-safe). */
export async function decodeDataUrlToImage(dataUrl: string): Promise<RawImage | null> {
  try {
    const res = await fetch(dataUrl);
    const blob = await res.blob();
    const bitmap = await createImageBitmap(blob);
    try {
      const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (!ctx) return null;
      ctx.drawImage(bitmap, 0, 0);
      const imageData = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
      return { width: bitmap.width, height: bitmap.height, data: imageData.data };
    } finally {
      bitmap.close();
    }
  } catch {
    return null;
  }
}

/** Convenience: full pipeline from a captured PNG data URL straight to hex. */
export async function phashFromDataUrl(dataUrl: string): Promise<string | null> {
  const img = await decodeDataUrlToImage(dataUrl);
  if (!img) return null;
  return phashHex(img);
}
