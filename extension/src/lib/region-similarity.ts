/**
 * Structural comparison of two page layouts.
 *
 * A single perceptual-hash distance answers "how far apart are these two
 * images?" — one number, no locality, and no way to see *where* they differ.
 * This module answers the same question structurally instead: both images are
 * reduced to edge maps (layout without colour or text), normalised to a common
 * grid, and compared region by region. The result is a per-region similarity
 * matrix the UI renders as a heatmap plus an overlay of the two edge maps.
 *
 * Everything here is a pure function over plain arrays, so it is tested
 * directly without a canvas or a browser.
 */

import { sobelEdges } from "../background/phash";

/** A binary edge map: 1 = edge pixel, 0 = background. */
export interface EdgeBitmap {
  width: number;
  height: number;
  data: Uint8Array;
}

/** Reduce an RGBA buffer to a binary edge map (layout, not pixels). */
export function edgeBitmapFromRgba(
  width: number,
  height: number,
  rgba: Uint8ClampedArray,
  threshold = 128,
): EdgeBitmap {
  const edges = sobelEdges(width, height, rgba);
  const data = new Uint8Array(width * height);
  for (let p = 0, i = 0; i < data.length; i += 1, p += 4) {
    // sobelEdges draws lines as black on white; a dark pixel is an edge.
    data[i] = edges[p] < threshold ? 1 : 0;
  }
  return { width, height, data };
}

/** Nearest-neighbour resize of an edge map (edges are binary; no smoothing). */
export function resizeEdgeBitmap(map: EdgeBitmap, width: number, height: number): EdgeBitmap {
  if (map.width === width && map.height === height) return map;
  const data = new Uint8Array(width * height);
  for (let y = 0; y < height; y += 1) {
    const sy = Math.min(map.height - 1, Math.floor((y * map.height) / height));
    for (let x = 0; x < width; x += 1) {
      const sx = Math.min(map.width - 1, Math.floor((x * map.width) / width));
      data[y * width + x] = map.data[sy * map.width + sx];
    }
  }
  return { width, height, data };
}

/**
 * Per-region agreement between two edge maps, as a `rows x cols` matrix of
 * 0..1 values.
 *
 * Each cell uses the Dice coefficient over its edge pixels: 2|A∩B| / (|A|+|B|).
 * Two empty cells count as agreement (1) — a blank region really is the same,
 * and treating it as a mismatch would drag every score down. A cell with edges
 * on one side only scores 0, which is exactly the "this page has the form
 * here, the reference does not" signal worth surfacing.
 */
export function regionSimilarity(
  a: EdgeBitmap,
  b: EdgeBitmap,
  cols: number,
  rows: number,
): number[][] {
  if (a.width !== b.width || a.height !== b.height) {
    throw new Error("regionSimilarity requires edge maps of equal size");
  }
  if (cols < 1 || rows < 1) throw new Error("regionSimilarity requires a positive grid");

  const matrix: number[][] = [];
  for (let row = 0; row < rows; row += 1) {
    const y0 = Math.floor((row * a.height) / rows);
    const y1 = Math.max(y0 + 1, Math.floor(((row + 1) * a.height) / rows));
    const line: number[] = [];
    for (let col = 0; col < cols; col += 1) {
      const x0 = Math.floor((col * a.width) / cols);
      const x1 = Math.max(x0 + 1, Math.floor(((col + 1) * a.width) / cols));
      let countA = 0;
      let countB = 0;
      let both = 0;
      for (let y = y0; y < y1; y += 1) {
        for (let x = x0; x < x1; x += 1) {
          const i = y * a.width + x;
          const inA = a.data[i] === 1;
          const inB = b.data[i] === 1;
          if (inA) countA += 1;
          if (inB) countB += 1;
          if (inA && inB) both += 1;
        }
      }
      if (countA + countB === 0) line.push(1);
      else line.push((2 * both) / (countA + countB));
    }
    matrix.push(line);
  }
  return matrix;
}

/** Mean of a similarity matrix, 0..1. */
export function overallSimilarity(matrix: number[][]): number {
  let total = 0;
  let count = 0;
  for (const row of matrix) {
    for (const value of row) {
      total += value;
      count += 1;
    }
  }
  return count === 0 ? 0 : total / count;
}

export interface OverlayColors {
  /** Edges present only in the first (captured) map. */
  first: [number, number, number];
  /** Edges present only in the second (reference) map. */
  second: [number, number, number];
  /** Edges present in both. */
  both: [number, number, number];
  background: [number, number, number];
}

export const DEFAULT_OVERLAY_COLORS: OverlayColors = {
  first: [245, 158, 11], // amber — this page
  second: [56, 189, 248], // sky — reference
  both: [244, 244, 245], // near-white — agreement
  background: [15, 23, 42], // slate-950 — empty space
};

/**
 * Superimpose two edge maps into one RGBA buffer.
 *
 * Colour carries the meaning: amber where only the captured page has
 * structure, blue where only the reference does, white where both agree. That
 * turns "distance 24" into a picture of exactly which parts of the page line
 * up and which do not.
 */
export function overlayEdgeMaps(
  a: EdgeBitmap,
  b: EdgeBitmap,
  colors: OverlayColors = DEFAULT_OVERLAY_COLORS,
): Uint8ClampedArray {
  if (a.width !== b.width || a.height !== b.height) {
    throw new Error("overlayEdgeMaps requires edge maps of equal size");
  }
  const out = new Uint8ClampedArray(a.width * a.height * 4);
  for (let i = 0; i < a.width * a.height; i += 1) {
    const inA = a.data[i] === 1;
    const inB = b.data[i] === 1;
    const rgb =
      inA && inB ? colors.both : inA ? colors.first : inB ? colors.second : colors.background;
    const p = i * 4;
    out[p] = rgb[0];
    out[p + 1] = rgb[1];
    out[p + 2] = rgb[2];
    out[p + 3] = 255;
  }
  return out;
}

/**
 * Heatmap colour for a 0..1 similarity: red (no agreement) through amber to
 * green (agreement), returned as a CSS colour.
 */
export function heatColor(value: number): string {
  const v = Math.max(0, Math.min(1, value));
  const stops: { at: number; rgb: [number, number, number] }[] = [
    { at: 0, rgb: [239, 68, 68] }, // red-500
    { at: 0.5, rgb: [245, 158, 11] }, // amber-500
    { at: 1, rgb: [16, 185, 129] }, // emerald-500
  ];
  let lower = stops[0];
  let upper = stops[stops.length - 1];
  for (let i = 0; i < stops.length - 1; i += 1) {
    if (v >= stops[i].at && v <= stops[i + 1].at) {
      lower = stops[i];
      upper = stops[i + 1];
      break;
    }
  }
  const span = upper.at - lower.at || 1;
  const t = (v - lower.at) / span;
  const mix = lower.rgb.map((c, i) => Math.round(c + (upper.rgb[i] - c) * t));
  return `rgb(${mix[0]} ${mix[1]} ${mix[2]})`;
}
