import { describe, expect, it } from "vitest";
import {
  DEFAULT_OVERLAY_COLORS,
  edgeBitmapFromRgba,
  heatColor,
  overallSimilarity,
  overlayEdgeMaps,
  regionSimilarity,
  resizeEdgeBitmap,
  type EdgeBitmap,
} from "../src/lib/region-similarity";

function bitmap(width: number, height: number, data: number[]): EdgeBitmap {
  expect(data.length).toBe(width * height);
  return { width, height, data: Uint8Array.from(data) };
}

function solidRgba(width: number, height: number, leftDark: boolean): Uint8ClampedArray {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const dark = leftDark ? x < width / 2 : false;
      const v = dark ? 10 : 245;
      const i = (y * width + x) * 4;
      data[i] = data[i + 1] = data[i + 2] = v;
      data[i + 3] = 255;
    }
  }
  return data;
}

describe("edgeBitmapFromRgba", () => {
  it("finds the boundary of a high-contrast shape", () => {
    const map = edgeBitmapFromRgba(24, 24, solidRgba(24, 24, true));

    expect(map.width).toBe(24);
    expect(map.height).toBe(24);
    expect(Array.from(map.data).filter((v) => v === 1).length).toBeGreaterThan(0);
  });

  it("finds no edges in a flat image", () => {
    const map = edgeBitmapFromRgba(16, 16, solidRgba(16, 16, false));
    expect(Array.from(map.data).every((v) => v === 0)).toBe(true);
  });
});

describe("resizeEdgeBitmap", () => {
  it("returns the same bitmap when the size already matches", () => {
    const map = bitmap(2, 2, [1, 0, 0, 1]);
    expect(resizeEdgeBitmap(map, 2, 2)).toBe(map);
  });

  it("resizes to the requested grid and preserves isolated edges", () => {
    const map = bitmap(
      4,
      4,
      Array.from({ length: 16 }, (_, i) => (i === 5 ? 1 : 0)),
    );
    const small = resizeEdgeBitmap(map, 8, 8);

    expect(small.width).toBe(8);
    expect(small.height).toBe(8);
    expect(Array.from(small.data).some((v) => v === 1)).toBe(true);
  });
});

describe("regionSimilarity", () => {
  it("scores identical maps as full agreement everywhere", () => {
    const a = bitmap(4, 2, [1, 1, 0, 0, 0, 0, 1, 0]);
    const matrix = regionSimilarity(a, a, 2, 1);

    expect(matrix).toEqual([[1, 1]]);
    expect(overallSimilarity(matrix)).toBe(1);
  });

  it("scores a region with structure on only one side as zero", () => {
    const a = bitmap(4, 2, [1, 1, 0, 0, 0, 0, 0, 0]);
    const b = bitmap(4, 2, [0, 0, 0, 0, 0, 0, 0, 0]);

    // Left cell: edges on one side only -> 0. Right cell: both blank -> 1.
    expect(regionSimilarity(a, b, 2, 1)).toEqual([[0, 1]]);
  });

  it("uses Dice overlap so a half-covered region lands in between", () => {
    // Two edges each, one shared: Dice = 2*1/(2+2) = 0.5
    const a = bitmap(4, 1, [1, 1, 0, 0]);
    const b = bitmap(4, 1, [1, 0, 1, 0]);
    // Whole bitmap as one region.
    const [score] = regionSimilarity(a, b, 1, 1)[0];
    expect(score).toBeCloseTo(0.5, 5);
  });

  it("rejects mismatched sizes and empty grids", () => {
    const a = bitmap(2, 1, [1, 0]);
    const b = bitmap(4, 1, [1, 0, 1, 0]);
    expect(() => regionSimilarity(a, b, 2, 1)).toThrow();
    expect(() => regionSimilarity(a, a, 0, 1)).toThrow();
  });
});

describe("overallSimilarity", () => {
  it("averages every cell", () => {
    expect(
      overallSimilarity([
        [1, 0],
        [0.5, 0.5],
      ]),
    ).toBeCloseTo(0.5, 5);
    expect(overallSimilarity([])).toBe(0);
  });
});

describe("overlayEdgeMaps", () => {
  it("colours legend, reference and agreement pixels distinctly", () => {
    const a = bitmap(4, 1, [1, 0, 1, 0]);
    const b = bitmap(4, 1, [1, 0, 0, 0]);

    const out = overlayEdgeMaps(a, b);
    const pixel = (i: number) => [out[i * 4], out[i * 4 + 1], out[i * 4 + 2]];

    expect(pixel(0)).toEqual([...DEFAULT_OVERLAY_COLORS.both]); // both agree
    expect(pixel(1)).toEqual([...DEFAULT_OVERLAY_COLORS.background]); // neither
    expect(pixel(2)).toEqual([...DEFAULT_OVERLAY_COLORS.first]); // captured only
    expect(out[3]).toBe(255);
  });

  it("rejects mismatched sizes", () => {
    expect(() => overlayEdgeMaps(bitmap(2, 1, [1, 0]), bitmap(3, 1, [0, 0, 0]))).toThrow();
  });
});

describe("heatColor", () => {
  it("runs red to green through amber and clamps out-of-range input", () => {
    expect(heatColor(0)).toBe("rgb(239 68 68)");
    expect(heatColor(0.5)).toBe("rgb(245 158 11)");
    expect(heatColor(1)).toBe("rgb(16 185 129)");
    expect(heatColor(-2)).toBe("rgb(239 68 68)");
    expect(heatColor(5)).toBe("rgb(16 185 129)");
  });
});
