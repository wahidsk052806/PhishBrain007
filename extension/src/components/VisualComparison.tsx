import { useEffect, useState } from "react";
import { decodeDataUrlToImage } from "../background/phash";
import {
  edgeBitmapFromRgba,
  heatColor,
  overallSimilarity,
  overlayEdgeMaps,
  regionSimilarity,
  resizeEdgeBitmap,
  type EdgeBitmap,
} from "../lib/region-similarity";

/** Normalised comparison grid. Small enough to be cheap, large enough to hold
 * a login page's structure: header, form card, fields, button, footer. */
const GRID_WIDTH = 96;
const GRID_HEIGHT = 60;
const COLS = 8;
const ROWS = 5;

interface Comparison {
  overlayUrl: string | null;
  matrix: number[][];
  score: number;
}

function rgbaToDataUrl(width: number, height: number, rgba: Uint8ClampedArray): string | null {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;
    const imageData = ctx.createImageData(width, height);
    imageData.data.set(rgba);
    ctx.putImageData(imageData, 0, 0);
    return canvas.toDataURL("image/png");
  } catch {
    return null;
  }
}

function tone(score: number): { text: string; label: string } {
  if (score >= 70) return { text: "text-red-300", label: "strong structural match" };
  if (score >= 45) return { text: "text-amber-300", label: "partial structural match" };
  return { text: "text-emerald-300", label: "little shared structure" };
}

async function buildComparison(captured: string, reference: string): Promise<Comparison | null> {
  try {
    const [a, b] = await Promise.all([
      decodeDataUrlToImage(captured),
      decodeDataUrlToImage(reference),
    ]);
    if (!a || !b) return null;
    const left: EdgeBitmap = resizeEdgeBitmap(
      edgeBitmapFromRgba(a.width, a.height, a.data),
      GRID_WIDTH,
      GRID_HEIGHT,
    );
    const right: EdgeBitmap = resizeEdgeBitmap(
      edgeBitmapFromRgba(b.width, b.height, b.data),
      GRID_WIDTH,
      GRID_HEIGHT,
    );
    const matrix = regionSimilarity(left, right, COLS, ROWS);
    return {
      overlayUrl: rgbaToDataUrl(GRID_WIDTH, GRID_HEIGHT, overlayEdgeMaps(left, right)),
      matrix,
      score: Math.round(overallSimilarity(matrix) * 100),
    };
  } catch {
    return null;
  }
}

/**
 * Structural comparison of the captured page against the matched brand's
 * reference: the two edge maps overlaid, a per-region similarity heatmap and a
 * single comparison score. A hash distance says *how far* apart two images
 * are; this says *where* they differ, which is what makes the evidence
 * reviewable rather than just asserted.
 */
export default function VisualComparison({
  captured,
  reference,
  brand,
}: {
  captured: string;
  reference: string;
  brand?: string | null;
}) {
  const [state, setState] = useState<"loading" | "ready" | "unavailable">("loading");
  const [data, setData] = useState<Comparison | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState("loading");
    setData(null);
    void buildComparison(captured, reference)
      .then((result) => {
        if (cancelled) return;
        if (!result) {
          setState("unavailable");
          return;
        }
        setData(result);
        setState("ready");
      })
      .catch(() => {
        if (!cancelled) setState("unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, [captured, reference]);

  if (state === "loading") {
    return <p className="mt-2 text-[10px] text-slate-500">Comparing page structure…</p>;
  }
  if (state === "unavailable" || !data) {
    return (
      <p className="mt-2 text-[10px] text-slate-500">
        Structural comparison unavailable for this result (the images could not be decoded in this
        browser).
      </p>
    );
  }

  const { text, label } = tone(data.score);

  return (
    <div className="mt-2 rounded-md border border-slate-800 bg-slate-950/60 p-2">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
          Structural comparison
        </span>
        <span className={`text-[11px] font-semibold ${text}`}>
          {data.score}% · {label}
        </span>
      </div>

      {data.overlayUrl && (
        <figure className="mt-2">
          {/* Width-only sizing keeps the grid's exact aspect ratio: a squashed
              overlay would misreport where the two layouts agree. */}
          <img
            src={data.overlayUrl}
            alt={`Overlay of this page's layout edges against the ${
              brand ?? "reference"
            } reference layout`}
            className="w-full rounded border border-slate-800 object-contain"
            style={{ imageRendering: "pixelated" }}
          />
          <figcaption className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[9px] text-slate-500">
            <span className="inline-flex items-center gap-1">
              <span
                aria-hidden="true"
                className="inline-block size-2 rounded-sm"
                style={{ backgroundColor: "rgb(245 158 11)" }}
              />
              This page only
            </span>
            <span className="inline-flex items-center gap-1">
              <span
                aria-hidden="true"
                className="inline-block size-2 rounded-sm"
                style={{ backgroundColor: "rgb(56 189 248)" }}
              />
              {brand ? `${brand} reference only` : "Reference only"}
            </span>
            <span className="inline-flex items-center gap-1">
              <span
                aria-hidden="true"
                className="inline-block size-2 rounded-sm"
                style={{ backgroundColor: "rgb(244 244 245)" }}
              />
              Both agree
            </span>
          </figcaption>
        </figure>
      )}

      <div className="mt-2">
        <p className="mb-1 text-[9px] uppercase tracking-wide text-slate-500">
          Per-region agreement ({COLS}×{ROWS})
        </p>
        <div
          className="grid gap-px overflow-hidden rounded border border-slate-800"
          style={{ gridTemplateColumns: `repeat(${COLS}, minmax(0, 1fr))` }}
          role="img"
          aria-label={`Per-region similarity heatmap, overall ${data.score}%`}
        >
          {data.matrix.flatMap((row, r) =>
            row.map((value, c) => (
              <span
                key={`${r}-${c}`}
                title={`Region row ${r + 1}, column ${c + 1}: ${Math.round(value * 100)}% agreement`}
                className="block h-5"
                style={{ backgroundColor: heatColor(value) }}
              />
            )),
          )}
        </div>
        <p className="mt-1 text-[9px] leading-snug text-slate-500">
          Each cell is the edge-map agreement (Dice overlap) of that region: green where the
          captured page and the reference share structure, red where one has layout the other does
          not. Two blank regions count as agreement.
        </p>
      </div>
    </div>
  );
}
