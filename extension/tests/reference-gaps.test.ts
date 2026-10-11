/**
 * Documented brand-capture gaps.
 *
 * Some brands refuse a headless browser outright. The failure is recorded as a
 * documented, testable gap rather than a silent absence, and this test keeps
 * the two sides honest:
 *
 *   - a documented gap that is ALSO shipped as a reference means the file is
 *     wrong (either the entry should be dropped, or — the bug this guards — a
 *     stale capture from a rejected run was left in place),
 *   - a gap entry must carry a real reason and a mitigation.
 *
 * It is deliberately a consistency check rather than a hard "Adobe always
 * fails": if someone later captures Adobe for real, removing the gap entry
 * makes the test pass again, which is the desired direction of travel.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

interface GapEntry {
  status?: string;
  reason?: string;
  mitigation?: string;
  first_observed?: string;
  documented_at?: string;
  user_impact?: string;
}

function readJson<T>(relative: string): T {
  const url = new URL(relative, import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), "utf8")) as T;
}

const gaps = readJson<Record<string, GapEntry>>("../data/known_reference_gaps.json");
const hashes = readJson<Record<string, string>>("../data/reference_hashes.json");
const thumbnails = readJson<Record<string, string>>("../data/reference_thumbnails.json");

describe("known reference gaps", () => {
  it("documents Adobe's persistent bot-wall failure", () => {
    const adobe = gaps.adobe;

    expect(adobe, "adobe must be documented as a known capture gap").toBeTruthy();
    expect(adobe.reason ?? "").toMatch(/bot|wall|interstitial|blank/i);
    expect((adobe.mitigation ?? "").length).toBeGreaterThan(20);
    expect(adobe.documented_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("never ships a reference for a documented gap", () => {
    const shipped = Object.keys(gaps).filter((brand) => brand in hashes);
    expect(
      shipped,
      "these brands are documented as capture gaps yet a reference is shipped — " +
        "the reference is stale or the gap entry is obsolete",
    ).toEqual([]);
  });

  it("never ships a thumbnail for a documented gap", () => {
    const shipped = Object.keys(gaps).filter((brand) => brand in thumbnails);
    expect(shipped).toEqual([]);
  });

  it("gives every gap entry a reason, a status and a mitigation", () => {
    for (const [brand, entry] of Object.entries(gaps)) {
      expect(entry.reason, `${brand} needs a reason`).toBeTruthy();
      expect(entry.mitigation, `${brand} needs a mitigation`).toBeTruthy();
      expect(["degenerate", "failed", "blocked"], `${brand} needs a recognised status`).toContain(
        entry.status,
      );
    }
  });

  it("keeps every shipped reference a plausible 64-bit hex pHash", () => {
    for (const [brand, hash] of Object.entries(hashes)) {
      expect(hash, `${brand} reference must be a 16-char hex pHash`).toMatch(/^[0-9a-f]{16}$/);
    }
  });
});
