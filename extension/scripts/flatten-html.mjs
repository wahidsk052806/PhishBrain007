import { readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";

const dist = join(import.meta.dirname, "..", "dist");
for (const [src, out] of [["src/popup/popup.html", "popup.html"], ["src/options/options.html", "options.html"]]) {
  const p = join(dist, src);
  if (!existsSync(p)) continue;
  const html = readFileSync(p, "utf8").replaceAll("../../assets/", "assets/").replaceAll("/assets/", "assets/");
  writeFileSync(join(dist, out), html);
}
rmSync(join(dist, "src"), { recursive: true, force: true });
console.log("flattened popup.html / options.html into dist/");
