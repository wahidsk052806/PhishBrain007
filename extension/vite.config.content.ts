import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";
import { copyFileSync, mkdirSync, existsSync, readdirSync, rmSync } from "fs";

function copyStaticAssets() {
  return {
    name: "copy-static-assets",
    closeBundle() {
      const distDir = resolve(__dirname, "dist");
      mkdirSync(distDir, { recursive: true });
      copyFileSync(resolve(__dirname, "manifest.json"), resolve(distDir, "manifest.json"));
      copyFileSync(
        resolve(__dirname, "manifest.firefox.json"),
        resolve(distDir, "manifest.firefox.json"),
      );
      const iconsDir = resolve(__dirname, "icons");
      const distIconsDir = resolve(distDir, "icons");
      mkdirSync(distIconsDir, { recursive: true });
      if (existsSync(iconsDir)) {
        for (const file of readdirSync(iconsDir)) {
          copyFileSync(resolve(iconsDir, file), resolve(distIconsDir, file));
        }
      }
      // Bundle this extension's OWN layout reference hashes. They must come
      // from extension/data/reference_hashes.json (written by
      // scripts/data/generate_reference_hashes.ts, i.e. the JS pHash engine) —
      // the backend's data/reference_hashes.json is hashed with Python's
      // `imagehash` and is NOT bit-comparable with hashes produced here.
      // Absent -> the visual layer relies on the runtime brand-icon
      // references (./src/background/brand-refs.ts) plus learned refs.
      const refsFile = resolve(__dirname, "data/reference_hashes.json");
      if (existsSync(refsFile)) {
        copyFileSync(refsFile, resolve(distDir, "reference_hashes.json"));
      } else {
        // Never ship a stale copy of the other engine's file.
        const distRefs = resolve(distDir, "reference_hashes.json");
        if (existsSync(distRefs)) rmSync(distRefs);
      }
      // Optional preview images for the matched brand, so the popup can show a
      // captured-vs-reference side-by-side. Written by the same generator.
      const thumbsFile = resolve(__dirname, "data/reference_thumbnails.json");
      if (existsSync(thumbsFile)) {
        copyFileSync(thumbsFile, resolve(distDir, "reference_thumbnails.json"));
      }
    },
  };
}

export default defineConfig(({ mode }) => ({
  plugins: [react(), tailwindcss(), copyStaticAssets()],
  // Vite deliberately leaves `process.env.NODE_ENV` in place for library
  // builds, but this bundle runs in a page where `process` does not exist:
  // React's module header evaluates `process.env.NODE_ENV` immediately, so the
  // shipped content script died with "process is not defined" before it ever
  // registered a listener — no email was parsed and no page was analysed.
  define: {
    "process.env.NODE_ENV": JSON.stringify(mode === "development" ? "development" : "production"),
  },
  build: {
    outDir: "dist",
    emptyOutDir: false,
    sourcemap: mode === "development",
    cssCodeSplit: false,
    lib: {
      entry: resolve(__dirname, "src/content/content-script.ts"),
      name: "PhishBrainContent",
      formats: ["iife"],
      fileName: () => "content.js",
    },
    rollupOptions: {
      output: {
        extend: true,
        assetFileNames: "assets/[name].[ext]",
      },
    },
  },
}));
