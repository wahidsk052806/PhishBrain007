import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";
import { copyFileSync, mkdirSync, existsSync, readdirSync } from "fs";

function copyStaticAssets() {
  return {
    name: "copy-static-assets",
    closeBundle() {
      const distDir = resolve(__dirname, "dist");
      mkdirSync(distDir, { recursive: true });
      copyFileSync(resolve(__dirname, "manifest.json"), resolve(distDir, "manifest.json"));
      copyFileSync(resolve(__dirname, "manifest.firefox.json"), resolve(distDir, "manifest.firefox.json"));
      const iconsDir = resolve(__dirname, "icons");
      const distIconsDir = resolve(distDir, "icons");
      mkdirSync(distIconsDir, { recursive: true });
      if (existsSync(iconsDir)) {
        for (const file of readdirSync(iconsDir)) {
          copyFileSync(resolve(iconsDir, file), resolve(distIconsDir, file));
        }
      }
      // Bundle the visual-clone reference hashes (data/reference_hashes.json,
      // same format as the backend's visual.py consumes) so the opt-in
      // screenshot analysis works with zero backend. Absent -> visual layer
      // reports "no reference hashes" until the user learns some.
      const refsFile = resolve(__dirname, "../data/reference_hashes.json");
      if (existsSync(refsFile)) {
        copyFileSync(refsFile, resolve(distDir, "reference_hashes.json"));
      }
    },
  };
}

export default defineConfig(({ mode }) => ({
  plugins: [react(), tailwindcss(), copyStaticAssets()],
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
