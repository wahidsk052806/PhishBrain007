import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig(({ mode }) => ({
  build: {
    outDir: "dist",
    emptyOutDir: false,
    sourcemap: mode === "development",
    lib: {
      entry: resolve(__dirname, "src/background/service-worker.ts"),
      name: "PhishBrainBackground",
      formats: ["iife"],
      fileName: () => "background.js",
    },
    rollupOptions: {
      output: {
        extend: true,
      },
    },
  },
}));
