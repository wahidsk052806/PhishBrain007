import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig(({ mode }) => ({
  // Same reason as the content bundle: library mode leaves
  // `process.env.NODE_ENV` in the output and the worker has no `process`.
  define: {
    "process.env.NODE_ENV": JSON.stringify(mode === "development" ? "development" : "production"),
  },
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
