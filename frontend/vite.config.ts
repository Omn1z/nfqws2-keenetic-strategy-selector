import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { viteSingleFile } from "vite-plugin-singlefile";

// The whole UI builds into ONE self-contained internal/server/web/index.html
// (JS + CSS inlined) which the Go binary embeds and serves gzipped.
export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  // Dev-only (`npm run dev`): proxy /api to a running backend. Point at the
  // router with N2S_DEV_API=http://<router>:8091. Ignored by the build.
  server: {
    host: true,
    proxy: { "/api": { target: process.env.N2S_DEV_API || "http://127.0.0.1:8091", changeOrigin: true } },
  },
  build: {
    outDir: "../internal/server/web",
    emptyOutDir: true,
    target: "es2020",
    minify: "esbuild",
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    chunkSizeWarningLimit: 4000,
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
});
