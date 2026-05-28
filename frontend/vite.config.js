import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// Build the whole UI into ONE self-contained internal/server/web/index.html
// (JS + CSS inlined) so the Go binary embeds a single minimal asset.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  // Dev-only (`npm run dev`): proxy /api to a running backend. Point it at your
  // router's dev instance with N2S_DEV_API=http://<router>:8091. Ignored by build.
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
    assetsInlineLimit: 100000000,
    chunkSizeWarningLimit: 4000,
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
});
