import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { routerSingleFile } from "./scripts/inline-bundle.mjs";
import { compactBundle, compactChunkName } from "./scripts/compact-bundle.mjs";

// Full installs embed a single HTML file. Compact installs load page packages on demand.
export default defineConfig(({ mode }) => {
  const compact = mode === "compact";
  return {
    plugins: [react(), tailwindcss(), compact ? compactBundle() : routerSingleFile()],
    base: compact ? "/" : "./",
    resolve: {
      alias: {
        ...(compact ? { "@/config/optionalPages": fileURLToPath(new URL("./src/config/compactPages.tsx", import.meta.url)) } : {}),
        "@": fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
    // Dev-only (`npm run dev`): proxy /api to a running backend. Point at the
    // router with N2S_DEV_API=http://<router>:8091. Ignored by the build.
    server: {
      host: true,
      proxy: { "/api": { target: process.env.N2S_DEV_API || "http://127.0.0.1:8091", changeOrigin: true } },
    },
    build: {
      outDir: compact ? "../dist/compact-ui/raw" : "../internal/server/web",
      emptyOutDir: true,
      target: "es2020",
      minify: "esbuild",
      cssCodeSplit: false,
      assetsInlineLimit: 100_000_000,
      assetsDir: "",
      chunkSizeWarningLimit: 4000,
      rollupOptions: { output: compact ? {
        entryFileNames: "ui/[name]-[hash].js",
        chunkFileNames: compactChunkName,
        assetFileNames: "ui/[name]-[hash][extname]",
      } : { inlineDynamicImports: true } },
    },
  };
});
