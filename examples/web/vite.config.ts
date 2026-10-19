import { defineConfig } from "vite";

export default defineConfig({
  // `@minip2p/web` initialises its wasm with top-level `await`.
  build: { target: "es2022" },
  // Pre-bundling would move the package away from its `.wasm`, which it
  // finds through `new URL(…, import.meta.url)`.
  optimizeDeps: { exclude: ["@minip2p/web"] },
  // Read the workspace packages from source, so only the `.wasm` needs a
  // build (`pnpm --filter @minip2p/web wasm:build`).
  resolve: { conditions: ["minip2p-source"] },
});
