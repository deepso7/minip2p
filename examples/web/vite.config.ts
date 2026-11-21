import { defineConfig } from "vite";

export default defineConfig({
  build: { target: "es2022" },
  optimizeDeps: { exclude: ["@minip2p/web"] },
  resolve: { conditions: ["minip2p-source"] },
});
