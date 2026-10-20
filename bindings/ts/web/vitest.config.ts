import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

const core = (path: string): string =>
  fileURLToPath(new URL(`../core/src/${path}`, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: "@minip2p/core/backend", replacement: core("backend.ts") },
      {
        find: "@minip2p/core/serde-backend",
        replacement: core("serde-backend.ts"),
      },
      { find: "@minip2p/core", replacement: core("index.ts") },
    ],
  },
  test: {
    // Playwright owns the browser suite.
    exclude: ["e2e/**", "node_modules/**"],
  },
});
