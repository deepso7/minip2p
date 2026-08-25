import { fileURLToPath } from "node:url";

import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@minip2p/core/backend",
        replacement: fileURLToPath(
          new URL("core/src/backend.ts", import.meta.url)
        ),
      },
      {
        find: "@minip2p/core",
        replacement: fileURLToPath(
          new URL("core/src/index.ts", import.meta.url)
        ),
      },
    ],
  },
  test: {
    exclude: [...configDefaults.exclude, "**/hooks-built.test.mjs"],
  },
});
