import { defineConfig, devices } from "@playwright/test";

const PORT = 4317;

// Browser e2e: `@minip2p/web` in Chromium and Firefox against native nodes
// on `localhost`. Needs `pnpm build:bindings` and the Node addon
// (`pnpm --filter @minip2p/node native:build`) first.
export default defineConfig({
  forbidOnly: process.env.CI !== undefined,
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
  ],
  reporter: process.env.CI === undefined ? "list" : [["list"], ["github"]],
  testDir: "e2e",
  timeout: 60_000,
  use: { baseURL: `http://localhost:${PORT}` },
  webServer: {
    command: `node e2e/server.mjs ${PORT}`,
    reuseExistingServer: process.env.CI === undefined,
    url: `http://localhost:${PORT}/`,
  },
  // The native peers bind real sockets; keep one browser at a time.
  workers: 1,
});
