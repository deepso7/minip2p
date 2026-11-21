import { defineConfig, devices } from "@playwright/test";

const PORT = 4317;

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
  workers: 1,
});
