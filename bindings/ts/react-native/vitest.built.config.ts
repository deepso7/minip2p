import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/hooks-built.test.mjs"],
  },
});
