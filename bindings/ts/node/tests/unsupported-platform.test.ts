import { afterEach, describe, expect, test } from "vitest";

const originalPlatform = process.platform;

afterEach(() => {
  Object.defineProperty(process, "platform", { value: originalPlatform });
});

describe("@minip2p/node native loader", () => {
  test("reports the requested and supported targets at import time", async () => {
    Object.defineProperty(process, "platform", { value: "plan9" });

    await expect(import("../src/native.js")).rejects.toThrow(
      /Unsupported minip2p Node target plan9-x64.*linux-x64-gnu.*darwin-arm64.*win32-x64/s
    );
  });
});
