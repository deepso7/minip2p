import { afterEach, describe, expect, test, vi } from "vitest";

const originalPlatform = process.platform;
const originalGetReport = process.report.getReport;

afterEach(() => {
  Object.defineProperty(process, "platform", { value: originalPlatform });
  Object.defineProperty(process.report, "getReport", {
    value: originalGetReport,
  });
  vi.resetModules();
});

describe("@minip2p/node native loader", () => {
  test("reports the requested and supported targets at import time", async () => {
    Object.defineProperty(process, "platform", { value: "plan9" });

    const loading = import("../src/native.js");
    await expect(loading).rejects.toThrow(
      /Unsupported minip2p Node target plan9-x64.*linux-x64-gnu.*darwin-arm64.*win32-x64/su
    );
    await expect(loading).rejects.not.toThrow(/optional dependencies/u);
  });

  test("recognizes glibc from the compiler version", async () => {
    Object.defineProperty(process, "platform", { value: "linux" });
    Object.defineProperty(process.report, "getReport", {
      value: () => ({ header: { glibcVersionCompiler: "2.28" } }),
    });

    await expect(import("../src/native.js")).resolves.toHaveProperty(
      "nativeBinding"
    );
  });
});
