import { afterEach, describe, expect, test, vi } from "vitest";

const originalPlatform = process.platform;
const originalGetReport = process.report.getReport;

afterEach(() => {
  Object.defineProperty(process, "platform", { value: originalPlatform });
  Object.defineProperty(process.report, "getReport", {
    value: originalGetReport,
  });
  vi.resetModules();
  vi.doUnmock("node:module");
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

  test("preserves the loader error for a present but broken local addon", async () => {
    vi.doMock("node:module", () => ({
      createRequire: () => (specifier: string) => {
        if (specifier.startsWith("../minip2p.")) {
          throw Object.assign(new Error("local addon is corrupt"), {
            code: "ERR_DLOPEN_FAILED",
          });
        }
        throw new Error(`unexpected package fallback: ${specifier}`);
      },
    }));

    await expect(import("../src/native.js")).rejects.toThrow(
      "local addon is corrupt"
    );
  });
});
