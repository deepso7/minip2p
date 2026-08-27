import { describe, expect, test } from "vitest";

import {
  assertNodePlatformManifest,
  nodePlatforms,
} from "../../scripts/node-platform-manifest.mjs";

describe("@minip2p/node platform selectors", () => {
  test("rejects the wrong Linux libc", () => {
    const platform = nodePlatforms.find(
      ({ target }) => target === "linux-x64-musl"
    );

    expect(() =>
      assertNodePlatformManifest(
        { cpu: ["x64"], libc: ["glibc"], os: ["linux"] },
        platform
      )
    ).toThrow("invalid libc metadata");
  });

  test("rejects libc metadata on platforms where npm does not use it", () => {
    const platform = nodePlatforms.find(
      ({ target }) => target === "darwin-arm64"
    );

    expect(() =>
      assertNodePlatformManifest(
        { cpu: ["arm64"], libc: ["musl"], os: ["darwin"] },
        platform
      )
    ).toThrow("invalid libc metadata");
  });
});
