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
        { os: ["linux"], cpu: ["x64"], libc: ["glibc"] },
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
        { os: ["darwin"], cpu: ["arm64"], libc: ["musl"] },
        platform
      )
    ).toThrow("invalid libc metadata");
  });
});
