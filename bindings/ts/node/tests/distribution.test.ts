import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  assertNodePlatformManifest,
  nodePlatforms,
} from "../../scripts/node-platform-manifest.mjs";

const nodeManifest = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../package.json", import.meta.url)),
    "utf-8"
  )
) as Record<string, unknown>;
const coreManifest = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../core/package.json", import.meta.url)),
    "utf-8"
  )
) as Record<string, unknown>;

describe("@minip2p/node distribution", () => {
  test("links seven lockstep platform packages", () => {
    expect(nodeManifest.private).not.toBe(true);
    expect(nodeManifest.version).toBe(coreManifest.version);
    expect(nodeManifest.optionalDependencies).toEqual({
      "@minip2p/node-darwin-arm64": "workspace:*",
      "@minip2p/node-darwin-x64": "workspace:*",
      "@minip2p/node-linux-arm64-gnu": "workspace:*",
      "@minip2p/node-linux-arm64-musl": "workspace:*",
      "@minip2p/node-linux-x64-gnu": "workspace:*",
      "@minip2p/node-linux-x64-musl": "workspace:*",
      "@minip2p/node-win32-x64-msvc": "workspace:*",
    });
  });

  test("platform manifests declare only their target binary", () => {
    const targets = Object.keys(
      nodeManifest.optionalDependencies as Record<string, string>
    ).map((name) => name.slice("@minip2p/node-".length));

    for (const target of targets) {
      const manifest = JSON.parse(
        readFileSync(
          fileURLToPath(
            new URL(`../npm/${target}/package.json`, import.meta.url)
          ),
          "utf-8"
        )
      ) as Record<string, unknown>;
      expect(manifest.name).toBe(`@minip2p/node-${target}`);
      expect(manifest.version).toBe(nodeManifest.version);
      expect(manifest.files).toEqual([`minip2p.${target}.node`]);
      expect(manifest.main).toBe(`minip2p.${target}.node`);
      const platform = nodePlatforms.find(
        ({ target: expectedTarget }) => expectedTarget === target
      );
      expect(platform).toBeDefined();
      assertNodePlatformManifest(manifest, platform);
    }
  });
});
