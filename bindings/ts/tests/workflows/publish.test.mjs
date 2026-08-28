import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

import {
  assertNodePlatformManifest,
  nodePlatforms,
} from "../../scripts/node-platform-manifest.mjs";

const workflowPath = new URL(
  "../../../../.github/workflows/publish.yml",
  import.meta.url
);
const workflow = parse(await readFile(workflowPath, "utf-8"));

test("release verification accepts workspace-linked Node platform packages", () => {
  const verifyStep = workflow.jobs["verify-release"].steps.find(
    ({ name }) => name === "Verify release tag and package versions"
  );

  assert.match(verifyStep.run, /select\(\.value != "workspace:\*"\)/u);
});

test("generated-file validation ignores downloaded Node artifacts", () => {
  const generatedStep = workflow.jobs["package-typescript"].steps.find(
    ({ name }) => name === "Generated files are current"
  );

  assert.match(generatedStep.run, /git status --porcelain -- react-native/u);
});

test("Node platform packages carry npm provenance repository metadata", async () => {
  await Promise.all(
    nodePlatforms.map(async (platform) => {
      const manifestUrl = new URL(
        `../../node/npm/${platform.target}/package.json`,
        import.meta.url
      );
      const manifest = JSON.parse(await readFile(manifestUrl, "utf-8"));

      assert.doesNotThrow(() => assertNodePlatformManifest(manifest, platform));
    })
  );
});
