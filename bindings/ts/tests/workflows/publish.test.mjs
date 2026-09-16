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

test("release native setup is portable across Windows and Android", () => {
  const nativeSteps = workflow.jobs["node-native"].steps;
  const install = workflow.jobs["node-native"].steps.find(
    ({ run }) => run === "pnpm --workspace-root install --frozen-lockfile"
  );
  assert.equal(install.shell, "bash");

  const normalizePatches = nativeSteps.find(
    ({ name }) => name === "Normalize pnpm patches on Windows"
  );
  assert.equal(normalizePatches.if, "runner.os == 'Windows'");
  assert.equal(normalizePatches.shell, "bash");
  assert.match(normalizePatches.run, /react-native\/patches\/\*\.patch/u);

  const androidSetups = Object.values(workflow.jobs).flatMap(({ steps = [] }) =>
    steps.filter(({ uses }) =>
      uses?.startsWith("android-actions/setup-android@")
    )
  );
  assert.ok(androidSetups.length > 0);
  for (const setupAndroid of androidSetups) {
    assert.equal(setupAndroid.with.packages, "platform-tools");
  }
});

test("a failed tagged release can be resumed without moving its tag", () => {
  const releaseTag = workflow.on.workflow_dispatch.inputs.release_tag;
  assert.equal(releaseTag.required, false);
  assert.equal(releaseTag.type, "string");

  const publishJobs = [
    "publish-relay-server-binaries",
    "publish-relay-container",
    "publish-crates",
    "publish-node-platforms",
    "publish-typescript",
  ];
  for (const jobName of publishJobs) {
    assert.match(workflow.jobs[jobName].if, /inputs\.release_tag != ''/u);
  }

  const checkout = workflow.jobs["verify-release"].steps.find(({ uses }) =>
    uses?.startsWith("actions/checkout@")
  );
  assert.match(checkout.with.ref, /inputs\.release_tag/u);
});

test("Node platform packages carry npm provenance repository metadata", async () => {
  await Promise.all(
    nodePlatforms.map(async (platform) => {
      const manifestUrl = new URL(
        `../../node-platforms/${platform.target}/package.json`,
        import.meta.url
      );
      const manifest = JSON.parse(await readFile(manifestUrl, "utf-8"));

      assert.doesNotThrow(() => assertNodePlatformManifest(manifest, platform));
    })
  );
});
