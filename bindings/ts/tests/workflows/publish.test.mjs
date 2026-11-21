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
const verifyScriptPath = new URL(
  "../../../../scripts/verify-release-versions.sh",
  import.meta.url
);
const publishNpmScriptPath = new URL(
  "../../../../scripts/publish-npm-packages.sh",
  import.meta.url
);
const setupAndroidPath = new URL(
  "../../../../.github/actions/setup-android/action.yml",
  import.meta.url
);
const setupNodePath = new URL(
  "../../../../.github/actions/setup-node/action.yml",
  import.meta.url
);

const workflow = parse(await readFile(workflowPath, "utf-8"));
const verifyScript = await readFile(verifyScriptPath, "utf-8");
const publishNpmScript = await readFile(publishNpmScriptPath, "utf-8");
const setupAndroid = parse(await readFile(setupAndroidPath, "utf-8"));
const setupNode = parse(await readFile(setupNodePath, "utf-8"));

test("release verification accepts workspace-linked Node platform packages", () => {
  const verifyStep = workflow.jobs["verify-release"].steps.find(
    ({ name }) => name === "Verify release tag and package versions"
  );

  assert.match(verifyStep.run, /scripts\/verify-release-versions\.sh/u);
  assert.match(verifyScript, /select\(\.value != "workspace:\*"\)/u);
});

test("generated-file validation ignores downloaded Node artifacts", () => {
  const generatedStep = workflow.jobs["package-typescript"].steps.find(
    ({ name }) => name === "Generated files are current"
  );

  assert.match(generatedStep.run, /git status --porcelain -- react-native/u);
});

test("release native setup is portable across Windows and Android", () => {
  const nativeSteps = workflow.jobs["node-native"].steps;
  const setupNodeStep = nativeSteps.find(
    ({ uses }) => uses === "./.github/actions/setup-node"
  );
  assert.equal(setupNodeStep.with["normalize-windows-patches"], "true");

  const install = setupNode.runs.steps.find(
    ({ run }) => run === "pnpm install --frozen-lockfile"
  );
  assert.equal(install.shell, "bash");

  const normalizePatches = setupNode.runs.steps.find(
    ({ name }) => name === "Normalize pnpm patches on Windows"
  );
  assert.match(normalizePatches.if, /runner\.os == 'Windows'/u);
  assert.equal(normalizePatches.shell, "bash");
  assert.match(normalizePatches.run, /react-native\/patches\/\*\.patch/u);

  assert.ok(
    workflow.jobs["android-native"].steps.some(
      ({ uses }) => uses === "./.github/actions/setup-android"
    )
  );
  assert.ok(
    workflow.jobs["android-apk"].steps.some(
      ({ uses }) => uses === "./.github/actions/setup-android"
    )
  );
  assert.ok(
    !workflow.jobs["package-typescript"].steps.some(
      ({ uses }) => uses === "./.github/actions/setup-android"
    )
  );
  const androidAction = setupAndroid.runs.steps.find(({ uses }) =>
    uses?.startsWith("android-actions/setup-android@")
  );
  assert.equal(androidAction.with.packages, "platform-tools");
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

test("nothing is published before the full Rust test matrix passes", () => {
  const needs = (jobName) => [workflow.jobs[jobName].needs ?? []].flat();
  const upstream = (jobName) =>
    needs(jobName).flatMap((need) => [need, ...upstream(need)]);

  const publishJobs = Object.keys(workflow.jobs).filter((jobName) =>
    jobName.startsWith("publish-")
  );
  assert.ok(publishJobs.length > 0);
  for (const jobName of publishJobs) {
    const deps = upstream(jobName);
    assert.ok(deps.includes("test-rust-workspace"), jobName);
    assert.ok(deps.includes("test-rust-matrix"), jobName);
  }

  const matrixJob = workflow.jobs["test-rust-matrix"];
  assert.deepEqual(matrixJob.strategy.matrix.shard, [1, 2, 3, 4]);
  const testRelease = matrixJob.steps.find(
    ({ name }) => name === "Test release feature-matrix shard"
  );
  assert.match(
    testRelease.run,
    /run-feature-matrix\.sh test full --shard "\$\{\{ matrix\.shard \}\}\/4"/u
  );
});

test("the web SDK's wasm is built, packed, verified, smoke-tested and published", () => {
  const { steps } = workflow.jobs["package-typescript"];
  assert.ok(
    steps.some(({ run }) => run === "pnpm --filter @minip2p/web wasm:build")
  );
  const step = (name) => steps.find((candidate) => candidate.name === name);
  assert.match(step("Pack public packages").run, /@minip2p\/web pack/u);
  for (const name of [
    "Verify packed contents and dependency versions",
    "Smoke-test installation from tarballs",
  ]) {
    assert.match(step(name).run, /minip2p-web-\$RELEASE_VERSION\.tgz/u);
  }
  const publish = workflow.jobs["publish-typescript"].steps.find(
    ({ name }) => name === "Publish public TypeScript packages"
  );
  assert.match(publish.run, /scripts\/publish-npm-packages\.sh/u);
  assert.match(publishNpmScript, /"@minip2p\/web"/u);
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
