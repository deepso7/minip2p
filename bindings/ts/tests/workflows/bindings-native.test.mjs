import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

const workflowPath = new URL(
  "../../../../.github/workflows/bindings-native.yml",
  import.meta.url
);
const workflow = parse(await readFile(workflowPath, "utf-8"));

test("native workflow runs weekly and on manual dispatch", () => {
  assert.ok(workflow.on.workflow_dispatch !== undefined);
  assert.equal(workflow.on.schedule[0].cron, "17 4 * * 1");
});

test("weekly workflow builds all seven Node targets", () => {
  const targets = [
    ...workflow.jobs["node-native"].strategy.matrix.include,
    ...workflow.jobs["node-musl"].strategy.matrix.include,
  ].map(({ target }) => target);

  assert.deepEqual(targets.toSorted(), [
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
  ]);
});

test("weekly workflow executes the suite on native runners and musl containers", () => {
  const nativeJob = workflow.jobs["node-native"];
  const runners = Object.fromEntries(
    nativeJob.strategy.matrix.include.map(({ runner, target }) => [
      target,
      runner,
    ])
  );
  assert.deepEqual(runners, {
    "aarch64-apple-darwin": "macos-26",
    "aarch64-unknown-linux-gnu": "ubuntu-24.04-arm",
    "x86_64-apple-darwin": "macos-26-intel",
    "x86_64-pc-windows-msvc": "windows-latest",
    "x86_64-unknown-linux-gnu": "ubuntu-24.04",
  });
  assert.ok(nativeJob.steps.some(({ run }) => run === "pnpm test"));

  const muslBuild = workflow.jobs["node-musl"].steps.find(
    ({ name }) => name === "Build addon"
  ).run;
  assert.ok(
    workflow.jobs["node-musl"].steps.some(
      ({ name }) => name === "Build musl relay fixture"
    )
  );
  assert.match(muslBuild, /PATH=\/opt\/pnpm\/bin:\/usr\/bin:/u);
  assert.match(muslBuild, /--prefix \/opt\/pnpm pnpm@11\.24\.0/u);
  assert.match(muslBuild, /pnpm --filter @minip2p\/node exec vitest run/u);
});
