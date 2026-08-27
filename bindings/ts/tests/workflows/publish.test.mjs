import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

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

test("Android release pins the Gradle version required by generated AGP", () => {
  const gradleStep = workflow.jobs["android-native"].steps.find(
    ({ name }) => name === "Pin generated Gradle wrapper"
  );

  assert.match(gradleStep.run, /gradle-9\.4\.1-bin\.zip/u);
  assert.match(gradleStep.run, /gradle-wrapper\.properties/u);
});
