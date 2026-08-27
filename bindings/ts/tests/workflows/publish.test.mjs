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
