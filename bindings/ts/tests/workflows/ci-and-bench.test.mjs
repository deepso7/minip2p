import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

const repoRoot = fileURLToPath(new URL("../../../../", import.meta.url));

const yamlFiles = async (dir) => {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        return yamlFiles(full);
      }
      if (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml")) {
        return [full];
      }
      return [];
    })
  );
  return nested.flat();
};

test("all third-party GitHub Actions are pinned to 40-character commit SHAs", async () => {
  const groups = await Promise.all([
    yamlFiles(path.join(repoRoot, ".github/workflows")),
    yamlFiles(path.join(repoRoot, ".github/actions")),
  ]);
  const files = groups.flat();
  assert.ok(files.length > 0);

  const docs = await Promise.all(
    files.map(async (file) => ({
      doc: parse(await readFile(file, "utf-8")),
      file,
    }))
  );

  for (const { doc, file } of docs) {
    const stepLists = [
      ...(doc.runs?.steps ? [doc.runs.steps] : []),
      ...Object.values(doc.jobs ?? {}).map((job) => job.steps ?? []),
    ];
    for (const steps of stepLists) {
      for (const step of steps) {
        if (typeof step.uses !== "string" || step.uses.startsWith("./")) {
          continue;
        }
        assert.match(
          step.uses,
          /@[0-9a-f]{40}$/u,
          `${path.relative(repoRoot, file)}: ${step.uses}`
        );
      }
    }
  }
});

test("CI gate job covers every verification job in ci.yml", async () => {
  const ci = parse(
    await readFile(path.join(repoRoot, ".github/workflows/ci.yml"), "utf-8")
  );
  const workerJobs = Object.keys(ci.jobs).filter(
    (name) => name !== "ci" && name !== "prune-caches"
  );
  assert.deepEqual([...ci.jobs.ci.needs].toSorted(), workerJobs.toSorted());
});

test("Bench workflow keeps self-hosted bench job read-only and comments on ubuntu-latest", async () => {
  const bench = parse(
    await readFile(path.join(repoRoot, ".github/workflows/bench.yml"), "utf-8")
  );
  assert.deepEqual(bench.jobs.bench.permissions, { contents: "read" });
  assert.equal(bench.jobs.comment["runs-on"], "ubuntu-latest");
  assert.equal(bench.jobs.comment.permissions["pull-requests"], "write");
  assert.deepEqual(bench.jobs.comment.needs, ["start-runner", "bench"]);
});
