import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
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

test("publish package-typescript matches ci ts-bindings rust-cache env and step order", async () => {
  const [ci, publish] = await Promise.all([
    readFile(path.join(repoRoot, ".github/workflows/ci.yml"), "utf-8").then(
      parse
    ),
    readFile(
      path.join(repoRoot, ".github/workflows/publish.yml"),
      "utf-8"
    ).then(parse),
  ]);
  assert.equal(
    publish.jobs["package-typescript"].env.CARGO_PROFILE_DEV_DEBUG,
    ci.env.CARGO_PROFILE_DEV_DEBUG
  );
  for (const steps of [
    ci.jobs["ts-bindings"].steps,
    publish.jobs["package-typescript"].steps,
  ]) {
    const nodeIdx = steps.findIndex(
      ({ uses }) => uses === "./.github/actions/setup-node"
    );
    const rustIdx = steps.findIndex(
      ({ uses }) => uses === "./.github/actions/setup-rust"
    );
    assert.ok(nodeIdx !== -1 && rustIdx !== -1 && nodeIdx < rustIdx);
  }
});

const OLD_HEAD = "a".repeat(40);
const NEW_HEAD = "b".repeat(40);
const comparisonFor = (sha) =>
  `<!-- bench-comment -->\n## Benchmark comparison\n\n- Head: \`${sha.slice(0, 12)}\`\n`;

const FAKE_GH = `#!/usr/bin/env bash
set -euo pipefail
case "$2" in
  --method) printf '%s\\n' "$3" > "$FAKE_DIR/method"; cp "\${6#body=@}" "$FAKE_DIR/posted.md" ;;
  */pulls/*) printf '%s\\n' "$FAKE_HEAD_SHA" ;;
  */comments) cat "$FAKE_DIR/comments.json" ;;
esac
`;

const runCommentStep = async ({
  benchResult,
  comments,
  existingBody,
  headSha,
}) => {
  const bench = parse(
    await readFile(path.join(repoRoot, ".github/workflows/bench.yml"), "utf-8")
  );
  const step = bench.jobs.comment.steps.find(
    ({ name }) => name === "Upsert sticky comment"
  );
  const dir = await mkdtemp(path.join(tmpdir(), "bench-comment-"));
  try {
    await writeFile(path.join(dir, "gh"), FAKE_GH);
    await chmod(path.join(dir, "gh"), 0o755);
    const existingComments =
      comments ??
      (existingBody === undefined
        ? []
        : [
            {
              body: existingBody,
              id: 7,
              user: { login: "github-actions[bot]" },
            },
          ]);
    await writeFile(
      path.join(dir, "comments.json"),
      JSON.stringify(existingComments)
    );
    await writeFile(path.join(dir, "comparison.md"), comparisonFor(OLD_HEAD));
    execFileSync("bash", ["-c", step.run], {
      env: {
        ...process.env,
        ARTIFACT_DIR: dir,
        BENCH_RESULT: benchResult,
        EXPECTED_HEAD_SHA: OLD_HEAD,
        FAKE_DIR: dir,
        FAKE_HEAD_SHA: headSha,
        GITHUB_REPOSITORY: "owner/repo",
        PATH: `${dir}:${process.env.PATH}`,
        PR_NUMBER: "1",
        RUN_URL: "https://example.test/run",
        START_RESULT: "success",
        TARGET: path.join(dir, "target.md"),
      },
      stdio: ["ignore", "ignore", "ignore"],
    });
    if (!existsSync(path.join(dir, "method"))) {
      return;
    }
    const method = await readFile(path.join(dir, "method"), "utf-8");
    return {
      body: await readFile(path.join(dir, "posted.md"), "utf-8"),
      method: method.trim(),
    };
  } finally {
    await rm(dir, { force: true, recursive: true });
  }
};

test("Bench comment posts the comparison when the PR head did not move", async () => {
  const posted = await runCommentStep({
    benchResult: "success",
    headSha: OLD_HEAD,
  });
  assert.deepEqual(posted, {
    body: comparisonFor(OLD_HEAD),
    method: "POST",
  });
});

test("Bench comment warns when the PR head moved during the run", async () => {
  const posted = await runCommentStep({
    benchResult: "failure",
    existingBody: comparisonFor("c".repeat(40)),
    headSha: NEW_HEAD,
  });
  assert.equal(posted?.method, "PATCH");
  assert.match(
    posted.body,
    /^<!-- bench-comment -->\n<!-- bench-status-start -->\n> \[!WARNING\]\n/u
  );
  assert.match(posted.body, /`aaaaaaaaaaaa` \(\[failure\]/u);
  assert.match(posted.body, /moved to `bbbbbbbbbbbb`/u);
  assert.match(posted.body, /- Head: `cccccccccccc`/u);
});

test("Bench comment keeps a stale run's comparison below its warning", async () => {
  const posted = await runCommentStep({
    benchResult: "success",
    headSha: NEW_HEAD,
  });
  assert.equal(posted?.body.match(/<!-- bench-comment -->/gu)?.length, 1);
  assert.match(posted.body, /comparison below is from that run/u);
  assert.match(posted.body, /- Head: `aaaaaaaaaaaa`/u);
});

test("Bench comment never replaces a comparison of the current head", async () => {
  const posted = await runCommentStep({
    benchResult: "success",
    existingBody: comparisonFor(NEW_HEAD),
    headSha: NEW_HEAD,
  });
  assert.equal(posted, undefined);
});

test("Bench comment ignores non-bot comments containing the marker", async () => {
  const posted = await runCommentStep({
    benchResult: "failure",
    comments: [
      {
        body: comparisonFor(NEW_HEAD),
        id: 99,
        user: { login: "someone-else" },
      },
    ],
    headSha: NEW_HEAD,
  });
  assert.equal(posted?.method, "POST");
  assert.match(posted.body, /moved to `bbbbbbbbbbbb`/u);
});
