/* oxlint-disable func-style -- Use named function declarations for script helpers. */

import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

import {
  customizeGenerated,
  normalizeGenerated,
} from "./normalize-generated.mjs";

const packageRoot = path.resolve(import.meta.dirname, "..");
const workspaceRoot = path.resolve(packageRoot, "../../..");
const cli = path.join(
  workspaceRoot,
  "node_modules",
  "@react-native-community",
  "cli",
  "build",
  "bin.js"
);

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    stdio: "inherit",
  });
  if (result.error !== undefined) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

// Codegen reads the customized spec, so the mDNS hooks land first.
customizeGenerated();
run(process.execPath, [cli, "codegen", "--source", "library"], packageRoot);

const generatedJavaRoot = path.join(packageRoot, "android/generated/java");
const generatedJava = path.join(
  generatedJavaRoot,
  "com/facebook/fbreact/specs/NativeMinip2pSpec.java"
);
const packageJavaRoot = path.join(generatedJavaRoot, "com/minip2p");
const packageJava = path.join(packageJavaRoot, "NativeMinip2pSpec.java");
const source = readFileSync(generatedJava, "utf-8").replace(
  "package com.facebook.fbreact.specs;",
  "package com.minip2p;"
);

mkdirSync(packageJavaRoot, { recursive: true });
writeFileSync(generatedJava, source);
rmSync(packageJava, { force: true });
renameSync(generatedJava, packageJava);
rmSync(path.join(generatedJavaRoot, "com/facebook"), {
  force: true,
  recursive: true,
});
normalizeGenerated();
