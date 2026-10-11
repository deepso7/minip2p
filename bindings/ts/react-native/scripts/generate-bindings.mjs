/* oxlint-disable func-style -- Use named function declarations for script helpers. */

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const packageRoot = path.resolve(import.meta.dirname, "..");
const workspaceRoot = path.resolve(packageRoot, "../../..");
const rustRoot = path.resolve(packageRoot, "../../..");
const libraryExtension =
  {
    darwin: "dylib",
    win32: "dll",
  }[process.platform] ?? "so";
const library = path.join(
  rustRoot,
  "target",
  "debug",
  `libminip2p_ffi.${libraryExtension}`
);
const ubrn = path.join(
  workspaceRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "ubrn.cmd" : "ubrn"
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

run(
  "cargo",
  ["build", "--manifest-path", path.join(rustRoot, "crates/ffi/Cargo.toml")],
  rustRoot
);
run(
  ubrn,
  [
    "generate",
    "jsi",
    "bindings",
    "--library",
    "--no-format",
    "--crate",
    "minip2p_ffi",
    "--ts-dir",
    path.join(packageRoot, "src/generated"),
    "--cpp-dir",
    path.join(packageRoot, "cpp/generated"),
    library,
  ],
  rustRoot
);
run(
  ubrn,
  [
    "generate",
    "jsi",
    "turbo-module",
    "--config",
    "ubrn.config.yaml",
    "minip2p_ffi_core",
    "minip2p_ffi",
  ],
  packageRoot
);
run(
  process.execPath,
  [path.join(packageRoot, "scripts/generate-codegen.mjs")],
  packageRoot
);
