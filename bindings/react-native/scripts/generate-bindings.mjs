/* oxlint-disable func-style -- The script keeps its hoisted process runner below the generation steps. */

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const packageRoot = path.resolve(import.meta.dirname, "..");
const rustRoot = path.resolve(packageRoot, "../..");
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
  packageRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "ubrn.cmd" : "ubrn"
);
const environment = { ...process.env };
delete environment.LIBCLANG_PATH;

run(
  "cargo",
  ["build", "--manifest-path", path.join(rustRoot, "crates/ffi/Cargo.toml")],
  rustRoot,
  environment
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
  rustRoot,
  environment
);
run(
  ubrn,
  [
    "generate",
    "jsi",
    "turbo-module",
    "--config",
    "ubrn.config.yaml",
    "minip2p_ffi",
  ],
  packageRoot,
  environment
);
run(
  process.execPath,
  [path.join(packageRoot, "scripts/normalize-generated.mjs")],
  packageRoot,
  environment
);

function run(command, args, cwd, env) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    stdio: "inherit",
  });
  if (result.error !== undefined) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
