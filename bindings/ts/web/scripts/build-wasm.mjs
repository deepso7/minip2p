// Builds `crates/web` for wasm32 and generates its wasm-bindgen glue into
// `wasm/`: the `.js` and `.d.ts` glue is committed (it is what typecheck
// and the adapter import), the `.wasm` is a build output.
//
// Needs the `wasm32-unknown-unknown` target and the wasm-bindgen CLI at the
// version `crates/web` pins (`cargo install wasm-bindgen-cli --version …`).

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../../", import.meta.url));
const out = fileURLToPath(new URL("../wasm/", import.meta.url));
const run = (command, args) => {
  execFileSync(command, args, { cwd: root, stdio: "inherit" });
};

run("cargo", [
  "build",
  "--locked",
  "-p",
  "minip2p-web",
  "--target",
  "wasm32-unknown-unknown",
  "--profile",
  "wasm-release",
]);
// Cargo's target directory, honoring `CARGO_TARGET_DIR` and `build.target-dir`.
const { target_directory: targetDir } = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
    cwd: root,
    encoding: "utf-8",
  })
);
run("wasm-bindgen", [
  "--target",
  "web",
  "--out-dir",
  out,
  path.join(
    targetDir,
    "wasm32-unknown-unknown",
    "wasm-release",
    "minip2p_web.wasm"
  ),
]);
