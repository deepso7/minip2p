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
const { target_directory: targetDir } = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
    cwd: root,
    encoding: "utf-8",
  })
);
const keepNames = process.env.MINIP2P_WASM_NAMES === "1";
run("wasm-bindgen", [
  "--target",
  "web",
  ...(keepNames ? [] : ["--remove-name-section", "--remove-producers-section"]),
  "--out-dir",
  out,
  path.join(
    targetDir,
    "wasm32-unknown-unknown",
    "wasm-release",
    "minip2p_web.wasm"
  ),
]);
