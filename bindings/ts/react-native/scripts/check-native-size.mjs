/* oxlint-disable func-style -- The script uses a hoisted formatting helper below its main flow. */

import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const [platform] = process.argv.slice(2);
if (platform !== "android" && platform !== "ios") {
  throw new Error("usage: check-native-size.mjs <android|ios>");
}

const packageRoot = path.resolve(import.meta.dirname, "..");
const baseline = JSON.parse(
  readFileSync(path.join(packageRoot, "native-size-baseline.json"), "utf-8")
);
const artifacts =
  platform === "android"
    ? {
        "arm64-v8a": "android/src/main/jniLibs/arm64-v8a/libminip2p_ffi.so",
        x86_64: "android/src/main/jniLibs/x86_64/libminip2p_ffi.so",
      }
    : {
        "ios-arm64": "build/Minip2pFfi.xcframework/ios-arm64/libminip2p_ffi.a",
        "ios-arm64-simulator":
          "build/Minip2pFfi.xcframework/ios-arm64-simulator/libminip2p_ffi.a",
      };

for (const [name, relativePath] of Object.entries(artifacts)) {
  const bytes = statSync(path.join(packageRoot, relativePath)).size;
  const expected = baseline[platform][name];
  if (
    typeof expected !== "number" ||
    !Number.isFinite(expected) ||
    expected <= 0
  ) {
    throw new Error(
      `Invalid native size baseline for ${platform}/${name}: ${String(expected)}`
    );
  }
  if (bytes <= 0) {
    throw new Error(`Native artifact is empty: ${platform}/${name}`);
  }
  const change = ((bytes - expected) / expected) * 100;
  console.log(
    `${platform}/${name}: ${bytes} bytes (${formatChange(change)} vs baseline)`
  );
  if (change > 20) {
    const message = `${platform}/${name} grew ${change.toFixed(1)}% above its ${expected}-byte baseline`;
    if (process.env.NATIVE_SIZE_STRICT === "1") {
      throw new Error(message);
    }
    console.log(`::warning title=Native size regression::${message}`);
  }
}

function formatChange(change) {
  return `${change >= 0 ? "+" : ""}${change.toFixed(1)}%`;
}
