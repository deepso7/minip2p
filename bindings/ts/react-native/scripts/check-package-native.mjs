import { execFileSync } from "node:child_process";
import { statSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const packageRoot = path.resolve(import.meta.dirname, "..");
const requiredArtifacts = [
  "android/src/main/jniLibs/arm64-v8a/libminip2p_ffi.so",
  "android/src/main/jniLibs/x86_64/libminip2p_ffi.so",
  "build/Minip2pFfi.xcframework/ios-arm64/libminip2p_ffi.a",
  "build/Minip2pFfi.xcframework/ios-arm64-simulator/libminip2p_ffi.a",
];

for (const relativePath of requiredArtifacts) {
  const artifact = path.join(packageRoot, relativePath);
  let size;
  try {
    ({ size } = statSync(artifact));
  } catch {
    throw new Error(
      `Missing ${relativePath}; run pnpm ubrn:android and pnpm ubrn:ios before packaging`
    );
  }
  if (size === 0) {
    throw new Error(`Native package artifact is empty: ${relativePath}`);
  }
}

execFileSync(
  process.execPath,
  [path.join(import.meta.dirname, "check-android-elf.mjs")],
  {
    stdio: "inherit",
  }
);
