import { defineConfig } from "oxlint";
import core from "ultracite/oxlint/core";
import react from "ultracite/oxlint/react";

export default defineConfig({
  extends: [core, react],
  ignorePatterns: [
    ...(core.ignorePatterns ?? []),
    "**/target",
    "target-linux",
    "tmp",
    "code-ref",
    ".repos",
    ".agents",
    ".claude",
    "docs/.blume",
    "docs/.blume-verify",
    "bindings/ts/react-native/lib",
    "examples/react-native/android",
    "examples/react-native/ios",
    "bindings/ts/react-native/src/NativeMinip2p.ts",
    "bindings/ts/react-native/src/native.tsx",
  ],
});
