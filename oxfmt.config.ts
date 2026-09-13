import { defineConfig } from "oxfmt";
import ultracite from "ultracite/oxfmt";

export default defineConfig({
  ...ultracite,
  ignorePatterns: [
    ...(ultracite.ignorePatterns ?? []),
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
