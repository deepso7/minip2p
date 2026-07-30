import { defineConfig } from "oxfmt";
import ultracite from "ultracite/oxfmt";

export default defineConfig({
  ...ultracite,
  ignorePatterns: [
    ...(ultracite.ignorePatterns ?? []),
    "**/dist",
    "**/lib",
    "react-native/example/android",
    "react-native/example/ios",
    "react-native/src/NativeMinip2p.ts",
    "react-native/src/native.tsx",
  ],
});
