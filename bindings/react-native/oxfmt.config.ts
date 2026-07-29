import { defineConfig } from "oxfmt";
import ultracite from "ultracite/oxfmt";

export default defineConfig({
  ...ultracite,
  ignorePatterns: [
    ...(ultracite.ignorePatterns ?? []),
    "lib",
    "example/android",
    "example/ios",
    "src/NativeMinip2p.ts",
    "src/native.tsx",
  ],
});
