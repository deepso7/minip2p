/* oxlint-disable func-style -- The script keeps its hoisted command runner below the checks. */

import { execFileSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const ndk = process.env.ANDROID_NDK_HOME;
if (ndk === undefined) {
  throw new Error("ANDROID_NDK_HOME is required");
}

const readelf = path.join(
  ndk,
  "toolchains",
  "llvm",
  "prebuilt",
  process.platform === "darwin" ? "darwin-x86_64" : "linux-x86_64",
  "bin",
  "llvm-readelf"
);
const libraries = ["arm64-v8a", "x86_64"].map((abi) => ({
  abi,
  path: path.join(
    "android",
    "src",
    "main",
    "jniLibs",
    abi,
    "libminip2p_ffi.so"
  ),
}));

for (const library of libraries) {
  const programHeaders = run(readelf, ["-lW", library.path]);
  const alignments = programHeaders
    .split("\n")
    .filter((line) => line.trimStart().startsWith("LOAD "))
    .map((line) => line.trim().split(/\s+/u).at(-1));
  if (
    alignments.length === 0 ||
    alignments.some(
      (alignment) => alignment !== "0x4000" && alignment !== "0x10000"
    )
  ) {
    throw new Error(
      `${library.abi} has incompatible LOAD alignments: ${alignments.join(", ")}`
    );
  }

  const symbols = run(readelf, ["-sW", library.path])
    .split("\n")
    .filter((line) =>
      /OPENSSL_memory_(?:alloc|free|get_size)$/u.test(line.trim())
    );
  const hasInvalidHooks =
    symbols.length !== 0 &&
    (symbols.length !== 3 ||
      symbols.some(
        (line) =>
          !/\bOBJECT\b/u.test(line) ||
          !/\bLOCAL\b/u.test(line) ||
          /\bUND\b/u.test(line)
      ));
  if (hasInvalidHooks) {
    throw new Error(
      `${library.abi} allocator hooks are neither optimized away nor three defined LOCAL OBJECT symbols`
    );
  }

  console.log(
    `${library.abi}: LOAD=${[...new Set(alignments)].join(",")} allocator-hooks=${symbols.length === 0 ? "optimized-away" : "LOCAL"}`
  );
}

function run(command, args) {
  return execFileSync(command, args, {
    encoding: "utf-8",
    maxBuffer: 16 * 1024 * 1024,
  });
}
