/* oxlint-disable func-style -- Use named function declarations for script helpers. */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";

import { namedExports } from "./module-exports.mjs";
import {
  assertNodePlatformManifest,
  nodePlatforms,
} from "./node-platform-manifest.mjs";

const [
  expectedVersion,
  coreTarball,
  reactNativeTarball,
  nativeSourceRoot,
  nodeTarball,
  nodePlatformRoot,
  webTarball,
] = process.argv.slice(2);

if (
  expectedVersion === undefined ||
  coreTarball === undefined ||
  reactNativeTarball === undefined ||
  nativeSourceRoot === undefined ||
  nodeTarball === undefined ||
  nodePlatformRoot === undefined ||
  webTarball === undefined
) {
  throw new Error(
    "usage: verify-release-packages.mjs <version> <core.tgz> <react-native.tgz> <native-source-root> <node.tgz> <node-platform-root> <web.tgz>"
  );
}

const maximumUnpackedBytes = 125 * 1024 * 1024;
// What every page that uses @minip2p/web downloads. Raise it deliberately.
// 4 MiB since relay reservations and circuits (3.65 MB, 0.57 MB gzipped).
const maximumWasmBytes = 4 * 1024 * 1024;
const temporaryRoot = mkdtempSync(
  path.join(tmpdir(), "minip2p-release-packages-")
);

function listFiles(root, relativeRoot = "") {
  const files = [];
  for (const entry of readdirSync(path.join(root, relativeRoot), {
    withFileTypes: true,
  })) {
    const relativePath = path.join(relativeRoot, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(root, relativePath));
    } else {
      files.push(relativePath);
    }
  }
  return files;
}

function extractPackage(tarball, directory) {
  const destination = path.join(temporaryRoot, directory);
  mkdirSync(destination, { recursive: true });
  execFileSync("tar", ["-xzf", path.resolve(tarball), "-C", destination]);

  const root = path.join(destination, "package");
  const manifest = JSON.parse(
    readFileSync(path.join(root, "package.json"), "utf-8")
  );
  return { files: listFiles(root), manifest, root };
}

function verifyManifest(packageInfo, expectedName) {
  if (packageInfo.manifest.name !== expectedName) {
    throw new Error(
      `expected package ${expectedName}, found ${packageInfo.manifest.name}`
    );
  }
  if (packageInfo.manifest.version !== expectedVersion) {
    throw new Error(
      `${expectedName} is ${packageInfo.manifest.version}, expected ${expectedVersion}`
    );
  }
  if (packageInfo.manifest.private === true) {
    throw new Error(`${expectedName} is marked private`);
  }
}

function requireFiles(root, requiredFiles) {
  for (const relativePath of requiredFiles) {
    const file = path.join(root, relativePath);
    let stats;
    try {
      stats = lstatSync(file);
    } catch {
      throw new Error(`release package is missing ${relativePath}`);
    }
    if (!stats.isFile() || stats.size === 0) {
      throw new Error(
        `release package file is empty or invalid: ${relativePath}`
      );
    }
  }
}

function isRejectedPath(file) {
  const components = file.split(/[\\/]/u);
  const basename = components.at(-1)?.toLowerCase() ?? "";
  return (
    components.some((component) => component.startsWith(".")) ||
    components.includes("node_modules") ||
    components.includes("example") ||
    /^(?:credentials(?:\.(?:ini|json|toml|ya?ml))?|service-account(?:-key)?\.json|id_(?:dsa|ecdsa|ed25519|rsa))$/u.test(
      basename
    ) ||
    /\.(?:jks|key|keystore|p12|pem|pfx)$/u.test(basename)
  );
}

function rejectPaths(root, files) {
  const rejected = files.filter(isRejectedPath);
  if (rejected.length !== 0) {
    throw new Error(
      `release package contains rejected paths: ${rejected.join(", ")}`
    );
  }

  for (const file of files) {
    const stats = lstatSync(path.join(root, file));
    if (stats.isSymbolicLink()) {
      throw new Error(`release package contains a symbolic link: ${file}`);
    }
  }
}

function verifyNodePackages(node, platformRoot) {
  const optionalDependencies = node.manifest.optionalDependencies ?? {};
  const packageNames = Object.keys(optionalDependencies).filter((name) =>
    name.startsWith("@minip2p/node-")
  );
  if (packageNames.length !== nodePlatforms.length) {
    throw new Error(
      `@minip2p/node must declare seven platform packages, found ${packageNames.length}`
    );
  }
  if (node.files.some((file) => file.endsWith(".node"))) {
    throw new Error(
      "@minip2p/node root package must not contain a native binary"
    );
  }

  for (const platform of nodePlatforms) {
    const { target } = platform;
    const packageName = `@minip2p/node-${target}`;
    if (optionalDependencies[packageName] !== expectedVersion) {
      throw new Error(`${packageName} is not locked to ${expectedVersion}`);
    }
    const manifest = JSON.parse(
      readFileSync(path.join(platformRoot, target, "package.json"), "utf-8")
    );
    const binary = `minip2p.${target}.node`;
    if (
      manifest.name !== packageName ||
      manifest.version !== expectedVersion ||
      manifest.main !== binary ||
      JSON.stringify(manifest.files) !== JSON.stringify([binary])
    ) {
      throw new Error(`${packageName} has invalid release metadata`);
    }
    assertNodePlatformManifest(manifest, platform);
    requireFiles(path.join(platformRoot, target), [binary]);
  }
}

function requireNamedExports(root, relativePath, requiredExports) {
  const file = path.join(root, relativePath);
  const exports = namedExports(readFileSync(file, "utf-8"));

  const missing = requiredExports.filter((name) => !exports.has(name));
  if (missing.length !== 0) {
    throw new Error(
      `${relativePath} is missing public exports: ${missing.join(", ")}`
    );
  }
}

function hashFile(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function verifyNativeArtifacts(packedRoot, sourceRoot) {
  const artifacts = [
    "android/src/main/jniLibs/arm64-v8a/libminip2p_ffi.so",
    "android/src/main/jniLibs/x86_64/libminip2p_ffi.so",
    "build/Minip2pFfi.xcframework/ios-arm64/libminip2p_ffi.a",
    "build/Minip2pFfi.xcframework/ios-arm64-simulator/libminip2p_ffi.a",
  ];
  for (const relativePath of artifacts) {
    const packedHash = hashFile(path.join(packedRoot, relativePath));
    const sourceHash = hashFile(path.join(sourceRoot, relativePath));
    if (packedHash !== sourceHash) {
      throw new Error(
        `packed native artifact differs from its validated source: ${relativePath}`
      );
    }
  }
}

function verifyWebPackage(web) {
  const exports = web.manifest.exports ?? {};
  for (const entry of [".", "./manual"]) {
    if (exports[entry]?.default === undefined) {
      throw new Error(`@minip2p/web must export ${entry}`);
    }
  }
  const wasmBytes = lstatSync(
    path.join(web.root, "wasm/minip2p_web_bg.wasm")
  ).size;
  if (wasmBytes > maximumWasmBytes) {
    throw new Error(
      `@minip2p/web's wasm is ${wasmBytes} bytes, exceeding the ${maximumWasmBytes}-byte limit`
    );
  }
  requireNamedExports(web.root, "dist/index.js", [
    "Minip2p",
    "generateSecretKey",
  ]);
  requireNamedExports(web.root, "dist/manual.js", ["Minip2p", "initMinip2p"]);
}

function directorySize(root) {
  return listFiles(root).reduce(
    (size, file) => size + lstatSync(path.join(root, file)).size,
    0
  );
}

try {
  const core = extractPackage(coreTarball, "core");
  const reactNative = extractPackage(reactNativeTarball, "react-native");
  const node = extractPackage(nodeTarball, "node");
  const web = extractPackage(webTarball, "web");

  verifyManifest(core, "@minip2p/core");
  verifyManifest(reactNative, "@minip2p/react-native");
  verifyManifest(node, "@minip2p/node");
  verifyManifest(web, "@minip2p/web");

  if (
    reactNative.manifest.dependencies?.["@minip2p/core"] !== expectedVersion
  ) {
    throw new Error(
      `@minip2p/react-native must depend on @minip2p/core ${expectedVersion}, found ${reactNative.manifest.dependencies?.["@minip2p/core"] ?? "no dependency"}`
    );
  }
  for (const binding of [node, web]) {
    const dependency = binding.manifest.dependencies?.["@minip2p/core"];
    if (dependency !== expectedVersion) {
      throw new Error(
        `${binding.manifest.name} must depend on @minip2p/core ${expectedVersion}, found ${dependency ?? "no dependency"}`
      );
    }
  }

  requireFiles(core.root, [
    "LICENSE",
    "README.md",
    "dist/backend.d.ts",
    "dist/backend.js",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/serde-backend.d.ts",
    "dist/serde-backend.js",
    "src/index.ts",
  ]);
  requireFiles(reactNative.root, [
    "LICENSE",
    "Minip2p.podspec",
    "README.md",
    "android/src/main/jniLibs/arm64-v8a/libminip2p_ffi.so",
    "android/src/main/jniLibs/x86_64/libminip2p_ffi.so",
    "build/Minip2pFfi.xcframework/Info.plist",
    "build/Minip2pFfi.xcframework/ios-arm64-simulator/libminip2p_ffi.a",
    "build/Minip2pFfi.xcframework/ios-arm64/libminip2p_ffi.a",
    "cpp/generated/minip2p_ffi.cpp",
    "cpp/generated/minip2p_ffi.hpp",
    "lib/module/index.js",
    "lib/module/hook-lifecycle.js",
    "lib/typescript/src/index.d.ts",
    "src/index.ts",
  ]);
  requireFiles(node.root, [
    "LICENSE",
    "README.md",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/native.d.ts",
    "dist/native.js",
  ]);
  requireFiles(web.root, [
    "LICENSE",
    "README.md",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/manual.d.ts",
    "dist/manual.js",
    "wasm/minip2p_web.d.ts",
    "wasm/minip2p_web.js",
    "wasm/minip2p_web_bg.wasm",
  ]);

  rejectPaths(core.root, core.files);
  rejectPaths(reactNative.root, reactNative.files);
  rejectPaths(node.root, node.files);
  rejectPaths(web.root, web.files);
  verifyWebPackage(web);
  verifyNodePackages(node, path.resolve(nodePlatformRoot));
  requireNamedExports(reactNative.root, "lib/module/index.js", ["Minip2p"]);
  requireNamedExports(reactNative.root, "lib/typescript/src/index.d.ts", [
    "Minip2p",
  ]);
  verifyNativeArtifacts(reactNative.root, path.resolve(nativeSourceRoot));
  execFileSync(
    process.execPath,
    [
      path.resolve(
        import.meta.dirname,
        "../react-native/scripts/check-android-elf.mjs"
      ),
      reactNative.root,
    ],
    { stdio: "inherit" }
  );

  const combinedSize =
    directorySize(core.root) +
    directorySize(reactNative.root) +
    directorySize(node.root) +
    directorySize(web.root);
  if (combinedSize > maximumUnpackedBytes) {
    throw new Error(
      `release packages unpack to ${combinedSize} bytes, exceeding the ${maximumUnpackedBytes}-byte limit`
    );
  }

  console.log(
    `verified @minip2p/core, @minip2p/react-native, @minip2p/node, and @minip2p/web ${expectedVersion} (${combinedSize} unpacked bytes)`
  );
} finally {
  rmSync(temporaryRoot, { force: true, recursive: true });
}
