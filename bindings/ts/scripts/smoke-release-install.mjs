/* oxlint-disable func-style -- Smoke-test helpers are hoisted below the installed-package checks. */

import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import ts from "typescript";

const [consumerRoot] = process.argv.slice(2);
if (consumerRoot === undefined) {
  throw new Error("usage: smoke-release-install.mjs <consumer-root>");
}

const modules = path.resolve(consumerRoot, "node_modules");
const coreRoot = path.join(modules, "@minip2p/core");
const reactNativeRoot = path.join(modules, "@minip2p/react-native");
const coreManifest = readManifest(coreRoot);
const reactNativeManifest = readManifest(reactNativeRoot);

if (
  reactNativeManifest.dependencies?.["@minip2p/core"] !== coreManifest.version
) {
  throw new Error(
    `installed @minip2p/react-native requires core ${reactNativeManifest.dependencies?.["@minip2p/core"] ?? "missing"}, but ${coreManifest.version} is installed`
  );
}

const coreEntry = packageExport(coreManifest, "default");
const core = await import(pathToFileURL(path.join(coreRoot, coreEntry)).href);
if (typeof core.Minip2pBase !== "function") {
  throw new TypeError("installed @minip2p/core is missing Minip2pBase");
}

requireNamedExport(
  path.join(reactNativeRoot, packageExport(reactNativeManifest, "default")),
  "Minip2p"
);
requireNamedExport(
  path.join(reactNativeRoot, packageExport(reactNativeManifest, "types")),
  "Minip2p"
);

console.log(
  `smoke-tested installed @minip2p/core and @minip2p/react-native ${coreManifest.version}`
);

function readManifest(root) {
  return JSON.parse(readFileSync(path.join(root, "package.json"), "utf-8"));
}

function packageExport(manifest, condition) {
  const target = manifest.exports?.["."]?.[condition];
  if (typeof target !== "string" || !target.startsWith("./")) {
    throw new Error(
      `${manifest.name} has no valid ${condition} package export`
    );
  }
  return target;
}

function requireNamedExport(file, expectedExport) {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, "utf-8"),
    ts.ScriptTarget.Latest,
    true
  );
  for (const statement of source.statements) {
    if (
      ts.isExportDeclaration(statement) &&
      statement.exportClause !== undefined &&
      ts.isNamedExports(statement.exportClause) &&
      statement.exportClause.elements.some(
        (element) => element.name.text === expectedExport
      )
    ) {
      return;
    }
  }
  throw new Error(`${file} is missing the ${expectedExport} public export`);
}
/* oxlint-disable func-style -- Smoke-test helpers are hoisted below the installed-package checks. */
