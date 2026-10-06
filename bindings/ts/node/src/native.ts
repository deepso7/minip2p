/* oxlint-disable func-style, no-use-before-define -- Hoisted loader helpers keep module initialization readable. */

import { createRequire } from "node:module";

import type * as Addon from "./addon.js";

const require = createRequire(import.meta.url);

const supportedTargets = [
  "linux-x64-gnu",
  "linux-x64-musl",
  "linux-arm64-gnu",
  "linux-arm64-musl",
  "darwin-x64",
  "darwin-arm64",
  "win32-x64-msvc",
] as const;

type SupportedTarget = (typeof supportedTargets)[number];

function linuxLibc(): "gnu" | "musl" {
  const report = process.report?.getReport();
  const header =
    report === undefined ? undefined : Reflect.get(report, "header");
  return header === undefined ||
    (Reflect.get(header, "glibcVersionRuntime") === undefined &&
      Reflect.get(header, "glibcVersionCompiler") === undefined)
    ? "musl"
    : "gnu";
}

function currentTarget(): string {
  if (process.platform === "linux") {
    return `${process.platform}-${process.arch}-${linuxLibc()}`;
  }
  if (process.platform === "win32") {
    return `${process.platform}-${process.arch}-msvc`;
  }
  return `${process.platform}-${process.arch}`;
}

function unsupportedTarget(target: string, cause?: unknown): Error {
  return new Error(
    `Unsupported minip2p Node target ${target}. Supported targets: ${supportedTargets.join(", ")}.`,
    cause === undefined ? undefined : { cause }
  );
}

/** The addon's exports, typed by the `addon.d.ts` that `native:build` generates. */
type NativeBinding = typeof Addon;

/** A native endpoint instance. */
export type NativeEndpoint = Addon.NodeEndpoint;

function loadNativeBinding(target: string): NativeBinding {
  if (!supportedTargets.includes(target as SupportedTarget)) {
    throw unsupportedTarget(target);
  }

  let binding: unknown;
  try {
    binding = require(`../minip2p.${target}.node`);
  } catch (error) {
    if (!isModuleNotFound(error)) {
      throw error;
    }
    try {
      binding = require(`@minip2p/node-${target}`);
    } catch (packageError) {
      throw unsupportedTarget(target, packageError);
    }
  }
  assertNativeBinding(binding);
  return binding;
}

function isModuleNotFound(error: unknown): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    Reflect.get(error, "code") === "MODULE_NOT_FOUND"
  );
}

function assertNativeBinding(value: unknown): asserts value is NativeBinding {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof Reflect.get(value, "NodeEndpoint") !== "function" ||
    typeof Reflect.get(value, "generateSecretKey") !== "function"
  ) {
    throw new Error("The minip2p native addon has an invalid export shape");
  }
}

export const nativeBinding = loadNativeBinding(currentTarget());
