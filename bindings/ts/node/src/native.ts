import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const supportedTargets = [
  "linux-x64-gnu",
  "linux-x64-musl",
  "linux-arm64-gnu",
  "linux-arm64-musl",
  "darwin-x64",
  "darwin-arm64",
  "win32-x64",
] as const;

type SupportedTarget = (typeof supportedTargets)[number];

function linuxLibc(): "gnu" | "musl" {
  const report = process.report?.getReport();
  const header = report === undefined ? undefined : Reflect.get(report, "header");
  return header === undefined ||
    Reflect.get(header, "glibcVersionRuntime") === undefined
    ? "musl"
    : "gnu";
}

function currentTarget(): string {
  if (process.platform === "linux") {
    return `${process.platform}-${process.arch}-${linuxLibc()}`;
  }
  return `${process.platform}-${process.arch}`;
}

function unsupportedTarget(target: string, cause?: unknown): Error {
  return new Error(
    `Unsupported minip2p Node target ${target}. Supported targets: ${supportedTargets.join(", ")}. Reinstall @minip2p/node without omitting optional dependencies.`,
    cause === undefined ? undefined : { cause }
  );
}

function loadNativeBinding(target: string): unknown {
  if (!supportedTargets.includes(target as SupportedTarget)) {
    throw unsupportedTarget(target);
  }

  try {
    return require(`../minip2p.${target}.node`);
  } catch (error) {
    throw unsupportedTarget(target, error);
  }
}

export const nativeBinding = loadNativeBinding(currentTarget());
