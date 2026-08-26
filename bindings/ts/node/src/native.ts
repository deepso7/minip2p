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

interface NativeEndpointConfig {
  readonly agentVersion?: string;
  readonly allowUnsigned: boolean;
  readonly autonatServers: string[];
  readonly forceRelay: boolean;
  readonly protocols: string[];
  readonly pubsubRouter: number;
  readonly quic?: { readonly listenAddrs?: string[] };
  readonly relays: string[];
  readonly tcp?: { readonly listenAddrs?: string[] };
}

export interface NativeEndpoint {
  close: () => void;
  isRunning: () => boolean;
  listenAddrs: () => string[];
  peerId: () => string;
  start: (doorbell: () => void) => void;
}

interface NativeBinding {
  readonly NodeEndpoint: new (
    secretKey: Uint8Array,
    config: NativeEndpointConfig
  ) => NativeEndpoint;
  circuitAddress: (relayAddress: string, peerId: string) => string;
  generateSecretKey: () => Uint8Array;
  peerIdFromSecretKey: (secretKey: Uint8Array) => string;
}

function loadNativeBinding(target: string): NativeBinding {
  if (!supportedTargets.includes(target as SupportedTarget)) {
    throw unsupportedTarget(target);
  }

  try {
    const binding: unknown = require(`../minip2p.${target}.node`);
    assertNativeBinding(binding);
    return binding;
  } catch (error) {
    throw unsupportedTarget(target, error);
  }
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
