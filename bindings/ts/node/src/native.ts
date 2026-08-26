/* oxlint-disable func-style, no-use-before-define -- Hoisted loader helpers keep module initialization readable. */

import { createRequire } from "node:module";

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

interface NativeEndpointConfig {
  readonly agentVersion?: string;
  readonly allowUnsigned: boolean;
  readonly autonatServers: string[];
  readonly forceRelay: boolean;
  readonly discovery?: {
    readonly autoDial: boolean;
    readonly beaconIntervalMs: bigint;
    readonly peerTtlMs: bigint;
    readonly topic: string;
  };
  readonly mdns?: {
    readonly autoDial: boolean;
    readonly enableIpv6: boolean;
    readonly interfaceRefreshMs: bigint;
    readonly maxAnnouncedAddrs: number;
    readonly maxPacketBytes: number;
    readonly queryIntervalMs: bigint;
    readonly socketPollIntervalMs: bigint;
    readonly ttlMs: bigint;
  };
  readonly protocols: string[];
  readonly pubsubRouter: number;
  readonly quic?: { readonly listenAddrs?: string[] };
  readonly relays: string[];
  readonly tcp?: { readonly listenAddrs?: string[] };
}

export interface NativeEndpoint {
  abandonStream: (peerId: string, streamId: bigint) => void;
  activeReservation: () => unknown;
  addProtocol: (protocolId: string) => void;
  cancelConnect: (id: bigint) => void;
  close: () => void;
  closeStreamWrite: (peerId: string, streamId: bigint) => void;
  connect: (peerId: string) => bigint;
  connectAddr: (address: string) => bigint;
  connectedPeers: () => string[];
  connectWithAddrs: (peerId: string, addresses: string[]) => bigint;
  dial: (address: string) => bigint[];
  dialIp4: (address: string) => bigint;
  dialIp6: (address: string) => bigint;
  disconnect: (peerId: string) => void;
  discoveryNowMs: () => bigint | null | undefined;
  drainEvents: (limit: number) => unknown[];
  isRunning: () => boolean;
  isPeerReady: (peerId: string) => boolean;
  knownPeers: () => unknown[];
  listenAddrs: () => string[];
  openStream: (
    peerId: string,
    protocolId: string
  ) => { readonly connId: bigint; readonly streamId: bigint };
  path: (peerId: string) => unknown;
  peerId: () => string;
  peerInfo: (peerId: string) => unknown;
  ping: (peerId: string) => void;
  publish: (topic: string, data: Uint8Array) => void;
  reachability: () => number;
  resetStream: (peerId: string, streamId: bigint) => void;
  sendStream: (peerId: string, streamId: bigint, data: Uint8Array) => void;
  setActive: (active: boolean) => void;
  start: (doorbell: () => void) => void;
  subscribe: (topic: string) => boolean;
  unsubscribe: (topic: string) => boolean;
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
    let binding: unknown;
    try {
      binding = require(`../minip2p.${target}.node`);
    } catch {
      binding = require(`@minip2p/node-${target}`);
    }
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
