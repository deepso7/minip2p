/* oxlint-disable func-style, no-use-before-define -- The public resolver reads first; hoisted helpers follow in call order. */

import type {
  Minip2pConfig,
  Minip2pDiscoveryOptions,
  Minip2pLimits,
  Minip2pMdnsOptions,
  Minip2pQuicLimits,
  Minip2pTcpLimits,
  Minip2pYamuxLimits,
} from "./types.js";

/**
 * Native-ready endpoint configuration: the SDK's discovery and mDNS defaults
 * applied, every number validated, and `u64` fields as `bigint` (the shape
 * both napi-rs and UniFFI expect). `limits` carries only the fields the
 * caller set, so native keeps its own defaults for the rest. Adapters pass
 * it through, so defaults and validation cannot drift between runtimes.
 */
export interface BackendEndpointConfig {
  readonly agentVersion?: string;
  readonly allowUnsigned: boolean;
  readonly autonatServers: string[];
  readonly discovery?: {
    readonly autoDial: boolean;
    readonly beaconIntervalMs: bigint;
    readonly peerTtlMs: bigint;
    readonly topic: string;
  };
  readonly forceRelay: boolean;
  readonly limits?: BackendLimits;
  /** Listen multiaddresses, or `undefined` for the native QUIC dual-stack defaults. */
  readonly listen?: string[];
  readonly mdns?: {
    readonly autoDial: boolean;
    readonly enableIpv6: boolean;
    readonly interfaceRefreshMs: bigint;
    readonly maxAnnouncedAddrs: number;
    readonly maxPacketBytes: number;
    readonly queryIntervalMs: bigint;
    readonly ttlMs: bigint;
  };
  readonly protocols: string[];
  readonly relays: string[];
}

/** {@link Minip2pLimits} in native form; absent fields keep native defaults. */
export interface BackendLimits {
  readonly circuit?: BackendYamuxLimits;
  readonly maxCircuits?: bigint;
  readonly quic?: BackendQuicLimits;
  readonly tcp?: BackendTcpLimits;
}

/** {@link Minip2pQuicLimits} in native form. */
export interface BackendQuicLimits {
  readonly connectionReceiveWindow?: bigint | "unlimited";
  readonly controlStreamReserveBytes?: bigint;
  readonly idleTimeoutMs?: bigint;
  readonly maxConnections?: bigint;
  readonly maxPendingBytesPerStream?: bigint;
  readonly maxPendingConnectionBytes?: bigint;
  readonly maxPendingDatagrams?: bigint;
  readonly maxStreamsPerConnection?: bigint;
  readonly requireAddressValidation?: boolean;
  readonly sendWindow?: bigint;
  readonly streamReceiveWindow?: bigint;
  readonly webtransportHandshakeTimeoutMs?: bigint;
}

/** {@link Minip2pTcpLimits} in native form. */
export interface BackendTcpLimits {
  readonly handshakeTimeoutMs?: bigint | "never";
  readonly maxBufferedSend?: bigint;
  readonly maxConnections?: bigint;
  readonly sendStallTimeoutMs?: bigint | "never";
  readonly yamux?: BackendYamuxLimits;
}

/** {@link Minip2pYamuxLimits} in native form; the two windows are `u32`. */
export interface BackendYamuxLimits {
  readonly controlStreamReserve?: bigint;
  readonly maxBufferedSend?: bigint;
  readonly maxFrameLen?: number;
  readonly maxPendingControl?: bigint;
  readonly maxStreams?: bigint;
  readonly maxTotalBufferedSend?: bigint;
  readonly receiveWindow?: number;
}

/** Applies SDK defaults to `config` and validates it for a native adapter. */
export function resolveEndpointConfig(
  config: Minip2pConfig
): BackendEndpointConfig {
  return {
    agentVersion: config.agentVersion,
    allowUnsigned: config.allowUnsigned ?? false,
    autonatServers: [...(config.autonatServers ?? [])],
    discovery: resolveDiscovery(config.discovery),
    forceRelay: config.forceRelay ?? false,
    limits: config.limits && resolveLimits(config.limits),
    listen: config.listen && [...config.listen],
    mdns: resolveMdns(config.mdns, config.discovery),
    protocols: [...(config.protocols ?? [])],
    relays: [...(config.relays ?? [])],
  };
}

function resolveDiscovery(
  discovery: Minip2pDiscoveryOptions | undefined
): BackendEndpointConfig["discovery"] {
  if (discovery === undefined) {
    return undefined;
  }
  return {
    autoDial: discovery.autoDial ?? true,
    beaconIntervalMs: u64(
      discovery.beaconIntervalMs ?? 10_000,
      "beaconIntervalMs"
    ),
    peerTtlMs: u64(discovery.peerTtlMs ?? 35_000, "peerTtlMs"),
    topic: discovery.topic,
  };
}

function resolveMdns(
  mdns: boolean | Minip2pMdnsOptions | undefined,
  discovery: Minip2pDiscoveryOptions | undefined
): BackendEndpointConfig["mdns"] {
  const options = mdns === true ? {} : mdns;
  if (options === undefined || options === false) {
    return undefined;
  }
  return {
    autoDial: options.autoDial ?? discovery?.autoDial ?? true,
    enableIpv6: options.enableIpv6 ?? false,
    interfaceRefreshMs: u64(
      options.interfaceRefreshMs ?? 10_000,
      "interfaceRefreshMs"
    ),
    maxAnnouncedAddrs: u32(
      options.maxAnnouncedAddrs ?? 16,
      "maxAnnouncedAddrs"
    ),
    maxPacketBytes: u32(options.maxPacketBytes ?? 1400, "maxPacketBytes"),
    queryIntervalMs: u64(options.queryIntervalMs ?? 300_000, "queryIntervalMs"),
    ttlMs: u64(options.ttlMs ?? 120_000, "ttlMs"),
  };
}

function resolveLimits(limits: Minip2pLimits): BackendLimits {
  return withoutUndefined({
    circuit: limits.circuit && resolveYamux(limits.circuit, "circuit"),
    maxCircuits: optionalU64(limits.maxCircuits, "maxCircuits"),
    quic: limits.quic && resolveQuic(limits.quic),
    tcp: limits.tcp && resolveTcp(limits.tcp),
  });
}

function resolveQuic(quic: Minip2pQuicLimits): BackendQuicLimits {
  return withoutUndefined({
    connectionReceiveWindow: u64OrLiteral(
      quic.connectionReceiveWindow,
      "unlimited",
      "quic.connectionReceiveWindow"
    ),
    controlStreamReserveBytes: optionalU64(
      quic.controlStreamReserveBytes,
      "quic.controlStreamReserveBytes"
    ),
    idleTimeoutMs: optionalU64(quic.idleTimeoutMs, "quic.idleTimeoutMs"),
    maxConnections: optionalU64(quic.maxConnections, "quic.maxConnections"),
    maxPendingBytesPerStream: optionalU64(
      quic.maxPendingBytesPerStream,
      "quic.maxPendingBytesPerStream"
    ),
    maxPendingConnectionBytes: optionalU64(
      quic.maxPendingConnectionBytes,
      "quic.maxPendingConnectionBytes"
    ),
    maxPendingDatagrams: optionalU64(
      quic.maxPendingDatagrams,
      "quic.maxPendingDatagrams"
    ),
    maxStreamsPerConnection: optionalU64(
      quic.maxStreamsPerConnection,
      "quic.maxStreamsPerConnection"
    ),
    requireAddressValidation: quic.requireAddressValidation,
    sendWindow: optionalU64(quic.sendWindow, "quic.sendWindow"),
    streamReceiveWindow: optionalU64(
      quic.streamReceiveWindow,
      "quic.streamReceiveWindow"
    ),
    webtransportHandshakeTimeoutMs: optionalU64(
      quic.webtransportHandshakeTimeoutMs,
      "quic.webtransportHandshakeTimeoutMs"
    ),
  });
}

function resolveTcp(tcp: Minip2pTcpLimits): BackendTcpLimits {
  return withoutUndefined({
    handshakeTimeoutMs: u64OrLiteral(
      tcp.handshakeTimeoutMs,
      "never",
      "tcp.handshakeTimeoutMs"
    ),
    maxBufferedSend: optionalU64(tcp.maxBufferedSend, "tcp.maxBufferedSend"),
    maxConnections: optionalU64(tcp.maxConnections, "tcp.maxConnections"),
    sendStallTimeoutMs: u64OrLiteral(
      tcp.sendStallTimeoutMs,
      "never",
      "tcp.sendStallTimeoutMs"
    ),
    yamux: tcp.yamux && resolveYamux(tcp.yamux, "tcp.yamux"),
  });
}

function resolveYamux(
  yamux: Minip2pYamuxLimits,
  path: string
): BackendYamuxLimits {
  const name = (field: string) => `${path}.${field}`;
  return withoutUndefined({
    controlStreamReserve: optionalU64(
      yamux.controlStreamReserve,
      name("controlStreamReserve")
    ),
    maxBufferedSend: optionalU64(
      yamux.maxBufferedSend,
      name("maxBufferedSend")
    ),
    maxFrameLen:
      yamux.maxFrameLen === undefined
        ? undefined
        : u32(yamux.maxFrameLen, name("maxFrameLen")),
    maxPendingControl: optionalU64(
      yamux.maxPendingControl,
      name("maxPendingControl")
    ),
    maxStreams: optionalU64(yamux.maxStreams, name("maxStreams")),
    maxTotalBufferedSend: optionalU64(
      yamux.maxTotalBufferedSend,
      name("maxTotalBufferedSend")
    ),
    receiveWindow:
      yamux.receiveWindow === undefined
        ? undefined
        : u32(yamux.receiveWindow, name("receiveWindow")),
  });
}

/** Drops unset fields, so native sees only what the caller chose. */
function withoutUndefined<T extends object>(value: T): T {
  return Object.fromEntries(
    Object.entries(value).filter(([, field]) => field !== undefined)
  ) as T;
}

function optionalU64(
  value: number | undefined,
  name: string
): bigint | undefined {
  return value === undefined ? undefined : u64(value, name);
}

/** A `u64`, or the literal that stands for "no limit". */
function u64OrLiteral<L extends string>(
  value: number | L | undefined,
  literal: L,
  name: string
): bigint | L | undefined {
  if (typeof value === "number") {
    return u64(value, name);
  }
  if (value !== undefined && value !== literal) {
    throw new RangeError(
      `${name} must be a non-negative safe integer or "${literal}"`
    );
  }
  return value;
}

function assertUnsigned(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}

function u64(value: number, name: string): bigint {
  assertUnsigned(value, name);
  return BigInt(value);
}

function u32(value: number, name: string): number {
  assertUnsigned(value, name);
  if (value > 0xff_ff_ff_ff) {
    throw new RangeError(`${name} exceeds the unsigned 32-bit range`);
  }
  return value;
}
