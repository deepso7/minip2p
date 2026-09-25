/* oxlint-disable func-style, no-use-before-define -- The public resolver reads first; hoisted helpers follow in call order. */

import type {
  Minip2pConfig,
  Minip2pDiscoveryOptions,
  Minip2pMdnsOptions,
  Minip2pTransportOptions,
} from "./types.js";

/** Listen settings for one legacy transport-keyed listener. */
export interface BackendTransportConfig {
  /** Exact listen multiaddresses, or `undefined` for dual-stack defaults. */
  readonly listenAddrs?: string[];
}

/**
 * Native-ready endpoint configuration: every SDK default applied, every
 * number validated, and `u64` fields as `bigint` (the shape both napi-rs and
 * UniFFI expect). Adapters pass it through, so defaults and validation
 * cannot drift between runtimes.
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
  /** Address-shaped listen set; when present, `quic` and `tcp` are absent. */
  readonly listen?: string[];
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
  readonly quic?: BackendTransportConfig;
  readonly relays: string[];
  readonly tcp?: BackendTransportConfig;
}

const MIXED_LISTEN_MESSAGE =
  "use either address-shaped `listen` or legacy `quic`/`tcp` transport options, not both";

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
    mdns: resolveMdns(config.mdns, config.discovery),
    protocols: [...(config.protocols ?? [])],
    relays: [...(config.relays ?? [])],
    ...resolveListen(config),
  };
}

function resolveListen(
  config: Minip2pConfig
): Pick<BackendEndpointConfig, "listen" | "quic" | "tcp"> {
  const { listen, transports } = config;
  if (listen !== undefined) {
    // Native would see only one of the two shapes, so reject the mix here
    // with ffi-core's wording.
    if (transports?.quic !== undefined || transports?.tcp !== undefined) {
      throw new Error(MIXED_LISTEN_MESSAGE);
    }
    return { listen: [...listen] };
  }
  if (transports?.quic === undefined && transports?.tcp === undefined) {
    return { quic: {} };
  }
  return {
    quic: resolveTransport(transports.quic),
    tcp: resolveTransport(transports.tcp),
  };
}

function resolveTransport(
  transport: true | Minip2pTransportOptions | undefined
): BackendTransportConfig | undefined {
  if (transport === undefined) {
    return undefined;
  }
  if (transport === true || transport.listen === undefined) {
    return {};
  }
  return { listenAddrs: [...transport.listen] };
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
    socketPollIntervalMs: u64(
      options.socketPollIntervalMs ?? 100,
      "socketPollIntervalMs"
    ),
    ttlMs: u64(options.ttlMs ?? 120_000, "ttlMs"),
  };
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
