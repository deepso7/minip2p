/* oxlint-disable no-redeclare -- Public constants and their value-union types intentionally share names. */

import type { DriverFailedError } from "./errors.js";
import type { Stream } from "./sdk.js";

/** Bytes accepted by the platform-neutral SDK. */
export type Bytes = ArrayBuffer | Uint8Array;

/** Signed-discovery settings. The topic is intentionally application-scoped. */
export interface Minip2pDiscoveryOptions {
  /** Application-scoped signed-beacon topic. */
  readonly topic: string;
  /** Beacon broadcast interval in milliseconds. */
  readonly beaconIntervalMs?: number;
  /** Time without observations before a peer expires. */
  readonly peerTtlMs?: number;
  /** Whether newly discovered peers should be dialed automatically. */
  readonly autoDial?: boolean;
}

/** Local-link mDNS discovery settings. Omitted fields use native defaults. */
export interface Minip2pMdnsOptions {
  /** Enables IPv6 multicast in addition to IPv4. */
  readonly enableIpv6?: boolean;
  /** TTL advertised in mDNS records. */
  readonly ttlMs?: number;
  /** Period between discovery queries. */
  readonly queryIntervalMs?: number;
  /** Maximum encoded DNS packet size. */
  readonly maxPacketBytes?: number;
  /** Maximum addresses advertised per response. */
  readonly maxAnnouncedAddrs?: number;
  /** Period between network-interface refreshes. */
  readonly interfaceRefreshMs?: number;
  /** Whether newly discovered peers should be dialed automatically. */
  readonly autoDial?: boolean;
}

/** Coarse local reachability states. */
export const Reachability = {
  Private: "Private",
  Public: "Public",
  Unknown: "Unknown",
} as const;
export type Reachability = (typeof Reachability)[keyof typeof Reachability];

/** Sources contributing peer-discovery observations. */
export const DiscoverySource = {
  Mdns: "Mdns",
  SignedBeacon: "SignedBeacon",
} as const;
export type DiscoverySource =
  (typeof DiscoverySource)[keyof typeof DiscoverySource];

/** Categories of an mDNS failure reported by `mdnsFailed`. */
export const MdnsFailureKind = {
  /** A goodbye could not be sent before shutdown gave up on a full send buffer. */
  Congested: "Congested",
  /** The interface id space is exhausted. */
  InterfaceIdsExhausted: "InterfaceIdsExhausted",
  /** Platform I/O failed. */
  Io: "Io",
  /** An interface has no usable address. */
  NoInterfaceAddress: "NoInterfaceAddress",
  /** A datagram is larger than the carrier can ever send. */
  Oversized: "Oversized",
  /** A send named an interface that has gone away. */
  UnknownInterface: "UnknownInterface",
  /** The platform cannot provide mDNS sockets. */
  Unsupported: "Unsupported",
} as const;
export type MdnsFailureKind =
  (typeof MdnsFailureKind)[keyof typeof MdnsFailureKind];

/** The part of an endpoint's configuration an `InvalidConfigError` names. */
export const ConfigCapability = {
  /** Signed discovery or peer-book settings. */
  Discovery: "Discovery",
  /** Gossipsub settings. */
  Gossipsub: "Gossipsub",
  /** mDNS settings. */
  Mdns: "Mdns",
  /**
   * The endpoint's own options: listen addresses, protocols, NAT and relay
   * policy, auto-dial.
   */
  Options: "Options",
  /** QUIC or TCP transport settings. */
  Transport: "Transport",
} as const;
export type ConfigCapability =
  (typeof ConfigCapability)[keyof typeof ConfigCapability];

/** Fatal native-driver failure categories. */
export const DriverFailureKind = {
  Invariant: "Invariant",
  Panic: "Panic",
  Swarm: "Swarm",
  Transport: "Transport",
} as const;
export type DriverFailureKind =
  (typeof DriverFailureKind)[keyof typeof DriverFailureKind];

/** Non-fatal endpoint runtime error categories. */
export const EndpointErrorKind = {
  Driver: "Driver",
  Identify: "Identify",
  IdentifyStreamRejected: "IdentifyStreamRejected",
  Multistream: "Multistream",
  OpenStreamFailed: "OpenStreamFailed",
  Ping: "Ping",
  Transport: "Transport",
  UnsupportedProtocol: "UnsupportedProtocol",
} as const;
export type EndpointErrorKind =
  (typeof EndpointErrorKind)[keyof typeof EndpointErrorKind];

/** Terminal NAT connection failure categories. */
export const NatErrorKind = {
  DialFailed: "DialFailed",
  NoPathAvailable: "NoPathAvailable",
  Protocol: "Protocol",
  RelayRefused: "RelayRefused",
  Timeout: "Timeout",
} as const;
export type NatErrorKind = (typeof NatErrorKind)[keyof typeof NatErrorKind];

/** Configuration accepted by a platform minip2p endpoint. */
export interface Minip2pConfig {
  /** Raw 32-byte Ed25519 secret key. */
  readonly secretKey: Bytes;
  /** Agent version advertised through Identify. */
  readonly agentVersion?: string;
  /** Direct QUIC or TCP relay peer multiaddresses. */
  readonly relays?: readonly string[];
  /** AutoNAT server peer multiaddresses. */
  readonly autonatServers?: readonly string[];
  /**
   * Listen multiaddresses; each address's shape selects its transport, e.g.
   * `/ip4/0.0.0.0/udp/4001/quic-v1` or `/ip4/0.0.0.0/tcp/4001`. Omit for the
   * native QUIC dual-stack defaults on ephemeral ports.
   */
  readonly listen?: readonly [string, ...string[]];
  /** Routes outbound connectivity through relays only. */
  readonly forceRelay?: boolean;
  /** Accepts unsigned pubsub messages. */
  readonly allowUnsigned?: boolean;
  /** Application protocol IDs accepted on inbound streams. */
  readonly protocols?: readonly string[];
  /** Signed-beacon discovery configuration. */
  readonly discovery?: Minip2pDiscoveryOptions;
  /** Enables mDNS with defaults or explicit options. */
  readonly mdns?: boolean | Minip2pMdnsOptions;
}

/** Latest Identify information advertised by a remote peer. */
export interface IdentifyInfo {
  /** Protobuf-encoded remote public key, when supplied. */
  readonly publicKey?: ArrayBuffer;
  /** Listen addresses advertised by the remote peer. */
  readonly listenAddrs: readonly string[];
  /** Protocols advertised by the remote peer. */
  readonly protocols: readonly string[];
  /** Address at which the remote observed this endpoint. */
  readonly observedAddr?: string;
  /** Remote libp2p protocol version. */
  readonly protocolVersion?: string;
  /** Remote agent version. */
  readonly agentVersion?: string;
}

/** Merged discovery information for one peer. */
export interface KnownPeerInfo {
  readonly peerId: string;
  readonly addrs: readonly string[];
  readonly beaconAddrs: readonly string[];
  readonly mdnsAddrs: readonly string[];
  readonly beaconLastSeenAgeMs?: number;
  readonly mdnsLastSeenAgeMs?: number;
  readonly connected: boolean;
}

/** Active relay reservation metadata. */
export interface RelayReservationInfo {
  readonly relayPeerId: string;
  readonly expiresUnixSecs?: number;
}

/** A usable NAT-orchestrated connection path. */
export type Path =
  | { readonly kind: "directDialed" }
  | { readonly kind: "directPunched" }
  | { readonly kind: "relayed"; readonly relayPeerId: string };

/**
 * Why one connection ended. `remote` carries the peer's close code: its QUIC
 * CONNECTION_CLOSE code, or its Yamux GoAway code over TCP and relay
 * circuits. `timedOut` means the peer went silent, `stalled` that it stopped
 * reading.
 */
export type ConnectionCloseReason =
  | { readonly kind: "local" }
  | { readonly kind: "remote"; readonly code: bigint }
  | { readonly kind: "timedOut" }
  | { readonly kind: "stalled" }
  | { readonly kind: "error"; readonly message: string };

/** Serializable metadata for an inbound stream catch-all event. */
export interface InboundStreamMeta {
  readonly peerId: string;
  readonly protocolId: string;
  readonly streamId: number;
  readonly connId: number;
  readonly initiatedLocally: boolean;
}

/** Payload types keyed by high-level SDK event name. */
export interface Minip2pNamedEventMap {
  eventsDropped: {
    readonly dropped: number;
    readonly totalDropped: number;
    readonly terminalConnectIds: readonly number[];
  };
  driverFailed: {
    readonly kind: DriverFailureKind;
    readonly detail: string;
  };
  /** A peer went from disconnected to connected on `connId`. */
  connectionEstablished: { readonly peerId: string; readonly connId: number };
  /**
   * The peer's last connection closed, for `reason`; the peer is now
   * disconnected. A failure that ended it is its `reason`, never also an
   * `endpointError`.
   */
  connectionClosed: {
    readonly peerId: string;
    readonly connId: number;
    readonly reason: ConnectionCloseReason;
  };
  /**
   * A newer connection took the peer's single connection slot from
   * `oldConnId`. The peer stays connected: this stands in for both a
   * `connectionClosed` for `oldConnId` and a `connectionEstablished` for
   * `newConnId`. Every stream and pending open on `oldConnId` ends with it,
   * and a fresh `peerReady` follows for `newConnId`.
   */
  connectionReplaced: {
    readonly peerId: string;
    readonly oldConnId: number;
    readonly newConnId: number;
  };
  /**
   * Identify completed on `connId`. Fires once per connection; one whose
   * `connId` is no longer the peer's current connection is stale.
   */
  peerReady: {
    readonly peerId: string;
    readonly connId: number;
    readonly protocols: readonly string[];
  };
  /** An Identify snapshot arrived on `connId`. */
  identifyReceived: {
    readonly peerId: string;
    readonly connId: number;
    readonly info: IdentifyInfo;
  };
  /** A ping round trip completed on `connId`. */
  pingRttMeasured: {
    readonly peerId: string;
    readonly connId: number;
    readonly rttMs: number;
  };
  /** A ping sent on `connId` timed out. */
  pingTimeout: { readonly peerId: string; readonly connId: number };
  stream: Stream;
  endpointError: {
    readonly kind: EndpointErrorKind;
    readonly peerId?: string;
    readonly connId?: number;
    readonly streamId?: number;
    readonly detail: string;
  };
  reachabilityChanged: {
    readonly previous: Reachability;
    readonly current: Reachability;
    readonly confirmedAddrs: readonly string[];
  };
  publicAddressesChanged: { readonly addrs: readonly string[] };
  relayReserved: {
    readonly relayPeerId: string;
    readonly expiresUnixSecs?: number;
  };
  relayReservationLost: { readonly relayPeerId: string };
  pathEstablished: {
    readonly connectId: number;
    readonly peerId: string;
    readonly connId: number;
    readonly path: Path;
  };
  inboundPathEstablished: {
    readonly peerId: string;
    readonly path: Path;
    /** Circuit connection carrying the path. */
    readonly connId: number;
  };
  pathUpgraded: {
    readonly connectId: number;
    readonly peerId: string;
    readonly from: Path;
    readonly to: Path;
    /** Connection that carried `from`. */
    readonly oldConnId: number;
    /** Connection carrying `to`. */
    readonly newConnId: number;
  };
  holePunchFailed: {
    readonly connectId: number;
    readonly attempt: number;
    readonly reason: string;
  };
  connectFailed: {
    readonly connectId: number;
    readonly peerId: string;
    readonly kind: NatErrorKind;
    readonly detail: string;
  };
  connectCancelled: {
    readonly connectId: number;
    readonly peerId: string;
  };
  inboundDirectUpgrade: {
    readonly peerId: string;
    /** Circuit connection that carried the relayed path. */
    readonly oldConnId: number;
    /** Direct connection now carrying the peer. */
    readonly newConnId: number;
  };
  message: {
    readonly fromPeerId: string;
    readonly topics: readonly string[];
    readonly data: ArrayBuffer;
    readonly seqno: ArrayBuffer;
    readonly signed: boolean;
  };
  peerSubscribed: { readonly peerId: string; readonly topic: string };
  peerUnsubscribed: { readonly peerId: string; readonly topic: string };
  gossipsubOutboundFailure: {
    readonly peerId: string;
    readonly reason: string;
  };
  gossipsubProtocolViolation: {
    readonly peerId: string;
    readonly reason: string;
  };
  peerDiscovered: {
    readonly peerId: string;
    readonly addrs: readonly string[];
    readonly source: DiscoverySource;
  };
  peerUpdated: {
    readonly peerId: string;
    readonly addrs: readonly string[];
    readonly source: DiscoverySource;
  };
  peerExpired: { readonly peerId: string };
  discoveryDialFailed: { readonly peerId: string; readonly reason: string };
  /**
   * mDNS hit a hard failure. It keeps running and retries; this fires once
   * per change in failure state, and `mdnsRecovered` follows once a retry
   * succeeds. A goodbye that failed during shutdown is final.
   */
  mdnsFailed: { readonly kind: MdnsFailureKind; readonly detail: string };
  /** mDNS recovered from its last `mdnsFailed`. Carries no fields. */
  mdnsRecovered: Readonly<Record<never, never>>;
  discoveryProtocolViolation: {
    readonly peerId?: string;
    readonly source: DiscoverySource;
    readonly reason: string;
    readonly suppressed: number;
  };
  queueOverflow: { readonly dropped: number };
  handlerError: {
    readonly eventType: keyof Minip2pNamedEventMap | "inboundStream";
    readonly metadata: Record<string, unknown>;
    readonly error: unknown;
  };
}

/** Events available to the catch-all endpoint subscriber. */
export type Minip2pCatchAllEventMap = Omit<
  Minip2pNamedEventMap,
  "stream" | "handlerError"
> & {
  inboundStream: InboundStreamMeta;
  handlerError: Minip2pNamedEventMap["handlerError"];
};

/** Discriminated union emitted to catch-all endpoint subscribers. */
export type Minip2pEvent = {
  [Kind in keyof Minip2pCatchAllEventMap]: {
    readonly type: Kind;
  } & Minip2pCatchAllEventMap[Kind];
}[keyof Minip2pCatchAllEventMap];

/** Timeout and cancellation controls shared by Promise-based operations. */
export interface OpOptions {
  /** Timeout in milliseconds; `0` disables the timeout. */
  readonly timeoutMs?: number;
  /** Abort signal that cancels only this caller's wait. */
  readonly signal?: AbortSignal;
}

/**
 * Where one Connection attempt goes:
 *
 * - a base58 peer ID, which applies the endpoint's discovery and relay policy;
 * - one complete peer multiaddress ending in `/p2p/<peer>`, as advertised;
 * - a non-empty list of complete peer multiaddresses that all name one peer.
 *
 * A string starting with `/` is an address; any other string is a peer ID.
 * Address family and transport come from the addresses themselves.
 */
export type ConnectTarget = string | readonly [string, ...string[]];

/**
 * Wait controls for a Connection attempt.
 *
 * `timeoutMs` bounds only the local wait: the attempt keeps running, and a
 * later {@link Minip2pBase.waitConnectResult} on its
 * {@link Minip2pBase.startConnect} ID can still consume its terminal outcome.
 * Aborting `signal` cancels the attempt, and the wait then settles from its
 * terminal: `ConnectCancelledError`, or the real outcome if cancellation
 * raced an attempt that had already settled.
 */
export interface ConnectOptions extends OpOptions {
  /** Also cancel the attempt when `timeoutMs` elapses. Defaults to `false`. */
  readonly cancelOnTimeout?: boolean;
}

/** The transport connection currently selected for a peer. */
export interface ConnectionInfo {
  /** Endpoint-local connection identifier, as carried by connection events. */
  readonly connId: number;
  /** Remote transport address, when known. */
  readonly remoteAddr?: string;
  /**
   * Protocols this connection advertised, once it is ready; absent until
   * then. Readiness, `connId` and protocols come from one native snapshot.
   */
  readonly readyProtocols?: readonly string[];
}

/** Options accepted by {@link Minip2pBase.once}. */
export type OnceOptions = OpOptions;

/** Options accepted by {@link Minip2pBase.waitFor}. */
export interface WaitForOptions<Event> extends OpOptions {
  /** Optional filter applied before resolving the waiter. */
  readonly predicate?: (event: Event) => boolean;
}

/** Controls one endpoint event iterator. */
export interface EventsOptions {
  /** Ends iteration without throwing when aborted. */
  readonly signal?: AbortSignal;
  /** Maximum events buffered for this iterator. */
  readonly bufferCap?: number;
}

/** First usable path produced by a connection attempt. */
export interface ConnectResult {
  readonly connectId: number;
  readonly peerId: string;
  readonly path: Path;
}

/** How the native close drain ended. */
export const CloseOutcome = {
  /** The close deadline passed with connections still tracked. */
  DeadlineExpired: "DeadlineExpired",
  /** Every tracked connection finished its teardown in time. */
  Drained: "Drained",
  /** Driving the transports failed and ended the drain early. */
  Failed: "Failed",
} as const;
export type CloseOutcome = (typeof CloseOutcome)[keyof typeof CloseOutcome];

/** Why the endpoint stopped: the application closed it, or its driver failed. */
export type EndpointCloseReason = "close" | "driverFailed";

/**
 * What endpoint close observers receive once the native drain finished.
 * `unfinished` lists the peers whose connections were still tracked when it
 * ended (an inbound handshake that had not identified its peer is not
 * listed); empty means no tracked teardown remains, not that peers
 * acknowledged it. A failed driver tears down at once, so its report has no
 * `outcome`.
 */
export type EndpointCloseReport =
  | {
      readonly reason: "close";
      readonly outcome: CloseOutcome;
      readonly unfinished: readonly string[];
    }
  | {
      readonly reason: "driverFailed";
      readonly error: DriverFailedError;
      readonly unfinished: readonly string[];
    };

/** Idempotent callback that removes a subscription. */
export type Unsubscribe = () => void;

/** Raw backend-only path tags. */
export const PathKind_Tags = {
  DirectDialed: "DirectDialed",
  DirectPunched: "DirectPunched",
  Relayed: "Relayed",
} as const;
export type PathKindTag = (typeof PathKind_Tags)[keyof typeof PathKind_Tags];
export type PathKind =
  | { readonly tag: typeof PathKind_Tags.DirectDialed }
  | { readonly tag: typeof PathKind_Tags.DirectPunched }
  | {
      readonly tag: typeof PathKind_Tags.Relayed;
      readonly inner: { readonly relayPeerId: string };
    };

/** Raw backend-only connection close reason tags. */
export const ConnectionCloseReason_Tags = {
  Error: "Error",
  Local: "Local",
  Remote: "Remote",
  Stalled: "Stalled",
  TimedOut: "TimedOut",
} as const;
export type RawConnectionCloseReason =
  | { readonly tag: typeof ConnectionCloseReason_Tags.Local }
  | {
      readonly tag: typeof ConnectionCloseReason_Tags.Remote;
      readonly inner: { readonly code: bigint };
    }
  | { readonly tag: typeof ConnectionCloseReason_Tags.TimedOut }
  | { readonly tag: typeof ConnectionCloseReason_Tags.Stalled }
  | {
      readonly tag: typeof ConnectionCloseReason_Tags.Error;
      readonly inner: { readonly message: string };
    };

/** Raw backend-only event tags. */
export const P2pEvent_Tags = {
  ConnectCancelled: "ConnectCancelled",
  ConnectFailed: "ConnectFailed",
  ConnectionClosed: "ConnectionClosed",
  ConnectionEstablished: "ConnectionEstablished",
  ConnectionReplaced: "ConnectionReplaced",
  DiscoveryDialFailed: "DiscoveryDialFailed",
  DiscoveryProtocolViolation: "DiscoveryProtocolViolation",
  DriverFailed: "DriverFailed",
  EndpointClosed: "EndpointClosed",
  EndpointError: "EndpointError",
  EventsDropped: "EventsDropped",
  GossipsubOutboundFailure: "GossipsubOutboundFailure",
  GossipsubProtocolViolation: "GossipsubProtocolViolation",
  HolePunchFailed: "HolePunchFailed",
  IdentifyReceived: "IdentifyReceived",
  InboundDirectUpgrade: "InboundDirectUpgrade",
  InboundPathEstablished: "InboundPathEstablished",
  MdnsFailed: "MdnsFailed",
  MdnsRecovered: "MdnsRecovered",
  Message: "Message",
  PathEstablished: "PathEstablished",
  PathUpgraded: "PathUpgraded",
  PeerDiscovered: "PeerDiscovered",
  PeerExpired: "PeerExpired",
  PeerReady: "PeerReady",
  PeerSubscribed: "PeerSubscribed",
  PeerUnsubscribed: "PeerUnsubscribed",
  PeerUpdated: "PeerUpdated",
  PingRttMeasured: "PingRttMeasured",
  PingTimeout: "PingTimeout",
  PublicAddressesChanged: "PublicAddressesChanged",
  ReachabilityChanged: "ReachabilityChanged",
  RelayReservationLost: "RelayReservationLost",
  RelayReserved: "RelayReserved",
  StreamClosed: "StreamClosed",
  StreamData: "StreamData",
  StreamReady: "StreamReady",
  StreamRemoteWriteClosed: "StreamRemoteWriteClosed",
  StreamWriteAccepted: "StreamWriteAccepted",
  StreamWriteStopped: "StreamWriteStopped",
} as const;
export type P2pEventTag = (typeof P2pEvent_Tags)[keyof typeof P2pEvent_Tags];

interface RawEvent<Tag extends P2pEventTag, Inner> {
  readonly tag: Tag;
  readonly inner: Readonly<Inner>;
}

export type P2pEvent =
  | RawEvent<
      typeof P2pEvent_Tags.EventsDropped,
      {
        dropped: number;
        totalDropped: number;
        terminalConnectIds: number[];
      }
    >
  | RawEvent<
      typeof P2pEvent_Tags.DriverFailed,
      { kind: DriverFailureKind; detail: string }
    >
  | RawEvent<
      typeof P2pEvent_Tags.EndpointClosed,
      {
        outcome: CloseOutcome;
        unfinished: { connId: number; peerId?: string }[];
      }
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectionEstablished,
      { peerId: string; connId: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectionClosed,
      { peerId: string; connId: number; reason: RawConnectionCloseReason }
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectionReplaced,
      Minip2pNamedEventMap["connectionReplaced"]
    >
  | RawEvent<typeof P2pEvent_Tags.PeerReady, Minip2pNamedEventMap["peerReady"]>
  | RawEvent<
      typeof P2pEvent_Tags.IdentifyReceived,
      Minip2pNamedEventMap["identifyReceived"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PingRttMeasured,
      Minip2pNamedEventMap["pingRttMeasured"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PingTimeout,
      Minip2pNamedEventMap["pingTimeout"]
    >
  | RawEvent<typeof P2pEvent_Tags.StreamReady, InboundStreamMeta>
  | RawEvent<
      typeof P2pEvent_Tags.StreamData,
      { peerId: string; connId: number; streamId: number; data: ArrayBuffer }
    >
  | RawEvent<
      typeof P2pEvent_Tags.StreamRemoteWriteClosed,
      { peerId: string; connId: number; streamId: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.StreamWriteAccepted,
      { peerId: string; connId: number; streamId: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.StreamWriteStopped,
      { peerId: string; connId: number; streamId: number; errorCode: bigint }
    >
  | RawEvent<
      typeof P2pEvent_Tags.StreamClosed,
      { peerId: string; connId: number; streamId: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.EndpointError,
      Minip2pNamedEventMap["endpointError"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.ReachabilityChanged,
      Minip2pNamedEventMap["reachabilityChanged"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PublicAddressesChanged,
      Minip2pNamedEventMap["publicAddressesChanged"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.RelayReserved,
      Minip2pNamedEventMap["relayReserved"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.RelayReservationLost,
      Minip2pNamedEventMap["relayReservationLost"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PathEstablished,
      { connectId: number; peerId: string; connId: number; path: PathKind }
    >
  | RawEvent<
      typeof P2pEvent_Tags.InboundPathEstablished,
      { peerId: string; path: PathKind; connId: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.PathUpgraded,
      {
        connectId: number;
        peerId: string;
        from: PathKind;
        to: PathKind;
        oldConnId: number;
        newConnId: number;
      }
    >
  | RawEvent<
      typeof P2pEvent_Tags.HolePunchFailed,
      Minip2pNamedEventMap["holePunchFailed"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectFailed,
      Minip2pNamedEventMap["connectFailed"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectCancelled,
      Minip2pNamedEventMap["connectCancelled"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.InboundDirectUpgrade,
      Minip2pNamedEventMap["inboundDirectUpgrade"]
    >
  | RawEvent<typeof P2pEvent_Tags.Message, Minip2pNamedEventMap["message"]>
  | RawEvent<
      typeof P2pEvent_Tags.PeerSubscribed,
      Minip2pNamedEventMap["peerSubscribed"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PeerUnsubscribed,
      Minip2pNamedEventMap["peerUnsubscribed"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.GossipsubOutboundFailure,
      Minip2pNamedEventMap["gossipsubOutboundFailure"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.GossipsubProtocolViolation,
      Minip2pNamedEventMap["gossipsubProtocolViolation"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PeerDiscovered,
      Minip2pNamedEventMap["peerDiscovered"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PeerUpdated,
      Minip2pNamedEventMap["peerUpdated"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PeerExpired,
      Minip2pNamedEventMap["peerExpired"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.DiscoveryDialFailed,
      Minip2pNamedEventMap["discoveryDialFailed"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.MdnsFailed,
      Minip2pNamedEventMap["mdnsFailed"]
    >
  // A variant without fields has no `inner`, as both runtimes deliver it.
  | { readonly tag: typeof P2pEvent_Tags.MdnsRecovered }
  | RawEvent<
      typeof P2pEvent_Tags.DiscoveryProtocolViolation,
      Minip2pNamedEventMap["discoveryProtocolViolation"]
    >;

export type P2pEventByTag<Tag extends P2pEventTag> = Extract<
  P2pEvent,
  { readonly tag: Tag }
>;
