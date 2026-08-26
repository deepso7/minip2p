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
  /** Socket polling interval used by the native driver. */
  readonly socketPollIntervalMs?: number;
  /** Whether newly discovered peers should be dialed automatically. */
  readonly autoDial?: boolean;
}

/** Available pubsub routing strategies. */
export const PubsubRouter = {
  Floodsub: 1,
  Gossipsub: 0,
} as const;
export type PubsubRouter = (typeof PubsubRouter)[keyof typeof PubsubRouter];

/** Coarse local reachability states. */
export const Reachability = {
  Private: 2,
  Public: 1,
  Unknown: 0,
} as const;
export type Reachability = (typeof Reachability)[keyof typeof Reachability];

/** Sources contributing peer-discovery observations. */
export const DiscoverySource = {
  Mdns: 1,
  SignedBeacon: 0,
} as const;
export type DiscoverySource =
  (typeof DiscoverySource)[keyof typeof DiscoverySource];

/** Fatal native-driver failure categories. */
export const DriverFailureKind = {
  Invariant: 2,
  Panic: 3,
  Swarm: 1,
  Transport: 0,
} as const;
export type DriverFailureKind =
  (typeof DriverFailureKind)[keyof typeof DriverFailureKind];

/** Non-fatal endpoint runtime error categories. */
export const EndpointErrorKind = {
  Driver: 7,
  Identify: 2,
  IdentifyStreamRejected: 4,
  Multistream: 1,
  OpenStreamFailed: 5,
  Ping: 3,
  Transport: 0,
  UnsupportedProtocol: 6,
} as const;
export type EndpointErrorKind =
  (typeof EndpointErrorKind)[keyof typeof EndpointErrorKind];

/** Terminal NAT connection failure categories. */
export const NatErrorKind = {
  DialFailed: 2,
  NoPathAvailable: 0,
  Protocol: 3,
  RelayRefused: 4,
  Timeout: 1,
} as const;
export type NatErrorKind = (typeof NatErrorKind)[keyof typeof NatErrorKind];

/** Listen configuration for one enabled transport. */
export interface Minip2pTransportOptions {
  /** Exact listen multiaddresses. Omit to listen on IPv4 and IPv6 defaults. */
  readonly listen?: readonly [string, ...string[]];
}

/** Transports enabled by an endpoint. */
export interface Minip2pTransports {
  /** Enables QUIC with defaults or explicit options. */
  readonly quic?: true | Minip2pTransportOptions;
  /** Enables TCP with defaults or explicit options. */
  readonly tcp?: true | Minip2pTransportOptions;
}

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
  /** Enabled transports. Defaults to dual-stack QUIC only. */
  readonly transports?: Minip2pTransports;
  /** Routes outbound connectivity through relays only. */
  readonly forceRelay?: boolean;
  /** Accepts unsigned pubsub messages. */
  readonly allowUnsigned?: boolean;
  /** Pubsub router to enable. */
  readonly pubsubRouter?: PubsubRouter;
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
  eventsDropped: { readonly dropped: number; readonly totalDropped: number };
  driverFailed: {
    readonly kind: DriverFailureKind;
    readonly detail: string;
  };
  connectionEstablished: { readonly peerId: string; readonly connId: number };
  connectionClosed: { readonly peerId: string; readonly connId: number };
  peerReady: { readonly peerId: string; readonly protocols: readonly string[] };
  identifyReceived: { readonly peerId: string; readonly info: IdentifyInfo };
  pingRttMeasured: { readonly peerId: string; readonly rttMs: number };
  pingTimeout: { readonly peerId: string };
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
    readonly path: Path;
  };
  inboundPathEstablished: {
    readonly peerId: string;
    readonly path: Path;
  };
  pathUpgraded: {
    readonly connectId: number;
    readonly peerId: string;
    readonly from: Path;
    readonly to: Path;
  };
  holePunchFailed: {
    readonly connectId: number;
    readonly attempt: number;
    readonly reason: string;
  };
  fellBackToRelay: { readonly connectId: number; readonly peerId: string };
  connectFailed: {
    readonly connectId: number;
    readonly peerId: string;
    readonly kind: NatErrorKind;
    readonly detail: string;
  };
  inboundDirectUpgrade: { readonly peerId: string };
  message: {
    readonly fromPeerId: string;
    readonly topics: readonly string[];
    readonly data: ArrayBuffer;
    readonly seqno: ArrayBuffer;
    readonly signed: boolean;
  };
  peerSubscribed: { readonly peerId: string; readonly topic: string };
  peerUnsubscribed: { readonly peerId: string; readonly topic: string };
  pubsubOutboundFailure: { readonly peerId: string; readonly reason: string };
  pubsubProtocolViolation: { readonly peerId: string; readonly reason: string };
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

/** Reason reported to endpoint close observers. */
export type CloseReason =
  | { readonly reason: "close" }
  | {
      readonly reason: "driverFailed";
      readonly error: DriverFailedError;
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

/** Raw backend-only event tags. */
export const P2pEvent_Tags = {
  ConnectFailed: "ConnectFailed",
  ConnectionClosed: "ConnectionClosed",
  ConnectionEstablished: "ConnectionEstablished",
  DiscoveryDialFailed: "DiscoveryDialFailed",
  DiscoveryProtocolViolation: "DiscoveryProtocolViolation",
  DriverFailed: "DriverFailed",
  EndpointError: "EndpointError",
  EventsDropped: "EventsDropped",
  FellBackToRelay: "FellBackToRelay",
  HolePunchFailed: "HolePunchFailed",
  IdentifyReceived: "IdentifyReceived",
  InboundDirectUpgrade: "InboundDirectUpgrade",
  InboundPathEstablished: "InboundPathEstablished",
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
  PubsubOutboundFailure: "PubsubOutboundFailure",
  PubsubProtocolViolation: "PubsubProtocolViolation",
  ReachabilityChanged: "ReachabilityChanged",
  RelayReservationLost: "RelayReservationLost",
  RelayReserved: "RelayReserved",
  StreamClosed: "StreamClosed",
  StreamData: "StreamData",
  StreamReady: "StreamReady",
  StreamRemoteWriteClosed: "StreamRemoteWriteClosed",
} as const;
export type P2pEventTag = (typeof P2pEvent_Tags)[keyof typeof P2pEvent_Tags];

interface RawEvent<Tag extends P2pEventTag, Inner> {
  readonly tag: Tag;
  readonly inner: Readonly<Inner>;
}

export type P2pEvent =
  | RawEvent<
      typeof P2pEvent_Tags.EventsDropped,
      { dropped: number; totalDropped: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.DriverFailed,
      { kind: DriverFailureKind; detail: string }
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectionEstablished,
      { peerId: string; connId: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectionClosed,
      { peerId: string; connId: number }
    >
  | RawEvent<
      typeof P2pEvent_Tags.PeerReady,
      { peerId: string; protocols: readonly string[] }
    >
  | RawEvent<
      typeof P2pEvent_Tags.IdentifyReceived,
      { peerId: string; info: IdentifyInfo }
    >
  | RawEvent<
      typeof P2pEvent_Tags.PingRttMeasured,
      { peerId: string; rttMs: number }
    >
  | RawEvent<typeof P2pEvent_Tags.PingTimeout, { peerId: string }>
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
      { connectId: number; peerId: string; path: PathKind }
    >
  | RawEvent<
      typeof P2pEvent_Tags.InboundPathEstablished,
      { peerId: string; path: PathKind }
    >
  | RawEvent<
      typeof P2pEvent_Tags.PathUpgraded,
      { connectId: number; peerId: string; from: PathKind; to: PathKind }
    >
  | RawEvent<
      typeof P2pEvent_Tags.HolePunchFailed,
      Minip2pNamedEventMap["holePunchFailed"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.FellBackToRelay,
      Minip2pNamedEventMap["fellBackToRelay"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.ConnectFailed,
      Minip2pNamedEventMap["connectFailed"]
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
      typeof P2pEvent_Tags.PubsubOutboundFailure,
      Minip2pNamedEventMap["pubsubOutboundFailure"]
    >
  | RawEvent<
      typeof P2pEvent_Tags.PubsubProtocolViolation,
      Minip2pNamedEventMap["pubsubProtocolViolation"]
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
      typeof P2pEvent_Tags.DiscoveryProtocolViolation,
      Minip2pNamedEventMap["discoveryProtocolViolation"]
    >;

export type P2pEventByTag<Tag extends P2pEventTag> = Extract<
  P2pEvent,
  { readonly tag: Tag }
>;
