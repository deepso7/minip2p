/** Bytes accepted by the platform-neutral SDK. */
export type Bytes = ArrayBuffer | Uint8Array;

/** Signed-discovery settings. */
export interface MiniP2pDiscoveryOptions {
  /** Pubsub topic carrying signed discovery beacons. */
  readonly topic: string;
  /** Milliseconds between local beacon announcements. */
  readonly beaconIntervalMs: number;
  /** Milliseconds before a signed peer observation expires. */
  readonly peerTtlMs: number;
  /** Whether accepted observations may trigger automatic dials. */
  readonly autoDial: boolean;
}

/** Configuration accepted by a platform minip2p endpoint. */
export interface MiniP2pConfig {
  /** Raw 32-byte Ed25519 secret key material. */
  readonly secretKey: Bytes;
  /** Identify agent version, or the native default when absent. */
  readonly agentVersion?: string;
  /** Direct QUIC relay peer addresses. */
  readonly relays: readonly string[];
  /** QUIC listen multiaddress, or dual-stack wildcard binding when absent. */
  readonly listenAddr?: string;
  /** Whether connection attempts must remain relayed. */
  readonly forceRelay: boolean;
  /** Whether unsigned pubsub messages are accepted. */
  readonly allowUnsigned: boolean;
  /** Signed-discovery settings, or no discovery when absent. */
  readonly discovery?: MiniP2pDiscoveryOptions;
}

/** Coarse local reachability state. */
export enum Reachability {
  Unknown = 0,
  Public = 1,
  Private = 2,
}

/** Source that contributed a discovery observation. */
export enum DiscoverySource {
  SignedBeacon = 0,
  Mdns = 1,
}

/** Category of a fatal background-driver failure. */
export enum DriverFailureKind {
  Transport = 0,
  Swarm = 1,
  Invariant = 2,
  Panic = 3,
}

/** Category of a non-fatal endpoint runtime error. */
export enum EndpointErrorKind {
  Transport = 0,
  Multistream = 1,
  Identify = 2,
  Ping = 3,
  IdentifyStreamRejected = 4,
  OpenStreamFailed = 5,
  UnsupportedProtocol = 6,
  Driver = 7,
}

/** Category of a failed NAT connection attempt. */
export enum NatErrorKind {
  NoPathAvailable = 0,
  Timeout = 1,
  DialFailed = 2,
  Protocol = 3,
  RelayRefused = 4,
}

/** Tags for a usable connection path. */
export enum PathKind_Tags {
  DirectDialed = "DirectDialed",
  DirectPunched = "DirectPunched",
  Relayed = "Relayed",
}

/** Kind of usable connection path. */
export type PathKind =
  | { readonly tag: PathKind_Tags.DirectDialed }
  | { readonly tag: PathKind_Tags.DirectPunched }
  | {
      readonly tag: PathKind_Tags.Relayed;
      readonly inner: { readonly relayPeerId: string };
    };

/** Tags for events delivered by a minip2p endpoint. */
export enum P2pEvent_Tags {
  EventsDropped = "EventsDropped",
  DriverFailed = "DriverFailed",
  ConnectionEstablished = "ConnectionEstablished",
  ConnectionClosed = "ConnectionClosed",
  PeerReady = "PeerReady",
  PingRttMeasured = "PingRttMeasured",
  PingTimeout = "PingTimeout",
  EndpointError = "EndpointError",
  ReachabilityChanged = "ReachabilityChanged",
  PublicAddressesChanged = "PublicAddressesChanged",
  RelayReserved = "RelayReserved",
  RelayReservationLost = "RelayReservationLost",
  PathEstablished = "PathEstablished",
  PathUpgraded = "PathUpgraded",
  HolePunchFailed = "HolePunchFailed",
  FellBackToRelay = "FellBackToRelay",
  ConnectFailed = "ConnectFailed",
  InboundDirectUpgrade = "InboundDirectUpgrade",
  Message = "Message",
  PeerSubscribed = "PeerSubscribed",
  PeerUnsubscribed = "PeerUnsubscribed",
  PubsubOutboundFailure = "PubsubOutboundFailure",
  PubsubProtocolViolation = "PubsubProtocolViolation",
  PeerDiscovered = "PeerDiscovered",
  PeerUpdated = "PeerUpdated",
  PeerExpired = "PeerExpired",
  DiscoveryDialFailed = "DiscoveryDialFailed",
  DiscoveryProtocolViolation = "DiscoveryProtocolViolation",
}

interface Event<Tag extends P2pEvent_Tags, Inner> {
  readonly tag: Tag;
  readonly inner: Readonly<Inner>;
}

/** A platform-independent event emitted by the minip2p driver. */
export type P2pEvent =
  | Event<
      P2pEvent_Tags.EventsDropped,
      { dropped: number; totalDropped: number }
    >
  | Event<
      P2pEvent_Tags.DriverFailed,
      { kind: DriverFailureKind; detail: string }
    >
  | Event<
      P2pEvent_Tags.ConnectionEstablished,
      { peerId: string; connId: number }
    >
  | Event<P2pEvent_Tags.ConnectionClosed, { peerId: string; connId: number }>
  | Event<
      P2pEvent_Tags.PeerReady,
      { peerId: string; protocols: readonly string[] }
    >
  | Event<P2pEvent_Tags.PingRttMeasured, { peerId: string; rttMs: number }>
  | Event<P2pEvent_Tags.PingTimeout, { peerId: string }>
  | Event<
      P2pEvent_Tags.EndpointError,
      {
        kind: EndpointErrorKind;
        peerId?: string;
        connId?: number;
        detail: string;
      }
    >
  | Event<
      P2pEvent_Tags.ReachabilityChanged,
      {
        previous: Reachability;
        current: Reachability;
        confirmedAddrs: readonly string[];
      }
    >
  | Event<P2pEvent_Tags.PublicAddressesChanged, { addrs: readonly string[] }>
  | Event<
      P2pEvent_Tags.RelayReserved,
      { relayPeerId: string; expiresUnixSecs?: number }
    >
  | Event<P2pEvent_Tags.RelayReservationLost, { relayPeerId: string }>
  | Event<
      P2pEvent_Tags.PathEstablished,
      { connectId: number; peerId: string; path: PathKind }
    >
  | Event<
      P2pEvent_Tags.PathUpgraded,
      { connectId: number; peerId: string; from: PathKind; to: PathKind }
    >
  | Event<
      P2pEvent_Tags.HolePunchFailed,
      { connectId: number; attempt: number; reason: string }
    >
  | Event<P2pEvent_Tags.FellBackToRelay, { connectId: number; peerId: string }>
  | Event<
      P2pEvent_Tags.ConnectFailed,
      {
        connectId: number;
        peerId: string;
        kind: NatErrorKind;
        detail: string;
      }
    >
  | Event<P2pEvent_Tags.InboundDirectUpgrade, { peerId: string }>
  | Event<
      P2pEvent_Tags.Message,
      {
        fromPeerId: string;
        topics: readonly string[];
        data: ArrayBuffer;
        seqno: ArrayBuffer;
        signed: boolean;
      }
    >
  | Event<P2pEvent_Tags.PeerSubscribed, { peerId: string; topic: string }>
  | Event<P2pEvent_Tags.PeerUnsubscribed, { peerId: string; topic: string }>
  | Event<
      P2pEvent_Tags.PubsubOutboundFailure,
      { peerId: string; reason: string }
    >
  | Event<
      P2pEvent_Tags.PubsubProtocolViolation,
      { peerId: string; reason: string }
    >
  | Event<
      P2pEvent_Tags.PeerDiscovered,
      { peerId: string; addrs: readonly string[]; source: DiscoverySource }
    >
  | Event<
      P2pEvent_Tags.PeerUpdated,
      { peerId: string; addrs: readonly string[]; source: DiscoverySource }
    >
  | Event<P2pEvent_Tags.PeerExpired, { peerId: string }>
  | Event<P2pEvent_Tags.DiscoveryDialFailed, { peerId: string; reason: string }>
  | Event<
      P2pEvent_Tags.DiscoveryProtocolViolation,
      {
        peerId?: string;
        source: DiscoverySource;
        reason: string;
        suppressed: number;
      }
    >;

/** One peer in the shared discovery address book. */
export interface KnownPeerInfo {
  readonly peerId: string;
  readonly addrs: readonly string[];
  readonly beaconAddrs: readonly string[];
  readonly mdnsAddrs: readonly string[];
  readonly beaconLastSeenAgeMs?: number;
  readonly mdnsLastSeenAgeMs?: number;
  readonly connected: boolean;
}

/** Snapshot of the active inbound relay reservation. */
export interface RelayReservationInfo {
  readonly relayPeerId: string;
  readonly expiresUnixSecs?: number;
}

/** Host-side notification that the TypeScript event queue discarded events. */
export interface QueueOverflowEvent {
  readonly type: "queueOverflow";
  readonly dropped: number;
}

/** An event emitted by the high-level SDK. */
export type MiniP2pEvent = P2pEvent | QueueOverflowEvent;

/** Removes an event subscription. */
export type Unsubscribe = () => void;
