import type {
  Bytes,
  IdentifyInfo,
  KnownPeerInfo,
  Minip2pConfig,
  PathKind,
  P2pEvent,
  Reachability,
  RelayReservationInfo,
} from "./types.js";

/** Full native identity allocated for an outbound stream. */
export interface BackendOpenStream {
  /** Endpoint-local connection carrying the stream. */
  readonly connId: number;
  /** Endpoint-local transport stream identifier. */
  readonly streamId: number;
}

/**
 * Native endpoint contract consumed by {@link Minip2pBase}.
 *
 * Platform packages implement this interface; application code normally uses
 * the high-level endpoint instead.
 */
export interface Minip2pBackend {
  /** Starts native event delivery exactly once. */
  start: (listener: (event: P2pEvent) => void) => void;
  /** Idempotently releases the native endpoint. */
  close: () => void;
  /** Returns the local peer ID. */
  peerId: () => string;
  /** Returns bound peer multiaddresses. */
  listenAddrs: () => string[];
  /** Returns currently connected peer IDs. */
  connectedPeers: () => string[];
  /** Returns whether Identify completed for a peer. */
  isPeerReady: (peerId: string) => boolean;
  /** Returns the latest Identify snapshot. */
  peerInfo: (peerId: string) => IdentifyInfo | undefined;
  /** Returns the merged discovery address book. */
  knownPeers: () => KnownPeerInfo[];
  /** Returns the discovery clock when enabled. */
  discoveryNowMs: () => number | undefined;
  /** Returns the active relay reservation. */
  activeReservation: () => RelayReservationInfo | undefined;
  /** Returns the authoritative native path to a peer. */
  path: (peerId: string) => PathKind | undefined;
  /** Builds a circuit address through a relay. */
  circuitAddress: (relayAddress: string, peerId: string) => string;
  /** Returns the native reachability state. */
  reachability: () => Reachability;
  /** Returns whether the driver accepts work. */
  isRunning: () => boolean;
  /** Selects foreground or idle polling. */
  setActive: (active: boolean) => void;
  /** Subscribes to a pubsub topic. */
  subscribe: (topic: string) => boolean;
  /** Unsubscribes from a pubsub topic. */
  unsubscribe: (topic: string) => boolean;
  /** Publishes one binary pubsub message. */
  publish: (topic: string, data: Uint8Array) => void;
  /** Starts one native ping operation. */
  ping: (peerId: string) => void;
  /** Registers an application protocol. */
  addProtocol: (protocolId: string) => void;
  /** Starts opening and negotiating an application stream. */
  openStream: (peerId: string, protocolId: string) => BackendOpenStream;
  /** Sends bytes on an application stream. */
  sendStream: (peerId: string, streamId: number, data: Uint8Array) => void;
  /** Half-closes the local stream write side. */
  closeStreamWrite: (peerId: string, streamId: number) => void;
  /** Abruptly resets a stream. */
  resetStream: (peerId: string, streamId: number) => void;
  /** Resets and relinquishes a stream. */
  abandonStream: (peerId: string, streamId: number) => void;
  /** Starts a NAT-orchestrated connection attempt. */
  connect: (peerId: string) => number;
  /** Starts a connection attempt with explicit addresses. */
  connectWithAddrs: (peerId: string, addresses: readonly string[]) => number;
  /** Starts a connection attempt from one full peer address. */
  connectAddr: (address: string) => number;
  /** Starts direct dials for applicable address families. */
  dial: (address: string) => number[];
  /** Starts one direct IPv4 dial. */
  dialIp4: (address: string) => number;
  /** Starts one direct IPv6 dial. */
  dialIp6: (address: string) => number;
  /** Cancels a connection attempt. */
  cancelConnect: (id: number) => void;
  /** Closes the active connection to a peer. */
  disconnect: (peerId: string) => void;
}

export {
  P2pEvent_Tags,
  PathKind_Tags,
  type P2pEvent,
  type P2pEventByTag,
  type PathKind,
} from "./types.js";

/** Platform implementation used to construct endpoints and identity helpers. */
export interface Minip2pBackendFactory {
  create: (config: Minip2pConfig) => Minip2pBackend;
  generateSecretKey: () => Uint8Array;
  peerIdFromSecretKey: (secretKey: Bytes) => string;
  circuitAddress: (relayAddress: string, peerId: string) => string;
}
