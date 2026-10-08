import {
  BackpressureError,
  MessageTooLargeError,
  NotPermittedError,
} from "./errors.js";
import type {
  Bytes,
  ConnectionInfo,
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
 * A Connection target already shaped by the SDK. Native adapters translate it
 * into their toolchain's target type; the FFI core validates it.
 */
export type BackendConnectTarget =
  | { readonly kind: "peer"; readonly peerId: string }
  | { readonly kind: "addresses"; readonly addresses: readonly string[] };

/**
 * Native endpoint contract consumed by {@link Minip2pBase}.
 *
 * Platform packages implement this interface; application code normally uses
 * the high-level endpoint instead.
 */
export interface Minip2pBackend {
  /** Starts native event delivery exactly once. */
  start: (listener: (event: P2pEvent) => void) => void;
  /** Releases adapter state retained until an event has been dispatched. */
  eventHandled?: (event: P2pEvent) => void;
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
  /** Returns the transport connection selected for a peer. */
  connectionInfo: (peerId: string) => ConnectionInfo | undefined;
  /** Builds a circuit address through a relay. */
  circuitAddress: (relayAddress: string, peerId: string) => string;
  /** Returns the native reachability state. */
  reachability: () => Reachability;
  /** Returns whether the driver accepts work. */
  isRunning: () => boolean;
  /** Accepted for compatibility; has no effect, since the driver sleeps until the endpoint's next deadline. */
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
  /**
   * Sends bytes on an application stream. Returns `true` once native
   * accepted every byte, or `false` when native holds the rest and a
   * `StreamWriteAccepted` event follows once it is accepted; until then the
   * stream takes no other write. Every stream operation names the stream by
   * connection too; one whose connection is no longer the peer's throws
   * instead of reaching a stream on a newer connection.
   */
  sendStream: (
    peerId: string,
    connId: number,
    streamId: number,
    data: Uint8Array
  ) => boolean;
  /**
   * Returns the function that acknowledges a stream's received bytes as
   * consumed, replenishing its receive budget so the sender can continue
   * (ADR 0012). Every registered protocol takes manual acknowledgement, so
   * a reader that stops consuming stalls its sender.
   *
   * Called once, when the stream becomes ready; the returned function keeps
   * naming that stream after its terminal event retires the public IDs. It
   * throws on an over-acknowledgement and is a no-op once the stream or its
   * connection is gone.
   */
  streamConsumer: (connId: number, streamId: number) => (bytes: number) => void;
  /** Half-closes the local stream write side, after any pending write. */
  closeStreamWrite: (peerId: string, connId: number, streamId: number) => void;
  /** Abruptly resets a stream. */
  resetStream: (peerId: string, connId: number, streamId: number) => void;
  /** Resets and relinquishes a stream. */
  abandonStream: (peerId: string, connId: number, streamId: number) => void;
  /** Starts one Connection attempt and returns its Connect ID. */
  connect: (target: BackendConnectTarget) => number;
  /** Cancels a Connection attempt; its terminal event still follows. */
  cancelConnect: (id: number) => void;
  /** Closes the active connection to a peer. */
  disconnect: (peerId: string) => void;
}

export { resolveEndpointConfig, type BackendEndpointConfig } from "./config.js";
export { EventDrain } from "./event-drain.js";
export { ConnectionIdMap, u64ToNumber } from "./native-ids.js";
export {
  P2pEvent_Tags,
  PathKind_Tags,
  type P2pEvent,
  type P2pEventByTag,
  type PathKind,
} from "./types.js";

/**
 * Returns the typed SDK error for a native `FfiError` variant name, or
 * `undefined` for variants that adapters rethrow unchanged. `detail` is the
 * variant's detail field, when it has one.
 */
export const typedFfiError = (
  tag: string | undefined,
  detail: string | undefined
): Error | undefined => {
  switch (tag) {
    case "Backpressure": {
      return new BackpressureError();
    }
    case "MessageTooLarge": {
      return new MessageTooLargeError();
    }
    case "NotPermitted": {
      return new NotPermittedError(detail);
    }
    default: {
      return undefined;
    }
  }
};

/** Platform implementation used to construct endpoints and identity helpers. */
export interface Minip2pBackendFactory {
  create: (config: Minip2pConfig) => Minip2pBackend;
  generateSecretKey: () => Uint8Array;
  peerIdFromSecretKey: (secretKey: Bytes) => string;
  circuitAddress: (relayAddress: string, peerId: string) => string;
}
