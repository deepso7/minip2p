import {
  BackpressureError,
  InvalidConfigError,
  MessageTooLargeError,
  NotPermittedError,
} from "./errors.js";
import { CloseOutcome, ConfigCapability } from "./types.js";
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

/** How the native endpoint's close drain ended (`EndpointClosed`). */
export interface BackendClosed {
  readonly outcome: CloseOutcome;
  /** Peers whose connections were still tracked, each once. */
  readonly unfinished: readonly string[];
}

/**
 * The peers `EndpointClosed`'s unfinished connections name, each once. An
 * inbound handshake that had not identified its peer names none.
 */
export const unfinishedPeers = (
  unfinished: readonly { readonly peerId?: string | undefined }[]
): string[] => [
  ...new Set(
    unfinished.flatMap(({ peerId }) => (peerId === undefined ? [] : [peerId]))
  ),
];

/**
 * A native adapter's side of {@link Minip2pBackend.close}: stops native once,
 * then resolves with the native `EndpointClosed` the adapter hands to
 * {@link settle}, or at once when no driver started.
 */
export class NativeCloseLatch {
  readonly #closed: Promise<BackendClosed>;
  #resolve: ((closed: BackendClosed) => void) | undefined;
  #closing: Promise<BackendClosed> | undefined;

  constructor() {
    // oxlint-disable-next-line promise/avoid-new -- Settled by a native event, not a callback API.
    this.#closed = new Promise((resolve) => {
      this.#resolve = resolve;
    });
  }

  /** Whether `close` was called; later native events can be ignored. */
  get requested(): boolean {
    return this.#closing !== undefined;
  }

  /** Records the native `EndpointClosed`, which may precede `close`. */
  settle(closed: BackendClosed): void {
    this.#resolve?.(closed);
  }

  /**
   * Runs `stop` on the first call, then resolves once native closed and
   * `release`, if any, ran. Later calls return the same promise.
   */
  close(
    started: boolean,
    stop: () => void,
    release?: () => void
  ): Promise<BackendClosed> {
    this.#closing ??= this.#finish(started, stop, release);
    return this.#closing;
  }

  async #finish(
    started: boolean,
    stop: () => void,
    release: (() => void) | undefined
  ): Promise<BackendClosed> {
    stop();
    // Without a driver, native released the endpoint at once.
    const closed = started
      ? await this.#closed
      : { outcome: CloseOutcome.Drained, unfinished: [] };
    try {
      release?.();
    } catch {
      // The endpoint is closed either way; the report still stands.
    }
    return closed;
  }
}

/** A native connection snapshot: {@link ConnectionInfo} with the raw path. */
export interface BackendConnectionInfo extends Omit<ConnectionInfo, "path"> {
  readonly path: PathKind;
}

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
  /**
   * Releases adapter state retained until an event has been dispatched,
   * elided, dropped, or coalesced into an earlier one.
   */
  eventHandled?: (event: P2pEvent) => void;
  /**
   * Requests native shutdown, draining for up to `timeoutMs` (`0` tears down
   * at once), and resolves with the native `EndpointClosed`, the driver's
   * last event, once the native endpoint is released. Idempotent: later
   * calls return the same promise and their timeout is ignored. Resolves at
   * once for a backend whose `start` failed. Never rejects.
   */
  close: (timeoutMs: number) => Promise<BackendClosed>;
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
  /** Returns the path of a peer's established connection. */
  path: (peerId: string) => PathKind | undefined;
  /** Returns a snapshot of a peer's established connection. */
  connectionInfo: (peerId: string) => BackendConnectionInfo | undefined;
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
   * its connection and stream IDs; one whose connection closed or was
   * replaced throws instead of reaching a stream on a newer connection.
   */
  sendStream: (connId: number, streamId: number, data: Uint8Array) => boolean;
  /**
   * Returns the function that acknowledges a stream's received bytes as
   * consumed, replenishing its receive budget so the sender can continue
   * (ADR 0012). Every registered protocol takes manual acknowledgement, so
   * a reader that stops consuming stalls its sender.
   *
   * Called once, when the stream becomes ready; the returned function keeps
   * naming that stream after its terminal event retires the public IDs. It
   * throws on an over-acknowledgement and is a no-op once the stream is
   * settled. Unacknowledged bytes hold their ended connection's native slot,
   * so this, and `abandonStream`, must still reach native for a stream whose
   * connection ended while its events were in flight (see `SettleHandles`).
   */
  streamConsumer: (connId: number, streamId: number) => (bytes: number) => void;
  /** Half-closes the local stream write side, after any pending write. */
  closeStreamWrite: (connId: number, streamId: number) => void;
  /** Abruptly resets a stream. */
  resetStream: (connId: number, streamId: number) => void;
  /** Resets and relinquishes a stream. */
  abandonStream: (connId: number, streamId: number) => void;
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
export { SettleHandles, eventStream } from "./settle-handles.js";
export {
  ConnectionCloseReason_Tags,
  P2pEvent_Tags,
  PathKind_Tags,
  type P2pEvent,
  type P2pEventByTag,
  type PathKind,
  type RawConnectionCloseReason,
} from "./types.js";

/**
 * The parts of a native `FfiError` an adapter reads off its toolchain's error
 * value: the variant name, its detail field, and an `InvalidConfig`'s
 * capability as its Rust variant name.
 */
export interface NativeErrorFields {
  readonly tag?: string | undefined;
  readonly detail?: string | undefined;
  readonly capability?: string | undefined;
}

// Each capability's name is its value, so an own key is a capability.
const isConfigCapability = (name: string): name is ConfigCapability =>
  Object.hasOwn(ConfigCapability, name);

/**
 * Returns the typed SDK error for a native `FfiError`, or `undefined` for
 * variants that adapters rethrow unchanged. An `InvalidConfig` whose
 * capability is missing or unknown (native and SDK versions out of step)
 * is rethrown unchanged too, rather than given a capability it did not name.
 */
export const typedFfiError = ({
  capability,
  detail,
  tag,
}: NativeErrorFields): Error | undefined => {
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
    case "InvalidConfig": {
      return capability !== undefined && isConfigCapability(capability)
        ? new InvalidConfigError(capability, detail ?? "")
        : undefined;
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
