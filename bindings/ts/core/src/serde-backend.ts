/* oxlint-disable class-methods-use-this, func-style, max-classes-per-file, max-lines, no-use-before-define -- The shared serde-shaped backend keeps the contract-complete native endpoint, value conversion, and handle maps together at the binding boundary. */

/**
 * The backend shared by the shells whose native endpoint hands values over
 * in `minip2p-ffi-core`'s serde shape: the Node addon (napi-rs) and the
 * browser's wasm module (wasm-bindgen). Each adapter supplies its native
 * endpoint and how to schedule event batches; ID mapping, value conversion,
 * stream settlement and error typing live here once.
 */

import { NativeCloseLatch, typedFfiError, unfinishedPeers } from "./backend.js";
import type {
  BackendClosed,
  BackendConnectionInfo,
  BackendConnectTarget,
  BackendOpenStream,
  Minip2pBackend,
} from "./backend.js";
import { StreamClosedError } from "./errors.js";
import { EventDrain } from "./event-drain.js";
import { ConnectionIdMap, u64ToNumber } from "./native-ids.js";
import { SettleHandles, eventStream } from "./settle-handles.js";
import { CloseOutcome, DriverFailureKind, P2pEvent_Tags } from "./types.js";
import type {
  IdentifyInfo,
  KnownPeerInfo,
  PathKind,
  P2pEvent,
  Reachability,
  RelayReservationInfo,
} from "./types.js";

/**
 * One SDK backend value as a serde shell encodes it: `u64` as a `number` or
 * a `bigint` (napi-rs switches above `u32::MAX`; wasm-bindgen always uses
 * `bigint`), and bytes as a `Uint8Array`.
 */
export type NativeShape<Value> = Value extends ArrayBuffer
  ? Uint8Array
  : Value extends number
    ? number | bigint
    : Value extends string | boolean
      ? Value
      : Value extends readonly (infer Item)[]
        ? readonly NativeShape<Item>[]
        : { readonly [Key in keyof Value]: NativeShape<Value[Key]> };

export type NativeEvent = NativeShape<P2pEvent>;
export type NativeIdentifyInfo = NativeShape<IdentifyInfo>;
export type NativeKnownPeerInfo = NativeShape<KnownPeerInfo>;
export type NativeRelayReservationInfo = NativeShape<RelayReservationInfo>;
export type NativeConnectionInfo = NativeShape<BackendConnectionInfo>;
export type NativeOpenStream = NativeShape<BackendOpenStream>;
export type NativePathKind = NativeShape<PathKind>;

/**
 * A native endpoint in the serde shape: the Node addon's `NodeEndpoint` and
 * the wasm module's `WebEndpoint` both have this surface. Absent values are
 * `null`; a failed call throws an `Error` tagged with the `FfiError`'s
 * `code`, `detail` and `capability`.
 */
export interface SerdeEndpoint {
  start: (doorbell: () => void) => void;
  close: (timeoutMs: number) => void;
  peerId: () => string;
  listenAddrs: () => string[];
  isRunning: () => boolean;
  drainEvents: (limit: number) => NativeEvent[];
  connectedPeers: () => string[];
  isPeerReady: (peerId: string) => boolean;
  peerInfo: (peerId: string) => NativeIdentifyInfo | null;
  setActive: (active: boolean) => void;
  subscribe: (topic: string) => boolean;
  unsubscribe: (topic: string) => boolean;
  publish: (topic: string, data: Uint8Array) => void;
  ping: (peerId: string) => void;
  addProtocol: (protocolId: string) => void;
  openStream: (peerId: string, protocolId: string) => NativeOpenStream;
  sendStream: (connId: bigint, streamId: bigint, data: Uint8Array) => boolean;
  closeStreamWrite: (connId: bigint, streamId: bigint) => void;
  resetStream: (connId: bigint, streamId: bigint) => void;
  abandonStream: (connId: bigint, streamId: bigint) => void;
  streamConsumed: (connId: bigint, streamId: bigint, bytes: number) => void;
  connect: (target: string | string[]) => bigint;
  cancelConnect: (id: bigint) => void;
  disconnect: (peerId: string) => void;
  path: (peerId: string) => NativePathKind | null;
  connectionInfo: (peerId: string) => NativeConnectionInfo | null;
  knownPeers: () => NativeKnownPeerInfo[];
  discoveryNowMs: () => bigint | null;
  reachability: () => Reachability;
  activeReservation: () => NativeRelayReservationInfo | null;
}

/** How one serde shell runs its native endpoint. */
export interface SerdeBackendOptions {
  /** Runs a native event batch on a later turn (see {@link EventDrain}). */
  readonly schedule: (task: () => void) => void;
  /**
   * Wraps every native call. The browser shell uses it to stop calling a
   * crashed wasm instance and to pump the endpoint after each command;
   * the default calls straight through.
   */
  readonly call?: <T>(operation: () => T) => T;
  /** The shell's circuit-address helper (a module function of its native). */
  readonly circuitAddress: (relayAddress: string, peerId: string) => string;
}

/** Native drain batch size. */
const DRAIN_LIMIT = 256;

/**
 * Runs a native call outside a backend (the endpoint constructor, the key
 * and address helpers), rethrowing a tagged `FfiError` as its typed SDK
 * error as the backend does for its own calls.
 */
export function typedNativeCall<T>(operation: () => T): T {
  return translateErrors(operation);
}

/** The {@link Minip2pBackend} over a {@link SerdeEndpoint}. */
export class SerdeBackend implements Minip2pBackend {
  readonly #connectionIds = new ConnectionIdMap();
  readonly #endpoint: SerdeEndpoint;
  readonly #options: SerdeBackendOptions;
  readonly #streamIds = new StreamIdMap();
  /** Native stream identities while their events are in flight (ADR 0012). */
  readonly #settleHandles = new SettleHandles<[bigint, bigint]>();
  readonly #close = new NativeCloseLatch();
  #events: EventDrain<NativeEvent> | undefined;
  #listener: ((event: P2pEvent) => void) | undefined;
  #failed = false;
  #started = false;

  constructor(endpoint: SerdeEndpoint, options: SerdeBackendOptions) {
    this.#endpoint = endpoint;
    this.#options = options;
  }

  start(listener: (event: P2pEvent) => void): void {
    this.#listener = listener;
    const events = new EventDrain(
      (limit) => this.#native((native) => native.drainEvents(limit)),
      (event: NativeEvent) => {
        if (event.tag === P2pEvent_Tags.EndpointClosed) {
          events.stop();
          this.#close.settle({
            outcome: event.inner.outcome,
            unfinished: unfinishedPeers(event.inner.unfinished),
          });
          return;
        }
        // The SDK has stopped listening; only `EndpointClosed` matters now.
        if (this.#close.requested) {
          return;
        }
        const normalized = normalizeEvent(
          event,
          this.#connectionIds,
          this.#streamIds
        );
        const stream = eventStream(normalized);
        const native = nativeStreamOf(event);
        if (stream !== undefined && native !== undefined) {
          this.#settleHandles.hold(stream.connId, stream.streamId, native);
        }
        listener(normalized);
      },
      DRAIN_LIMIT,
      this.#options.schedule
    );
    this.#events = events;
    this.#native((native) => {
      native.start(() => {
        events.ring();
      });
    });
    this.#started = true;
  }

  /**
   * Fails the endpoint without native's help, for a native instance that
   * can no longer run (a trapped wasm module): `DriverFailed` reaches the
   * SDK on a later turn and `close` resolves `Failed` without calling
   * native again. Idempotent; a no-op once `close` was requested.
   */
  fail(detail: string): void {
    if (this.#failed || this.#close.requested) {
      return;
    }
    this.#failed = true;
    this.#events?.stop();
    this.#close.settle({ outcome: CloseOutcome.Failed, unfinished: [] });
    const listener = this.#listener;
    if (listener !== undefined) {
      queueMicrotask(() => {
        listener({
          inner: { detail, kind: DriverFailureKind.Panic },
          tag: P2pEvent_Tags.DriverFailed,
        });
      });
    }
  }

  eventHandled(event: P2pEvent): void {
    releaseTerminalIds(event, this.#streamIds);
    const stream = eventStream(event);
    if (stream !== undefined) {
      this.#settleHandles.release(stream.connId, stream.streamId);
    }
  }

  close(timeoutMs: number): Promise<BackendClosed> {
    return this.#close.close(this.#started, () => {
      if (!this.#failed) {
        this.#native((native) => {
          native.close(timeoutMs);
        });
      }
    });
  }

  peerId(): string {
    return this.#native((native) => native.peerId());
  }

  listenAddrs(): string[] {
    return this.#native((native) => native.listenAddrs());
  }

  isRunning(): boolean {
    return !this.#failed && this.#native((native) => native.isRunning());
  }

  connectedPeers(): string[] {
    return this.#native((native) => native.connectedPeers());
  }

  isPeerReady(peerId: string): boolean {
    return this.#native((native) => native.isPeerReady(peerId));
  }

  peerInfo(peerId: string): IdentifyInfo | undefined {
    const info = this.#native((native) => native.peerInfo(peerId));
    return info === null ? undefined : identifyInfo(info);
  }

  knownPeers(): KnownPeerInfo[] {
    return this.#native((native) => native.knownPeers()).map(knownPeer);
  }

  discoveryNowMs(): number | undefined {
    const value = this.#native((native) => native.discoveryNowMs());
    return value === null ? undefined : u64ToNumber(value, "clock");
  }

  activeReservation(): RelayReservationInfo | undefined {
    const reservation = this.#native((native) => native.activeReservation());
    return reservation === null ? undefined : relayReservation(reservation);
  }

  path(peerId: string): PathKind | undefined {
    return this.#native((native) => native.path(peerId)) ?? undefined;
  }

  connectionInfo(peerId: string): BackendConnectionInfo | undefined {
    const info = this.#native((native) => native.connectionInfo(peerId));
    if (info === null) {
      return undefined;
    }
    const { connId, ...rest } = info;
    return {
      ...rest,
      connId: this.#connectionIds.toPublic(BigInt(connId)),
    };
  }

  circuitAddress(relayAddress: string, peerId: string): string {
    return this.#options.circuitAddress(relayAddress, peerId);
  }

  reachability(): Reachability {
    return this.#native((native) => native.reachability());
  }

  setActive(active: boolean): void {
    this.#native((native) => {
      native.setActive(active);
    });
  }

  subscribe(topic: string): boolean {
    return this.#native((native) => native.subscribe(topic));
  }

  unsubscribe(topic: string): boolean {
    return this.#native((native) => native.unsubscribe(topic));
  }

  publish(topic: string, data: Uint8Array): void {
    this.#native((native) => {
      native.publish(topic, data);
    });
  }

  ping(peerId: string): void {
    this.#native((native) => {
      native.ping(peerId);
    });
  }

  addProtocol(protocolId: string): void {
    this.#native((native) => {
      native.addProtocol(protocolId);
    });
  }

  openStream(peerId: string, protocolId: string): BackendOpenStream {
    const stream = this.#native((native) =>
      native.openStream(peerId, protocolId)
    );
    const connId = this.#connectionIds.toPublic(BigInt(stream.connId));
    return {
      connId,
      streamId: this.#streamIds.toPublic(connId, BigInt(stream.streamId)),
    };
  }

  sendStream(connId: number, streamId: number, data: Uint8Array): boolean {
    const [nativeConn, nativeStream] = this.#nativeStream(connId, streamId);
    return this.#native((native) =>
      native.sendStream(nativeConn, nativeStream, data)
    );
  }

  closeStreamWrite(connId: number, streamId: number): void {
    const [nativeConn, nativeStream] = this.#nativeStream(connId, streamId);
    this.#native((native) => {
      native.closeStreamWrite(nativeConn, nativeStream);
    });
  }

  resetStream(connId: number, streamId: number): void {
    const [nativeConn, nativeStream] = this.#nativeStream(connId, streamId);
    this.#native((native) => {
      native.resetStream(nativeConn, nativeStream);
    });
  }

  abandonStream(connId: number, streamId: number): void {
    const [nativeConn, nativeStream] = this.#settleStream(connId, streamId);
    this.#native((native) => {
      native.abandonStream(nativeConn, nativeStream);
    });
  }

  streamConsumer(connId: number, streamId: number): (bytes: number) => void {
    const [nativeConn, nativeStream] = this.#settleStream(connId, streamId);
    return (bytes) => {
      this.#native((native) => {
        native.streamConsumed(nativeConn, nativeStream, bytes);
      });
    };
  }

  // Connect IDs are not mapped because they round-trip into native calls,
  // and native allocates them well inside the safe integer range.
  connect(target: BackendConnectTarget): number {
    return u64ToNumber(
      this.#native((native) =>
        native.connect(
          target.kind === "peer" ? target.peerId : [...target.addresses]
        )
      ),
      "connectId"
    );
  }

  cancelConnect(id: number): void {
    this.#native((native) => {
      native.cancelConnect(BigInt(id));
    });
  }

  disconnect(peerId: string): void {
    this.#native((native) => {
      native.disconnect(peerId);
    });
  }

  /** Runs one native call through the shell's wrapper, typing its errors. */
  #native<T>(operation: (native: SerdeEndpoint) => T): T {
    const { call } = this.#options;
    const typed = (): T => translateErrors(() => operation(this.#endpoint));
    return call === undefined ? typed() : call(typed);
  }

  /**
   * Native connection and stream IDs for a public stream. Native names the
   * stream by both, so an operation for a connection that native already
   * replaced fails there instead of reaching a stream on the new connection.
   * A connection whose close or replacement this adapter has already drained
   * has no native ID, so the operation throws `StreamClosedError`.
   */
  #nativeStream(connId: number, streamId: number): [bigint, bigint] {
    return [
      this.#connectionIds.toNative(connId),
      this.#streamIds.toNative(streamId),
    ];
  }

  /**
   * Native IDs for settling a stream: acknowledging or abandoning its bytes.
   * Those still hold the native slot of a connection whose end this adapter
   * already drained, so a stream with events in flight resolves through its
   * settle handle once the live mapping is gone.
   */
  #settleStream(connId: number, streamId: number): [bigint, bigint] {
    try {
      return this.#nativeStream(connId, streamId);
    } catch (error) {
      const handle = this.#settleHandles.get(connId, streamId);
      if (handle === undefined) {
        throw error;
      }
      return handle;
    }
  }
}

/**
 * Rethrows a native `FfiError` as its typed SDK error. The shells tag each
 * error with the variant name as `code`, its detail field as `detail`, and
 * an `InvalidConfig`'s capability name as `capability`; untyped variants are
 * rethrown unchanged with those properties intact.
 */
function translateErrors<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    throw (
      typedFfiError({
        capability: stringProperty(error, "capability"),
        detail: stringProperty(error, "detail"),
        tag: stringProperty(error, "code"),
      }) ?? error
    );
  }
}

function stringProperty(value: unknown, key: string): string | undefined {
  if (value === null || typeof value !== "object") {
    return undefined;
  }
  const property: unknown = Reflect.get(value, key);
  return typeof property === "string" ? property : undefined;
}

/** Converts an Identify snapshot, copying its public key into an `ArrayBuffer`. */
function identifyInfo({
  publicKey,
  ...info
}: NativeIdentifyInfo): IdentifyInfo {
  return {
    ...info,
    ...(publicKey !== undefined && { publicKey: toArrayBuffer(publicKey) }),
  };
}

function knownPeer({
  beaconLastSeenAgeMs,
  mdnsLastSeenAgeMs,
  ...peer
}: NativeKnownPeerInfo): KnownPeerInfo {
  return {
    ...peer,
    ...(beaconLastSeenAgeMs !== undefined && {
      beaconLastSeenAgeMs: u64ToNumber(
        beaconLastSeenAgeMs,
        "beaconLastSeenAgeMs"
      ),
    }),
    ...(mdnsLastSeenAgeMs !== undefined && {
      mdnsLastSeenAgeMs: u64ToNumber(mdnsLastSeenAgeMs, "mdnsLastSeenAgeMs"),
    }),
  };
}

function relayReservation({
  expiresUnixSecs,
  relayPeerId,
}: NativeRelayReservationInfo): RelayReservationInfo {
  return {
    relayPeerId,
    ...(expiresUnixSecs !== undefined && {
      expiresUnixSecs: u64ToNumber(expiresUnixSecs, "expiresUnixSecs"),
    }),
  };
}

/** Event fields carrying a native connection ID. */
const CONNECTION_ID_KEYS: ReadonlySet<string> = new Set([
  "connId",
  "oldConnId",
  "newConnId",
]);

/**
 * Converts one value of a native `tag` event: integers to numbers, connection
 * IDs through the connection map, and bytes to `ArrayBuffer`s. A stream ID is
 * mapped together with the connection of the record that carries it.
 */
function normalizeNativeValue(
  value: unknown,
  maps: NativeIdMaps,
  tag: string,
  key?: string
): unknown {
  if (typeof value === "bigint" || typeof value === "number") {
    if (key !== undefined && CONNECTION_ID_KEYS.has(key)) {
      return maps.connectionIds.toPublicInEvent(tag, key, BigInt(value));
    }
    // QUIC stop and close codes are 62-bit varints the remote picks: keep
    // them whole.
    if (key === "errorCode" || key === "code") {
      return BigInt(value);
    }
    return key === "streamId" ? value : u64ToNumber(value, key ?? "native u64");
  }
  if (value instanceof Uint8Array) {
    return toArrayBuffer(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeNativeValue(item, maps, tag));
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  const record: Record<string, unknown> = Object.fromEntries(
    Object.entries(value).map(([itemKey, item]) => [
      itemKey,
      normalizeNativeValue(item, maps, tag, itemKey),
    ])
  );
  const { connId, streamId } = record;
  if (typeof streamId === "bigint" || typeof streamId === "number") {
    // Public stream IDs are allocated per connection. A record without a
    // connection (an endpoint error, say) cannot name a public stream.
    if (typeof connId === "number") {
      record.streamId = maps.streamIds.toPublic(connId, BigInt(streamId));
    } else {
      delete record.streamId;
    }
  }
  return record;
}

/**
 * Converts one native event to its SDK backend form, then retires the IDs it
 * ends.
 */
function normalizeEvent(
  event: NativeEvent,
  connectionIds: ConnectionIdMap,
  streamIds: StreamIdMap
): P2pEvent {
  const normalized = convertEvent(event, { connectionIds, streamIds });
  retireTerminalIds(normalized, connectionIds, streamIds);
  return normalized;
}

/**
 * Per-chunk and per-write events, and pubsub messages, convert field by
 * field. Identify snapshots go through the typed {@link identifyInfo}, and a
 * field-less event passes through by tag. The rest share the generic walk: the addon's serde shape is the SDK shape with
 * napi-rs integers and buffers (see `native-shape.ts`).
 */
function convertEvent(event: NativeEvent, maps: NativeIdMaps): P2pEvent {
  switch (event.tag) {
    case P2pEvent_Tags.StreamData: {
      return {
        inner: {
          ...streamRef(event.inner, maps),
          data: toArrayBuffer(event.inner.data),
        },
        tag: event.tag,
      };
    }
    case P2pEvent_Tags.StreamWriteAccepted:
    case P2pEvent_Tags.StreamRemoteWriteClosed:
    case P2pEvent_Tags.StreamClosed: {
      return { inner: streamRef(event.inner, maps), tag: event.tag };
    }
    case P2pEvent_Tags.Message: {
      const { data, fromPeerId, seqno, signed, topics } = event.inner;
      return {
        inner: {
          data: toArrayBuffer(data),
          fromPeerId,
          seqno: toArrayBuffer(seqno),
          signed,
          topics,
        },
        tag: event.tag,
      };
    }
    case P2pEvent_Tags.IdentifyReceived: {
      return {
        inner: {
          connId: maps.connectionIds.toPublic(BigInt(event.inner.connId)),
          info: identifyInfo(event.inner.info),
          peerId: event.inner.peerId,
        },
        tag: event.tag,
      };
    }
    case P2pEvent_Tags.MdnsRecovered: {
      return { tag: event.tag };
    }
    default: {
      return {
        inner: normalizeNativeValue(event.inner, maps, event.tag),
        tag: event.tag,
      } as P2pEvent;
    }
  }
}

/** The native identity of the stream a native stream event names. */
function nativeStreamOf(event: NativeEvent): [bigint, bigint] | undefined {
  switch (event.tag) {
    case P2pEvent_Tags.StreamReady:
    case P2pEvent_Tags.StreamData:
    case P2pEvent_Tags.StreamWriteAccepted:
    case P2pEvent_Tags.StreamWriteStopped:
    case P2pEvent_Tags.StreamRemoteWriteClosed:
    case P2pEvent_Tags.StreamClosed: {
      return [BigInt(event.inner.connId), BigInt(event.inner.streamId)];
    }
    default: {
      return undefined;
    }
  }
}

/** The public identity of the stream a native stream event names. */
function streamRef(
  inner: {
    readonly peerId: string;
    readonly connId: number | bigint;
    readonly streamId: number | bigint;
  },
  maps: NativeIdMaps
): { peerId: string; connId: number; streamId: number } {
  const connId = maps.connectionIds.toPublic(BigInt(inner.connId));
  return {
    connId,
    peerId: inner.peerId,
    streamId: maps.streamIds.toPublic(connId, BigInt(inner.streamId)),
  };
}

/**
 * Stops new native events from reaching identifiers this event ends, so a
 * reused native ID gets a fresh public number. An ended connection is
 * released at once, so a stream operation queued behind its event throws
 * `StreamClosedError` without reaching native; stream numbers stay resolvable
 * until {@link releaseTerminalIds} runs after dispatch.
 */
function retireTerminalIds(
  event: P2pEvent,
  connectionIds: ConnectionIdMap,
  streamIds: StreamIdMap
): void {
  const connId = endedConnection(event);
  if (connId !== undefined) {
    connectionIds.release(connId);
    streamIds.retireConnection(connId);
  }
  if (event.tag === P2pEvent_Tags.StreamClosed) {
    streamIds.retirePublic(event.inner.streamId);
  }
}

/** Frees stream identifiers this event ended, once the SDK dispatched it. */
function releaseTerminalIds(event: P2pEvent, streamIds: StreamIdMap): void {
  const connId = endedConnection(event);
  if (connId !== undefined) {
    streamIds.deleteConnection(connId);
  }
  if (event.tag === P2pEvent_Tags.StreamClosed) {
    streamIds.deletePublic(event.inner.streamId);
  }
}

/**
 * The connection this event ends. A closed or replaced connection reports no
 * per-stream terminal events, so its streams end with it.
 */
function endedConnection(event: P2pEvent): number | undefined {
  if (event.tag === P2pEvent_Tags.ConnectionClosed) {
    return event.inner.connId;
  }
  if (event.tag === P2pEvent_Tags.ConnectionReplaced) {
    return event.inner.oldConnId;
  }
  return undefined;
}

/** Copies native bytes unless they already own their whole `ArrayBuffer`. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (
    bytes.buffer instanceof ArrayBuffer &&
    bytes.byteOffset === 0 &&
    bytes.byteLength === bytes.buffer.byteLength
  ) {
    return bytes.buffer;
  }
  return Uint8Array.from(bytes).buffer;
}

interface NativeIdMaps {
  readonly connectionIds: ConnectionIdMap;
  readonly streamIds: StreamIdMap;
}

/**
 * Maps native stream IDs, which are unique only within their connection, to
 * public numbers that never repeat. Each stream remembers its public
 * connection, so a closed or replaced connection frees every stream on it.
 */
class StreamIdMap {
  /** Live public IDs by public connection, then native stream ID. */
  readonly #publicByNative = new Map<number, Map<bigint, number>>();
  readonly #streams = new Map<
    number,
    { readonly connId: number; readonly native: bigint }
  >();
  #next = 1;

  toPublic(connId: number, native: bigint): number {
    let byNative = this.#publicByNative.get(connId);
    const existing = byNative?.get(native);
    if (existing !== undefined) {
      return existing;
    }
    if (byNative === undefined) {
      byNative = new Map();
      this.#publicByNative.set(connId, byNative);
    }
    const publicId = this.#next;
    this.#next += 1;
    byNative.set(native, publicId);
    this.#streams.set(publicId, { connId, native });
    return publicId;
  }

  toNative(publicId: number): bigint {
    const stream = this.#streams.get(publicId);
    if (stream === undefined) {
      throw new StreamClosedError("The stream closed");
    }
    return stream.native;
  }

  deletePublic(publicId: number): void {
    this.retirePublic(publicId);
    this.#streams.delete(publicId);
  }

  retirePublic(publicId: number): void {
    const stream = this.#streams.get(publicId);
    if (stream === undefined) {
      return;
    }
    const byNative = this.#publicByNative.get(stream.connId);
    if (byNative?.get(stream.native) === publicId) {
      byNative.delete(stream.native);
      if (byNative.size === 0) {
        this.#publicByNative.delete(stream.connId);
      }
    }
  }

  deleteConnection(connId: number): void {
    for (const publicId of this.#onConnection(connId)) {
      this.deletePublic(publicId);
    }
  }

  retireConnection(connId: number): void {
    for (const publicId of this.#onConnection(connId)) {
      this.retirePublic(publicId);
    }
  }

  #onConnection(connId: number): number[] {
    return [...this.#streams]
      .filter(([, stream]) => stream.connId === connId)
      .map(([publicId]) => publicId);
  }
}
