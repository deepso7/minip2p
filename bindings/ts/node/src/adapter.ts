/* oxlint-disable class-methods-use-this, func-style, max-classes-per-file, no-use-before-define -- The adapter keeps the contract-complete native endpoint, value conversion, and handle maps together at the binding boundary. */

import { Minip2pBase, StreamClosedError } from "@minip2p/core";
import type {
  Bytes,
  ConnectionInfo,
  IdentifyInfo,
  KnownPeerInfo,
  Minip2pConfig,
  Reachability,
  RelayReservationInfo,
} from "@minip2p/core";
import {
  ConnectionIdMap,
  EventDrain,
  P2pEvent_Tags,
  resolveEndpointConfig,
  typedFfiError,
  u64ToNumber,
} from "@minip2p/core/backend";
import type {
  BackendConnectTarget,
  BackendOpenStream,
  Minip2pBackend,
  PathKind,
  P2pEvent,
} from "@minip2p/core/backend";

import type {
  NativeEvent,
  NativeIdentifyInfo,
  NativeKnownPeerInfo,
  NativeRelayReservationInfo,
} from "./native-shape.js";
import { nativeBinding } from "./native.js";
import type { NativeEndpoint } from "./native.js";

/** Native drain batch size. */
const DRAIN_LIMIT = 256;

class NodeBackend implements Minip2pBackend {
  readonly #connectionIds = new ConnectionIdMap();
  readonly #endpoint: NativeEndpoint;
  #events: EventDrain<NativeEvent> | undefined;
  readonly #streamIds = new StreamIdMap();

  constructor(config: Minip2pConfig) {
    this.#endpoint = translateErrors(
      () =>
        new nativeBinding.NodeEndpoint(
          toUint8Array(config.secretKey),
          resolveEndpointConfig(config)
        )
    );
  }

  start(listener: (event: P2pEvent) => void): void {
    const events = new EventDrain(
      (limit) => this.#endpoint.drainEvents(limit),
      (event: NativeEvent) => {
        listener(normalizeEvent(event, this.#connectionIds, this.#streamIds));
      },
      DRAIN_LIMIT,
      // One check-phase turn keeps native callbacks out of the caller's stack
      // without paying the timer granularity for every bounded batch.
      (task) => {
        setImmediate(task);
      }
    );
    this.#events = events;
    translateErrors(() => {
      this.#endpoint.start(() => {
        events.ring();
      });
    });
  }

  eventHandled(event: P2pEvent): void {
    releaseTerminalIds(event, this.#streamIds);
  }

  close(): void {
    this.#endpoint.close();
    this.#events?.stop();
  }

  peerId(): string {
    return this.#endpoint.peerId();
  }

  listenAddrs(): string[] {
    return this.#endpoint.listenAddrs();
  }

  isRunning(): boolean {
    return this.#endpoint.isRunning();
  }

  connectedPeers(): string[] {
    return translateErrors(() => this.#endpoint.connectedPeers());
  }

  isPeerReady(peerId: string): boolean {
    return translateErrors(() => this.#endpoint.isPeerReady(peerId));
  }

  peerInfo(peerId: string): IdentifyInfo | undefined {
    const info = translateErrors(() => this.#endpoint.peerInfo(peerId));
    return info === null ? undefined : identifyInfo(info);
  }

  knownPeers(): KnownPeerInfo[] {
    return translateErrors(() => this.#endpoint.knownPeers()).map(knownPeer);
  }

  discoveryNowMs(): number | undefined {
    const value = translateErrors(() => this.#endpoint.discoveryNowMs());
    return value === null ? undefined : u64ToNumber(value, "clock");
  }

  activeReservation(): RelayReservationInfo | undefined {
    const reservation = translateErrors(() =>
      this.#endpoint.activeReservation()
    );
    return reservation === null ? undefined : relayReservation(reservation);
  }

  path(peerId: string): PathKind | undefined {
    return translateErrors(() => this.#endpoint.path(peerId)) ?? undefined;
  }

  connectionInfo(peerId: string): ConnectionInfo | undefined {
    const info = translateErrors(() => this.#endpoint.connectionInfo(peerId));
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
    return circuitAddress(relayAddress, peerId);
  }

  reachability(): Reachability {
    return translateErrors(() => this.#endpoint.reachability());
  }

  setActive(active: boolean): void {
    this.#endpoint.setActive(active);
  }

  subscribe(topic: string): boolean {
    return translateErrors(() => this.#endpoint.subscribe(topic));
  }

  unsubscribe(topic: string): boolean {
    return translateErrors(() => this.#endpoint.unsubscribe(topic));
  }

  publish(topic: string, data: Uint8Array): void {
    translateErrors(() => {
      this.#endpoint.publish(topic, data);
    });
  }

  ping(peerId: string): void {
    translateErrors(() => {
      this.#endpoint.ping(peerId);
    });
  }

  addProtocol(protocolId: string): void {
    translateErrors(() => {
      this.#endpoint.addProtocol(protocolId);
    });
  }

  openStream(peerId: string, protocolId: string): BackendOpenStream {
    const stream = translateErrors(() =>
      this.#endpoint.openStream(peerId, protocolId)
    );
    const connId = this.#connectionIds.toPublic(BigInt(stream.connId));
    return {
      connId,
      streamId: this.#streamIds.toPublic(connId, BigInt(stream.streamId)),
    };
  }

  sendStream(
    peerId: string,
    connId: number,
    streamId: number,
    data: Uint8Array
  ): boolean {
    return translateErrors(() =>
      this.#endpoint.sendStream(
        peerId,
        ...this.#nativeStream(connId, streamId),
        data
      )
    );
  }

  closeStreamWrite(peerId: string, connId: number, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.closeStreamWrite(
        peerId,
        ...this.#nativeStream(connId, streamId)
      );
    });
  }

  resetStream(peerId: string, connId: number, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.resetStream(
        peerId,
        ...this.#nativeStream(connId, streamId)
      );
    });
  }

  abandonStream(peerId: string, connId: number, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.abandonStream(
        peerId,
        ...this.#nativeStream(connId, streamId)
      );
    });
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

  // Connect IDs are not mapped because they round-trip into native calls,
  // and native allocates them well inside the safe integer range.
  connect(target: BackendConnectTarget): number {
    return u64ToNumber(
      translateErrors(() =>
        this.#endpoint.connect(
          target.kind === "peer" ? target.peerId : [...target.addresses]
        )
      ),
      "connectId"
    );
  }

  cancelConnect(id: number): void {
    translateErrors(() => {
      this.#endpoint.cancelConnect(BigInt(id));
    });
  }

  disconnect(peerId: string): void {
    translateErrors(() => {
      this.#endpoint.disconnect(peerId);
    });
  }
}

/** High-level Node.js owner for one native minip2p endpoint. */
export class Minip2p extends Minip2pBase {
  private constructor(backend: Minip2pBackend, relays: readonly string[]) {
    super(backend, relays);
  }

  /** Constructs and starts a Node.js endpoint. */
  static create(config: Minip2pConfig): Minip2p {
    return new Minip2p(new NodeBackend(config), config.relays ?? []);
  }
}

/** Generates a new 32-byte Ed25519 secret key. */
export function generateSecretKey(): Uint8Array {
  return nativeBinding.generateSecretKey();
}

/** Derives a peer ID from raw Ed25519 secret key material. */
export function peerIdFromSecretKey(secretKey: Bytes): string {
  return translateErrors(() =>
    nativeBinding.peerIdFromSecretKey(toUint8Array(secretKey))
  );
}

/** Builds a circuit multiaddress through a direct relay address. */
export function circuitAddress(relayAddress: string, peerId: string): string {
  return translateErrors(() =>
    nativeBinding.circuitAddress(relayAddress, peerId)
  );
}

/**
 * Rethrows a native `FfiError` as its typed SDK error. The addon tags each
 * error with the variant name as `code` and its detail field as `detail`;
 * untyped variants are rethrown unchanged with both properties intact.
 */
function translateErrors<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    throw (
      typedFfiError(
        stringProperty(error, "code"),
        stringProperty(error, "detail")
      ) ?? error
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

function toUint8Array(value: Bytes): Uint8Array {
  return value instanceof Uint8Array
    ? Uint8Array.from(value)
    : new Uint8Array(value);
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
 * Converts one value of a native event: integers to numbers, connection IDs
 * through the connection map, and bytes to `ArrayBuffer`s. A stream ID is
 * mapped together with the connection of the record that carries it.
 */
function normalizeNativeValue(
  value: unknown,
  maps: NativeIdMaps,
  key?: string
): unknown {
  if (typeof value === "bigint" || typeof value === "number") {
    if (key !== undefined && CONNECTION_ID_KEYS.has(key)) {
      return maps.connectionIds.toPublic(BigInt(value));
    }
    return key === "streamId" ? value : u64ToNumber(value, key ?? "native u64");
  }
  if (value instanceof Uint8Array) {
    return toArrayBuffer(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeNativeValue(item, maps));
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  const record: Record<string, unknown> = Object.fromEntries(
    Object.entries(value).map(([itemKey, item]) => [
      itemKey,
      normalizeNativeValue(item, maps, itemKey),
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
 * Converts one native event to its SDK backend form. Identify snapshots go
 * through the typed {@link identifyInfo}; every other event shares the
 * generic integer, ID and byte conversion.
 */
function normalizeEvent(
  event: NativeEvent,
  connectionIds: ConnectionIdMap,
  streamIds: StreamIdMap
): P2pEvent {
  // Outside Identify, the addon's serde shape is the SDK shape with napi-rs
  // integers and buffers (see `native-shape.ts`), which the walk converts.
  const normalized: P2pEvent =
    event.tag === P2pEvent_Tags.IdentifyReceived
      ? {
          inner: {
            info: identifyInfo(event.inner.info),
            peerId: event.inner.peerId,
          },
          tag: event.tag,
        }
      : ({
          inner: normalizeNativeValue(event.inner, {
            connectionIds,
            streamIds,
          }),
          tag: event.tag,
        } as P2pEvent);
  retireTerminalIds(normalized, connectionIds, streamIds);
  return normalized;
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
  readonly #publicByKey = new Map<string, number>();
  readonly #streams = new Map<
    number,
    { readonly connId: number; readonly key: string; readonly native: bigint }
  >();
  #next = 1;

  toPublic(connId: number, native: bigint): number {
    const key = `${connId}:${native}`;
    const existing = this.#publicByKey.get(key);
    if (existing !== undefined) {
      return existing;
    }
    const publicId = this.#next;
    this.#next += 1;
    this.#publicByKey.set(key, publicId);
    this.#streams.set(publicId, { connId, key, native });
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
    if (
      stream !== undefined &&
      this.#publicByKey.get(stream.key) === publicId
    ) {
      this.#publicByKey.delete(stream.key);
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
