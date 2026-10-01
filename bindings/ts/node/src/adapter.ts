/* oxlint-disable class-methods-use-this, func-style, max-classes-per-file, no-await-in-loop, no-use-before-define, prefer-destructuring, promise/avoid-new, unicorn/no-useless-undefined -- The adapter keeps the contract-complete native endpoint, value conversion, handle maps, and drain loop together at the binding boundary. */

import { Minip2pBase } from "@minip2p/core";
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
  P2pEvent_Tags,
  resolveEndpointConfig,
  typedFfiError,
} from "@minip2p/core/backend";
import type {
  BackendConnectTarget,
  BackendOpenStream,
  Minip2pBackend,
  PathKind,
  P2pEvent,
} from "@minip2p/core/backend";

import { nativeBinding } from "./native.js";
import type { NativeEndpoint } from "./native.js";

class NodeBackend implements Minip2pBackend {
  readonly #connectionIds = new IdMap();
  readonly #endpoint: NativeEndpoint;
  readonly #events: EventDrain;
  readonly #streamIds = new StreamIdMap();

  constructor(config: Minip2pConfig) {
    this.#endpoint = translateErrors(
      () =>
        new nativeBinding.NodeEndpoint(
          toUint8Array(config.secretKey),
          resolveEndpointConfig(config)
        )
    );
    this.#events = new EventDrain(
      () => this.#endpoint.drainEvents(256),
      (event) => normalizeEvent(event, this.#connectionIds, this.#streamIds)
    );
  }

  start(listener: (event: P2pEvent) => void): void {
    this.#events.start(listener);
    translateErrors(() => {
      this.#endpoint.start(() => {
        this.#events.ring();
      });
    });
  }

  eventHandled(event: P2pEvent): void {
    releaseTerminalIds(event, this.#connectionIds, this.#streamIds);
  }

  close(): void {
    this.#endpoint.close();
    this.#events.stop();
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
    return info === null || info === undefined
      ? undefined
      : normalizeIdentifyInfo(info);
  }

  knownPeers(): KnownPeerInfo[] {
    return translateErrors(() => this.#endpoint.knownPeers()).map((peer) =>
      normalizeRecord<KnownPeerInfo>(peer)
    );
  }

  discoveryNowMs(): number | undefined {
    const value = translateErrors(() => this.#endpoint.discoveryNowMs());
    return value === null || value === undefined
      ? undefined
      : bigintToNumber(value, "clock");
  }

  activeReservation(): RelayReservationInfo | undefined {
    return normalizeOptional<RelayReservationInfo>(
      translateErrors(() => this.#endpoint.activeReservation())
    );
  }

  path(peerId: string): PathKind | undefined {
    return normalizeOptional<PathKind>(
      translateErrors(() => this.#endpoint.path(peerId))
    );
  }

  connectionInfo(peerId: string): ConnectionInfo | undefined {
    const info = translateErrors(() => this.#endpoint.connectionInfo(peerId));
    if (info === null || info === undefined) {
      return undefined;
    }
    return {
      connId: this.#connectionIds.toPublic(info.connId),
      ...(typeof info.remoteAddr === "string" && {
        remoteAddr: info.remoteAddr,
      }),
      ...(Array.isArray(info.readyProtocols) && {
        readyProtocols: info.readyProtocols,
      }),
    };
  }

  circuitAddress(relayAddress: string, peerId: string): string {
    return circuitAddress(relayAddress, peerId);
  }

  reachability(): Reachability {
    return translateErrors(() => this.#endpoint.reachability()) as Reachability;
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
    const connId = this.#connectionIds.toPublic(stream.connId);
    return {
      connId,
      streamId: this.#streamIds.toPublic(connId, stream.streamId),
    };
  }

  sendStream(peerId: string, streamId: number, data: Uint8Array): void {
    translateErrors(() => {
      this.#endpoint.sendStream(
        peerId,
        this.#streamIds.toNative(streamId),
        data
      );
    });
  }

  closeStreamWrite(peerId: string, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.closeStreamWrite(
        peerId,
        this.#streamIds.toNative(streamId)
      );
    });
  }

  resetStream(peerId: string, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.resetStream(peerId, this.#streamIds.toNative(streamId));
    });
  }

  abandonStream(peerId: string, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.abandonStream(peerId, this.#streamIds.toNative(streamId));
    });
  }

  // Connect IDs are not mapped because they round-trip into native calls,
  // and native allocates them well inside the safe integer range.
  connect(target: BackendConnectTarget): number {
    return bigintToNumber(
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

function bigintToNumber(value: bigint, name: string): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new RangeError(`${name} exceeds JavaScript's safe integer range`);
  }
  return number;
}

function normalizeOptional<Value>(value: unknown): Value | undefined {
  return value === null || value === undefined
    ? undefined
    : normalizeRecord<Value>(value);
}

function normalizeRecord<Value>(value: unknown): Value {
  return normalizeNativeValue(value) as Value;
}

function normalizeIdentifyInfo(value: unknown): IdentifyInfo {
  const info = normalizeRecord<Record<string, unknown>>(value);
  const publicKey = info.publicKey;
  if (publicKey === undefined) {
    return info as unknown as IdentifyInfo;
  }
  if (Array.isArray(publicKey) || publicKey instanceof Uint8Array) {
    return {
      ...info,
      publicKey: nativeBytesToArrayBuffer(publicKey),
    } as unknown as IdentifyInfo;
  }
  throw new TypeError(
    "The native addon returned an invalid Identify public key"
  );
}

/** Event fields carrying a native connection ID (`old`/`new` belong to `ConnectionReplaced`). */
const CONNECTION_ID_KEYS: ReadonlySet<string> = new Set([
  "connId",
  "old",
  "new",
]);

function normalizeNativeValue(
  value: unknown,
  key?: string,
  maps?: NativeIdMaps
): unknown {
  const isId = typeof value === "bigint" || typeof value === "number";
  if (isId && maps !== undefined && key !== undefined) {
    if (CONNECTION_ID_KEYS.has(key)) {
      return maps.connectionIds.toPublic(BigInt(value));
    }
    if (key === "streamId") {
      // Mapped with its connection once the whole record is normalized.
      return value;
    }
  }
  if (typeof value === "bigint") {
    return bigintToNumber(value, "native value");
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeNativeValue(item, undefined, maps));
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value !== null && typeof value === "object") {
    const record: Record<string, unknown> = Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== null)
        .map(([itemKey, item]) => [
          itemKey,
          normalizeNativeValue(item, itemKey, maps),
        ])
    );
    const { connId, streamId } = record;
    if (maps !== undefined && streamId !== undefined) {
      if (
        typeof connId !== "number" ||
        (typeof streamId !== "bigint" && typeof streamId !== "number")
      ) {
        throw new TypeError("The native addon returned an invalid stream ID");
      }
      record.streamId = maps.streamIds.toPublic(connId, BigInt(streamId));
    }
    return record;
  }
  return value;
}

function normalizeEvent(
  value: unknown,
  connectionIds: IdMap,
  streamIds: StreamIdMap
): P2pEvent {
  const event = normalizeNativeValue(value, undefined, {
    connectionIds,
    streamIds,
  }) as { tag?: unknown; inner?: unknown };
  if (typeof event.tag !== "string" || event.inner === undefined) {
    throw new TypeError("The native addon returned an invalid event");
  }
  if (
    event.tag === "StreamData" ||
    event.tag === "Message" ||
    event.tag === "IdentifyReceived"
  ) {
    event.inner = normalizeEventBytes(event.tag, event.inner);
  }
  const normalized = event as P2pEvent;
  retireTerminalIds(normalized, connectionIds, streamIds);
  return normalized;
}

/**
 * Stops new native events from reaching identifiers this event ends, so a
 * reused native ID gets a fresh public number. The public numbers stay
 * resolvable until {@link releaseTerminalIds} runs after dispatch.
 */
function retireTerminalIds(
  event: P2pEvent,
  connectionIds: IdMap,
  streamIds: StreamIdMap
): void {
  const connId = endedConnection(event);
  if (connId !== undefined) {
    connectionIds.retirePublic(connId);
    streamIds.retireConnection(connId);
  }
  if (event.tag === P2pEvent_Tags.StreamClosed) {
    streamIds.retirePublic(event.inner.streamId);
  }
}

/** Frees identifiers this event ended, once the SDK has dispatched it. */
function releaseTerminalIds(
  event: P2pEvent,
  connectionIds: IdMap,
  streamIds: StreamIdMap
): void {
  const connId = endedConnection(event);
  if (connId !== undefined) {
    connectionIds.deletePublic(connId);
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
    return event.inner.old;
  }
  return undefined;
}

function normalizeEventBytes(tag: string, value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  const inner = { ...value };
  if (tag === "StreamData") {
    const data = Reflect.get(inner, "data");
    if (Array.isArray(data) || data instanceof Uint8Array) {
      Reflect.set(inner, "data", nativeBytesToArrayBuffer(data));
    }
  }
  if (tag === "Message") {
    for (const key of ["data", "seqno"] as const) {
      const bytes = Reflect.get(inner, key);
      if (Array.isArray(bytes) || bytes instanceof Uint8Array) {
        Reflect.set(inner, key, nativeBytesToArrayBuffer(bytes));
      }
    }
  }
  if (tag === "IdentifyReceived") {
    const info = Reflect.get(inner, "info");
    if (info !== null && typeof info === "object") {
      Reflect.set(inner, "info", normalizeIdentifyInfo(info));
    }
  }
  return inner;
}

function nativeBytesToArrayBuffer(bytes: number[] | Uint8Array): ArrayBuffer {
  if (Array.isArray(bytes)) {
    return Uint8Array.from(bytes).buffer;
  }
  if (
    bytes.buffer instanceof ArrayBuffer &&
    bytes.byteOffset === 0 &&
    bytes.byteLength === bytes.buffer.byteLength
  ) {
    return bytes.buffer;
  }
  return Uint8Array.from(bytes).buffer;
}

class EventDrain {
  readonly #drain: () => unknown[];
  readonly #normalize: (event: unknown) => P2pEvent;
  #listener: ((event: P2pEvent) => void) | undefined;
  #pending = false;
  #running = false;
  #stopped = false;

  constructor(drain: () => unknown[], normalize: (event: unknown) => P2pEvent) {
    this.#drain = drain;
    this.#normalize = normalize;
  }

  start(listener: (event: P2pEvent) => void): void {
    this.#listener = listener;
  }

  ring(): void {
    if (this.#stopped) {
      return;
    }
    this.#pending = true;
    if (!this.#running) {
      this.#running = true;
      // One check-phase turn keeps native callbacks out of the caller's stack
      // without paying the timer granularity for every bounded batch.
      setImmediate(() => {
        void this.#run();
      });
    }
  }

  stop(): void {
    this.#stopped = true;
    this.#pending = false;
    this.#listener = undefined;
  }

  async #run(): Promise<void> {
    try {
      while (!this.#stopped && this.#pending) {
        this.#pending = false;
        let events = this.#drain();
        while (!this.#stopped && events.length > 0) {
          for (const event of events) {
            try {
              this.#listener?.(this.#normalize(event));
            } catch {
              // Application callbacks and malformed events cannot stop draining.
            }
          }
          await new Promise<void>((resolve) => {
            setImmediate(resolve);
          });
          if (this.#stopped) {
            break;
          }
          events = this.#drain();
        }
      }
    } finally {
      this.#running = false;
      if (this.#pending && !this.#stopped) {
        this.ring();
      }
    }
  }
}

interface NativeIdMaps {
  readonly connectionIds: IdMap;
  readonly streamIds: StreamIdMap;
}

class IdMap {
  readonly #nativeByPublic = new Map<number, bigint>();
  readonly #publicByNative = new Map<bigint, number>();
  #next = 1;

  toPublic(native: bigint): number {
    const existing = this.#publicByNative.get(native);
    if (existing !== undefined) {
      return existing;
    }
    const publicId = this.#next;
    this.#next += 1;
    this.#publicByNative.set(native, publicId);
    this.#nativeByPublic.set(publicId, native);
    return publicId;
  }

  toNative(publicId: number): bigint {
    const native = this.#nativeByPublic.get(publicId);
    if (native === undefined) {
      throw new RangeError(`Unknown native identifier ${publicId}`);
    }
    return native;
  }

  deletePublic(publicId: number): void {
    this.retirePublic(publicId);
    this.#nativeByPublic.delete(publicId);
  }

  retirePublic(publicId: number): void {
    const native = this.#nativeByPublic.get(publicId);
    if (native !== undefined && this.#publicByNative.get(native) === publicId) {
      this.#publicByNative.delete(native);
    }
  }
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
      throw new RangeError(`Unknown native identifier ${publicId}`);
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
