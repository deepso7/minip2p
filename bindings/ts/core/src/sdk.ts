/* oxlint-disable default-case, func-style, max-classes-per-file, no-await-in-loop, no-empty-function, no-loop-func, no-use-before-define, promise/avoid-new, promise/prefer-await-to-callbacks, promise/prefer-await-to-then, typescript/no-invalid-void-type, unicorn/consistent-function-scoping, unicorn/no-new-array, unicorn/no-useless-spread, unicorn/no-useless-undefined -- Promise adapters, sequential async iterators, void event payloads, snapshot fan-out, and bounded queues are deliberate SDK internals. */

import type { Minip2pBackend } from "./backend.js";
import {
  AbortError,
  ClosedError,
  ConnectFailedError,
  ConnectResultUnavailableError,
  DriverFailedError,
  EventQueueOverflowError,
  OpenStreamError,
  PeerDisconnectedError,
  StreamClosedError,
  TimeoutError,
} from "./errors.js";
import { P2pEvent_Tags, PathKind_Tags } from "./types.js";
import type {
  Bytes,
  CloseReason,
  ConnectResult,
  EventsOptions,
  IdentifyInfo,
  InboundStreamMeta,
  KnownPeerInfo,
  Minip2pCatchAllEventMap,
  Minip2pEvent,
  Minip2pNamedEventMap,
  OnceOptions,
  OpOptions,
  P2pEvent,
  Path,
  PathKind,
  Reachability,
  RelayReservationInfo,
  Unsubscribe,
  WaitForOptions,
} from "./types.js";

declare const TextEncoder: new () => {
  encode: (input: string) => Uint8Array;
};

const DEFAULT_TIMEOUT_MS = 65_000;
const EVENT_QUEUE_CAP = 4096;
const EVENT_FLUSH_BATCH = 256;
const CONNECT_TERMINAL_CAP = 1024;
const STREAM_CHUNK_CAP = 64;
const STREAM_BYTE_CAP = 1024 * 1024;

type EventKind = keyof Minip2pNamedEventMap;
type AnyPayload = Minip2pNamedEventMap[EventKind];
type NamedHandler<Kind extends EventKind> = (
  payload: Minip2pNamedEventMap[Kind]
) => void;
type CatchAllHandler = (event: Minip2pEvent) => void;
type QueueItem =
  | { readonly source: "native"; readonly event: P2pEvent }
  | {
      readonly source: "high";
      readonly type: "handlerError";
      readonly payload: Minip2pCatchAllEventMap["handlerError"];
    };

interface EventWaiter {
  readonly type: EventKind;
  readonly predicate: (event: unknown) => boolean;
  readonly resolve: (event: unknown) => void;
  readonly reject: (error: unknown) => void;
  timer?: ReturnType<typeof setTimeout>;
  removeAbort?: () => void;
}

type ConnectTerminal =
  | {
      readonly ok: true;
      readonly result: ConnectResult;
    }
  | {
      readonly ok: false;
      readonly error: ConnectFailedError;
    };

interface ConnectAttempt {
  terminal?: ConnectTerminal;
  waiting: boolean;
  resolve?: (result: ConnectResult) => void;
  reject?: (error: unknown) => void;
}

interface PendingOpen {
  readonly peerId: string;
  readonly protocolId: string;
  readonly connId: number;
  readonly streamId: number;
  readonly resolve: (stream: Stream) => void;
  readonly reject: (error: unknown) => void;
  timer?: ReturnType<typeof setTimeout>;
  removeAbort?: () => void;
}

interface PendingRead {
  readonly resolve: (data?: Uint8Array) => void;
  readonly reject: (error: unknown) => void;
}

interface PingOperation {
  readonly promise: Promise<number>;
  readonly cancel: (error: unknown) => void;
  callers: number;
}

class BoundedQueue<Item> {
  readonly #items: (Item | undefined)[];
  #head = 0;
  #size = 0;

  constructor(capacity: number) {
    this.#items = new Array<Item | undefined>(capacity);
  }

  get length(): number {
    return this.#size;
  }

  push(item: Item): Item | undefined {
    if (this.#size === this.#items.length) {
      const dropped = this.#items[this.#head];
      this.#items[this.#head] = item;
      this.#head = (this.#head + 1) % this.#items.length;
      return dropped;
    }
    const tail = (this.#head + this.#size) % this.#items.length;
    this.#items[tail] = item;
    this.#size += 1;
    return undefined;
  }

  shift(): Item | undefined {
    if (this.#size === 0) {
      return undefined;
    }
    const item = this.#items[this.#head];
    this.#items[this.#head] = undefined;
    this.#head = (this.#head + 1) % this.#items.length;
    this.#size -= 1;
    return item;
  }

  clear(): void {
    this.#items.fill(undefined);
    this.#head = 0;
    this.#size = 0;
  }
}

/** A negotiated custom-protocol stream with exclusive pull or flowing reads. */
export class Stream {
  /** Remote peer that owns the other end of this stream. */
  readonly peerId: string;
  /** Negotiated multistream protocol identifier. */
  readonly protocolId: string;
  /** Endpoint-local transport stream identifier. */
  readonly streamId: number;
  /** Endpoint-local connection carrying this stream. */
  readonly connId: number;
  /** Whether this endpoint initiated the stream. */
  readonly initiatedLocally: boolean;
  readonly #backend: Minip2pBackend;
  readonly #onTerminal: () => void;
  readonly #listeners = new Map<
    keyof StreamEventMap,
    Set<(payload: StreamEventMap[keyof StreamEventMap]) => void>
  >();
  readonly #fifo: Uint8Array[] = [];
  readonly #reads: PendingRead[] = [];
  #fifoBytes = 0;
  #mode: "pull" | "flowing" | undefined;
  #remoteWriteClosed = false;
  #closed = false;
  #terminalError: unknown;

  constructor(
    backend: Minip2pBackend,
    meta: InboundStreamMeta,
    onTerminal: () => void
  ) {
    this.#backend = backend;
    this.#onTerminal = onTerminal;
    this.peerId = meta.peerId;
    this.protocolId = meta.protocolId;
    this.streamId = meta.streamId;
    this.connId = meta.connId;
    this.initiatedLocally = meta.initiatedLocally;
  }

  /** Subscribes to stream lifecycle or data events. */
  on<Kind extends keyof StreamEventMap>(
    type: Kind,
    handler: (payload: StreamEventMap[Kind]) => void
  ): Unsubscribe {
    if (type === "data") {
      if (this.#mode === "pull") {
        throw new Error("Cannot use flowing data handlers after read()");
      }
      this.#mode = "flowing";
    }
    let listeners = this.#listeners.get(type);
    if (listeners === undefined) {
      listeners = new Set();
      this.#listeners.set(type, listeners);
    }
    listeners.add(
      handler as (payload: StreamEventMap[keyof StreamEventMap]) => void
    );
    if (type === "data") {
      this.#flushFlowing();
    }
    let active = true;
    return () => {
      if (!active) {
        return;
      }
      active = false;
      listeners?.delete(
        handler as (payload: StreamEventMap[keyof StreamEventMap]) => void
      );
    };
  }

  /**
   * Reads the next buffered chunk, or `undefined` after the remote write side
   * closes. Pull reads and flowing `data` handlers are mutually exclusive.
   */
  read(): Promise<Uint8Array | undefined> {
    if (this.#mode === "flowing") {
      return Promise.reject(
        new Error('Cannot call read() after subscribing to "data"')
      );
    }
    this.#mode = "pull";
    if (this.#closed) {
      return Promise.reject(this.#terminalError);
    }
    const buffered = this.#shift();
    if (buffered !== undefined) {
      return Promise.resolve(buffered);
    }
    if (this.#remoteWriteClosed) {
      return Promise.resolve(this.#shift());
    }
    return new Promise((resolve, reject) => {
      this.#reads.push({ reject, resolve });
    });
  }

  /** Writes UTF-8 text or bytes to the stream. */
  write(data: string | Bytes): void {
    if (this.#closed) {
      throw new ClosedError();
    }
    this.#backend.sendStream(this.peerId, this.streamId, toUint8Array(data));
  }

  /** Half-closes the local write side while keeping reads available. */
  closeWrite(): void {
    if (!this.#closed) {
      this.#backend.closeStreamWrite(this.peerId, this.streamId);
    }
  }

  /** Abruptly resets the stream and emits `closed`. */
  reset(): void {
    if (!this.#closed) {
      this.#backend.resetStream(this.peerId, this.streamId);
      this.terminal();
    }
  }

  /** Relinquishes the stream and requests a reset while it remains active. */
  abandon(): void {
    if (!this.#closed) {
      try {
        this.#backend.abandonStream(this.peerId, this.streamId);
      } catch {
        // A native close can overtake its queued terminal event.
      }
      this.terminal();
    }
  }

  [Symbol.dispose](): void {
    this.abandon();
  }

  /**
   * Iterates received chunks until the remote peer closes its write side.
   *
   * @yields {Uint8Array} Received binary chunks in order.
   */
  async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array, void, void> {
    try {
      while (true) {
        const chunk = await this.read();
        if (chunk === undefined) {
          return;
        }
        yield chunk;
      }
    } catch (error) {
      if (!(error instanceof ClosedError)) {
        throw error;
      }
    }
  }

  /** @internal */
  receive(data: ArrayBuffer): void {
    if (this.#closed) {
      return;
    }
    const chunk = new Uint8Array(data);
    const read = this.#reads.shift();
    if (read !== undefined) {
      read.resolve(chunk);
      return;
    }
    if (this.#mode === "flowing") {
      this.#emit("data", chunk);
      return;
    }
    if (
      this.#fifo.length >= STREAM_CHUNK_CAP ||
      this.#fifoBytes + chunk.byteLength > STREAM_BYTE_CAP
    ) {
      this.#emit("dataOverflow", {
        droppedBytes: chunk.byteLength,
        droppedChunks: 1,
      });
      return;
    }
    this.#fifo.push(chunk);
    this.#fifoBytes += chunk.byteLength;
  }

  /** @internal */
  remoteWriteClosed(): void {
    if (this.#closed || this.#remoteWriteClosed) {
      return;
    }
    this.#remoteWriteClosed = true;
    this.#emit("remoteWriteClosed");
    if (this.#fifo.length === 0) {
      for (const read of this.#reads.splice(0)) {
        read.resolve();
      }
    }
  }

  /** @internal */
  terminal(error: unknown = new ClosedError()): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#terminalError = error;
    this.#fifo.length = 0;
    this.#fifoBytes = 0;
    for (const read of this.#reads.splice(0)) {
      read.reject(error);
    }
    this.#emit("closed");
    this.#listeners.clear();
    this.#onTerminal();
  }

  #flushFlowing(): void {
    while (this.#fifo.length > 0 && !this.#closed) {
      const chunk = this.#shift();
      if (chunk !== undefined) {
        this.#emit("data", chunk);
      }
    }
  }

  #shift(): Uint8Array | undefined {
    const chunk = this.#fifo.shift();
    if (chunk !== undefined) {
      this.#fifoBytes -= chunk.byteLength;
    }
    return chunk;
  }

  #emit<Kind extends keyof StreamEventMap>(
    type: Kind,
    payload?: StreamEventMap[Kind]
  ): void {
    for (const handler of [...(this.#listeners.get(type) ?? [])]) {
      try {
        handler(payload as StreamEventMap[Kind]);
      } catch {
        // Stream handlers are isolated from native callbacks and one another.
      }
    }
  }
}

/** Events emitted by a negotiated {@link Stream}. */
export interface StreamEventMap {
  /** A received binary chunk. */
  data: Uint8Array;
  /** The remote peer half-closed its write side. */
  remoteWriteClosed: void;
  /** The stream reached a terminal state. */
  closed: void;
  /** Incoming data exceeded the bounded pull-read buffer. */
  dataOverflow: {
    readonly droppedChunks: number;
    readonly droppedBytes: number;
  };
}

/**
 * Promise-first, platform-neutral owner for one native minip2p endpoint.
 *
 * Platform packages subclass this and provide a native backend factory.
 */
export class Minip2pBase {
  readonly #backend: Minip2pBackend;
  readonly #relayAddrs: readonly string[];
  readonly #named = new Map<EventKind, Set<(payload: AnyPayload) => void>>();
  readonly #catchAll = new Set<CatchAllHandler>();
  readonly #closeHandlers = new Set<(reason: CloseReason) => void>();
  readonly #waiters = new Set<EventWaiter>();
  readonly #queue = new BoundedQueue<QueueItem>(EVENT_QUEUE_CAP);
  readonly #connects = new Map<number, ConnectAttempt>();
  readonly #terminalConnects = new Set<number>();
  readonly #streams = new Map<string, Stream>();
  readonly #pendingOpens = new Map<string, PendingOpen>();
  readonly #pings = new Map<string, PingOperation>();
  #dropped = 0;
  #flushScheduled = false;
  #closed = false;

  protected constructor(
    backend: Minip2pBackend,
    relayAddresses: readonly string[]
  ) {
    this.#backend = backend;
    this.#relayAddrs = relayAddresses;
    try {
      backend.start((event) => {
        this.#enqueueNative(event);
      });
    } catch (error) {
      backend.close();
      throw error;
    }
  }

  /** Subscribes to one named event and returns an idempotent unsubscribe. */
  on<Kind extends EventKind>(
    type: Kind,
    handler: NamedHandler<Kind>
  ): Unsubscribe;
  /** Subscribes to the catch-all metadata event stream. */
  on(handler: CatchAllHandler): Unsubscribe;
  on<Kind extends EventKind>(
    typeOrHandler: Kind | CatchAllHandler,
    maybeHandler?: NamedHandler<Kind>
  ): Unsubscribe {
    this.#assertOpen();
    if (typeof typeOrHandler === "function") {
      return subscribe(this.#catchAll, typeOrHandler);
    }
    let handlers = this.#named.get(typeOrHandler);
    if (handlers === undefined) {
      handlers = new Set();
      this.#named.set(typeOrHandler, handlers);
    }
    return subscribe(
      handlers,
      maybeHandler as unknown as (payload: AnyPayload) => void
    );
  }

  /**
   * Iterates endpoint events until the endpoint closes or the caller aborts.
   *
   * @yields {Minip2pEvent} Endpoint events in delivery order.
   */
  async *events(
    options: EventsOptions = {}
  ): AsyncGenerator<Minip2pEvent, void, void> {
    if (options.signal?.aborted === true) {
      return;
    }
    const bufferCap = options.bufferCap ?? EVENT_QUEUE_CAP;
    if (!Number.isSafeInteger(bufferCap) || bufferCap < 1) {
      throw new RangeError("bufferCap must be a positive safe integer");
    }
    const buffer = new BoundedQueue<Minip2pEvent>(bufferCap);
    let dropped = 0;
    let done = false;
    let aborted = false;
    let wake: (() => void) | undefined;
    const finish = () => {
      if (done) {
        return;
      }
      done = true;
      wake?.();
    };
    const offEvents = this.on((event) => {
      if (buffer.push(event) !== undefined) {
        dropped += 1;
      }
      wake?.();
    });
    const offClose = this.onClose(finish);
    const abort = () => {
      aborted = true;
      finish();
      offEvents();
      offClose();
      buffer.clear();
      dropped = 0;
    };
    const removeAbort = listenAbort(options.signal, abort);
    try {
      while (true) {
        if (aborted) {
          return;
        }
        if (dropped > 0) {
          const count = dropped;
          dropped = 0;
          yield { dropped: count, type: "queueOverflow" };
          continue;
        }
        const event = buffer.shift();
        if (event !== undefined) {
          yield event;
          continue;
        }
        if (done) {
          return;
        }
        await new Promise<void>((resolve) => {
          wake = resolve;
        });
        wake = undefined;
      }
    } finally {
      offEvents();
      offClose();
      removeAbort?.();
    }
  }

  /** Resolves with the next event of `type`. */
  once<Kind extends EventKind>(
    type: Kind,
    options?: OnceOptions
  ): Promise<{ readonly type: Kind } & Minip2pNamedEventMap[Kind]> {
    return this.waitFor(type, { ...options });
  }

  /** Resolves with the next event of `type` accepted by `predicate`. */
  waitFor<Kind extends EventKind>(
    type: Kind,
    options: WaitForOptions<
      { readonly type: Kind } & Minip2pNamedEventMap[Kind]
    >
  ): Promise<{ readonly type: Kind } & Minip2pNamedEventMap[Kind]> {
    this.#assertOpen();
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    assertTimeout(timeoutMs);
    if (options.signal?.aborted === true) {
      return Promise.reject(new AbortError());
    }
    return new Promise((resolve, reject) => {
      const waiter: EventWaiter = {
        predicate: (event) =>
          options.predicate?.(
            event as { readonly type: Kind } & Minip2pNamedEventMap[Kind]
          ) ?? true,
        reject,
        resolve: (event) => {
          resolve(
            event as { readonly type: Kind } & Minip2pNamedEventMap[Kind]
          );
        },
        type,
      };
      if (timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          this.#waiters.delete(waiter);
          waiter.removeAbort?.();
          reject(new TimeoutError(timeoutMs));
        }, timeoutMs);
      }
      waiter.removeAbort = listenAbort(options.signal, () => {
        this.#waiters.delete(waiter);
        clearTimeout(waiter.timer);
        reject(new AbortError());
      });
      this.#waiters.add(waiter);
    });
  }

  /** Registers a one-shot endpoint shutdown observer. */
  onClose(handler: (reason: CloseReason) => void): Unsubscribe {
    if (this.#closed) {
      return () => {};
    }
    return subscribe(this.#closeHandlers, handler);
  }

  /** Idempotently stops the endpoint and rejects outstanding operations. */
  close(): void {
    this.#teardown({ reason: "close" }, new ClosedError());
  }

  [Symbol.dispose](): void {
    this.close();
  }

  /** Returns this endpoint's base58 peer ID. */
  peerId(): string {
    this.#assertOpen();
    return this.#backend.peerId();
  }

  /** Returns the currently bound peer multiaddresses. */
  listenAddrs(): string[] {
    this.#assertOpen();
    return this.#backend.listenAddrs();
  }

  /** Returns peer IDs with live transport connections. */
  connectedPeers(): string[] {
    this.#assertOpen();
    return this.#backend.connectedPeers();
  }

  /** Returns whether Identify completed for a connected peer. */
  isPeerReady(peerId: string): boolean {
    this.#assertOpen();
    return this.#backend.isPeerReady(peerId);
  }

  /** Returns the latest Identify snapshot for `peerId`. */
  peerInfo(peerId: string): IdentifyInfo | undefined {
    this.#assertOpen();
    return this.#backend.peerInfo(peerId);
  }

  /** Returns the normalized multi-source discovery address book. */
  knownPeers(): KnownPeerInfo[] {
    this.#assertOpen();
    return this.#backend.knownPeers();
  }

  /** Returns the discovery monotonic clock when discovery is enabled. */
  discoveryNowMs(): number | undefined {
    this.#assertOpen();
    return this.#backend.discoveryNowMs();
  }

  /** Returns the active relay reservation, if any. */
  activeReservation(): RelayReservationInfo | undefined {
    this.#assertOpen();
    return this.#backend.activeReservation();
  }

  /** Returns this endpoint's usable circuit address, if reserved. */
  get circuitAddress(): string | undefined {
    const reservation = this.activeReservation();
    if (reservation === undefined) {
      return undefined;
    }
    const relay = this.#relayAddrs.find((address) =>
      address.endsWith(`/p2p/${reservation.relayPeerId}`)
    );
    return relay === undefined
      ? undefined
      : this.#backend.circuitAddress(relay, this.peerId());
  }

  /** Returns the latest AutoNAT reachability verdict. */
  reachability(): Reachability {
    this.#assertOpen();
    return this.#backend.reachability();
  }

  /** Returns the authoritative active path to `peerId`, if connected. */
  path(peerId: string): Path | undefined {
    this.#assertOpen();
    const path = this.#backend.path(peerId);
    return path === undefined ? undefined : normalizePath(path);
  }

  /** Returns whether the native driver is accepting work. */
  isRunning(): boolean {
    return !this.#closed && this.#backend.isRunning();
  }

  /** Selects foreground or idle native polling behavior. */
  setActive(active: boolean): void {
    this.#assertOpen();
    this.#backend.setActive(active);
  }

  /** Subscribes to a pubsub topic; returns whether the set changed. */
  subscribe(topic: string): boolean {
    this.#assertOpen();
    return this.#backend.subscribe(topic);
  }

  /** Unsubscribes from a pubsub topic; returns whether the set changed. */
  unsubscribe(topic: string): boolean {
    this.#assertOpen();
    return this.#backend.unsubscribe(topic);
  }

  /** Publishes UTF-8 text or bytes to a subscribed pubsub topic. */
  publish(topic: string, data: string | Bytes): void {
    this.#assertOpen();
    this.#backend.publish(topic, toUint8Array(data));
  }

  /** Registers an application protocol for future inbound streams. */
  addProtocol(protocolId: string): void {
    this.#assertOpen();
    this.#backend.addProtocol(protocolId);
  }

  /** Waits for Identify readiness or rejects if the peer disconnects. */
  waitPeerReady(
    peerId: string,
    options: OpOptions = {}
  ): Promise<{
    readonly peerId: string;
    readonly protocols: readonly string[];
  }> {
    const info = this.isPeerReady(peerId) ? this.peerInfo(peerId) : undefined;
    if (info !== undefined) {
      return Promise.resolve({ peerId, protocols: info.protocols });
    }
    const controller = new AbortController();
    if (options.signal?.aborted === true) {
      controller.abort();
    }
    const removeExternalAbort = listenAbort(options.signal, () => {
      controller.abort();
    });
    const ready = this.waitFor("peerReady", {
      ...options,
      predicate: (event) => event.peerId === peerId,
      signal: controller.signal,
    }).then(({ protocols }) => ({ peerId, protocols }));
    const disconnected = this.waitFor("connectionClosed", {
      ...options,
      predicate: (event) =>
        event.peerId === peerId &&
        !this.#backend.connectedPeers().includes(peerId),
      signal: controller.signal,
    }).then(() => {
      throw new PeerDisconnectedError(peerId, "waitPeerReady");
    });
    return Promise.race([ready, disconnected]).finally(() => {
      removeExternalAbort?.();
      controller.abort();
    });
  }

  /** Measures round-trip latency in milliseconds, coalescing concurrent calls. */
  ping(peerId: string, options: OpOptions = {}): Promise<number> {
    this.#assertOpen();
    let operation = this.#pings.get(peerId);
    if (operation === undefined) {
      operation = this.#runPing(peerId);
      this.#pings.set(peerId, operation);
      const current = operation;
      void operation.promise.then(
        () => this.#removePing(peerId, current),
        () => this.#removePing(peerId, current)
      );
      this.#backend.ping(peerId);
    }
    operation.callers += 1;
    const current = operation;
    return withOptions(operation.promise, options).finally(() => {
      current.callers -= 1;
      if (current.callers === 0 && this.#pings.get(peerId) === current) {
        current.cancel(new AbortError("No ping callers remain"));
        this.#pings.delete(peerId);
      }
    });
  }

  /** Opens and negotiates an application-protocol stream. */
  openStream(
    peerId: string,
    protocolId: string,
    options: OpOptions = {}
  ): Promise<Stream> {
    this.#assertOpen();
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    assertTimeout(timeoutMs);
    if (options.signal?.aborted === true) {
      return Promise.reject(new AbortError());
    }
    let identity: { readonly connId: number; readonly streamId: number };
    try {
      identity = this.#backend.openStream(peerId, protocolId);
    } catch (error) {
      return Promise.reject(
        new OpenStreamError({
          detail: errorMessage(error),
          kind: "synchronous",
          peerId,
        })
      );
    }
    return new Promise((resolve, reject) => {
      const pending: PendingOpen = {
        connId: identity.connId,
        peerId,
        protocolId,
        reject,
        resolve,
        streamId: identity.streamId,
      };
      if (timeoutMs > 0) {
        pending.timer = setTimeout(() => {
          this.#expireOpen(pending, new TimeoutError(timeoutMs));
        }, timeoutMs);
      }
      pending.removeAbort = listenAbort(options.signal, () => {
        this.#expireOpen(pending, new AbortError());
      });
      const key = pendingOpenKey(peerId, identity.connId, identity.streamId);
      const overwritten = this.#pendingOpens.get(key);
      if (overwritten !== undefined) {
        clearPendingOpen(overwritten);
        overwritten.reject(
          new OpenStreamError({
            connId: overwritten.connId,
            detail: "The native backend reused an in-flight stream identity",
            kind: "synchronous",
            peerId: overwritten.peerId,
            streamId: overwritten.streamId,
          })
        );
      }
      this.#pendingOpens.set(key, pending);
    });
  }

  /** Starts an advanced NAT-orchestrated connection attempt. */
  startConnect(peerId: string): number {
    this.#assertOpen();
    return this.#rememberConnect(this.#backend.connect(peerId));
  }

  /** Starts a connection attempt with an explicit ordered address set. */
  startConnectWithAddrs(peerId: string, addresses: readonly string[]): number {
    this.#assertOpen();
    return this.#rememberConnect(
      this.#backend.connectWithAddrs(peerId, addresses)
    );
  }

  /** Starts a connection attempt from one full peer multiaddress. */
  startConnectAddr(address: string): number {
    this.#assertOpen();
    return this.#rememberConnect(this.#backend.connectAddr(address));
  }

  /** Connects to a known peer and resolves with its first usable path. */
  connect(peerId: string, options: OpOptions = {}): Promise<ConnectResult> {
    return this.#primaryConnect(this.startConnect(peerId), options);
  }

  /** Connects using an explicit ordered address set. */
  connectWithAddrs(
    peerId: string,
    addresses: readonly string[],
    options: OpOptions = {}
  ): Promise<ConnectResult> {
    return this.#primaryConnect(
      this.startConnectWithAddrs(peerId, addresses),
      options
    );
  }

  /** Connects using one full peer multiaddress. */
  connectAddr(
    address: string,
    options: OpOptions = {}
  ): Promise<ConnectResult> {
    return this.#primaryConnect(this.startConnectAddr(address), options);
  }

  /** Consumes the terminal result for a `startConnect*` attempt. */
  waitConnectResult(
    connectId: number,
    options: OpOptions = {}
  ): Promise<ConnectResult> {
    this.#assertOpen();
    assertId(connectId, "connectId");
    const attempt = this.#connects.get(connectId);
    if (attempt === undefined || attempt.waiting) {
      return Promise.reject(new ConnectResultUnavailableError(connectId));
    }
    if (attempt.terminal !== undefined) {
      this.#connects.delete(connectId);
      this.#terminalConnects.delete(connectId);
      return attempt.terminal.ok
        ? Promise.resolve(attempt.terminal.result)
        : Promise.reject(attempt.terminal.error);
    }
    attempt.waiting = true;
    const result = new Promise<ConnectResult>((resolve, reject) => {
      attempt.resolve = resolve;
      attempt.reject = reject;
    });
    return withOptions(result, options, () => {
      this.cancelConnect(connectId);
    }).finally(() => {
      this.#connects.delete(connectId);
    });
  }

  /** Cancels an in-flight advanced connection attempt. */
  cancelConnect(connectId: number): void {
    this.#assertOpen();
    assertId(connectId, "connectId");
    this.#backend.cancelConnect(connectId);
    const attempt = this.#connects.get(connectId);
    attempt?.reject?.(new AbortError("The connection attempt was cancelled"));
    this.#connects.delete(connectId);
    this.#terminalConnects.delete(connectId);
  }

  /** Starts direct transport dials for every applicable local address family. */
  dial(address: string): number[] {
    this.#assertOpen();
    return this.#backend.dial(address);
  }

  /** Starts a direct IPv4 transport dial. */
  dialIp4(address: string): number {
    this.#assertOpen();
    return this.#backend.dialIp4(address);
  }

  /** Starts a direct IPv6 transport dial. */
  dialIp6(address: string): number {
    this.#assertOpen();
    return this.#backend.dialIp6(address);
  }

  /** Closes the active connection to `peerId`. */
  disconnect(peerId: string): void {
    this.#assertOpen();
    this.#backend.disconnect(peerId);
  }

  #rememberConnect(connectId: number): number {
    this.#connects.set(connectId, { waiting: false });
    return connectId;
  }

  #primaryConnect(
    connectId: number,
    options: OpOptions
  ): Promise<ConnectResult> {
    return this.waitConnectResult(connectId, options);
  }

  #runPing(peerId: string): PingOperation {
    let settled = false;
    let rejectOperation: (error: unknown) => void = () => {};
    let cleanup: () => void = () => {};
    const promise = new Promise<number>((resolve, reject) => {
      rejectOperation = reject;
      const offRtt = this.on("pingRttMeasured", (event) => {
        if (event.peerId === peerId) {
          finish();
          resolve(event.rttMs);
        }
      });
      const offTimeout = this.on("pingTimeout", (event) => {
        if (event.peerId === peerId) {
          finish();
          reject(new TimeoutError());
        }
      });
      const offClosed = this.on("connectionClosed", (event) => {
        if (
          event.peerId === peerId &&
          !this.#backend.connectedPeers().includes(peerId)
        ) {
          finish();
          reject(new PeerDisconnectedError(peerId, "ping"));
        }
      });
      cleanup = () => {
        offRtt();
        offTimeout();
        offClosed();
      };
      const finish = () => {
        if (!settled) {
          settled = true;
          cleanup();
        }
      };
    });
    return {
      callers: 0,
      cancel: (error) => {
        if (!settled) {
          settled = true;
          cleanup();
          rejectOperation(error);
        }
      },
      promise,
    };
  }

  #removePing(peerId: string, operation: PingOperation): void {
    if (this.#pings.get(peerId) === operation) {
      this.#pings.delete(peerId);
    }
  }

  #handleQueueOverflow(): void {
    const error = new EventQueueOverflowError();
    for (const waiter of [...this.#waiters]) {
      this.#settleWaiter(waiter, error);
    }
    for (const ping of this.#pings.values()) {
      ping.cancel(error);
    }
    this.#pings.clear();
    for (const [connectId, attempt] of [...this.#connects]) {
      if (attempt.terminal === undefined) {
        attempt.reject?.(error);
        this.#connects.delete(connectId);
        this.#terminalConnects.delete(connectId);
      }
    }
    for (const pending of this.#pendingOpens.values()) {
      clearPendingOpen(pending);
      pending.reject(error);
      try {
        this.#backend.abandonStream(pending.peerId, pending.streamId);
      } catch {
        // The operation is already failed; native cleanup is best effort.
      }
    }
    this.#pendingOpens.clear();
  }

  #enqueueNative(event: P2pEvent): void {
    if (this.#closed) {
      return;
    }
    const dropped = this.#queue.push({ event, source: "native" });
    if (dropped !== undefined) {
      this.#releaseQueueItem(dropped);
      this.#dropped += 1;
      this.#handleQueueOverflow();
    }
    this.#scheduleFlush();
  }

  #enqueueHigh(
    type: "handlerError",
    payload: Minip2pCatchAllEventMap["handlerError"]
  ): void {
    if (this.#closed) {
      return;
    }
    const dropped = this.#queue.push({ payload, source: "high", type });
    if (dropped !== undefined) {
      this.#releaseQueueItem(dropped);
      this.#dropped += 1;
      this.#handleQueueOverflow();
    }
    this.#scheduleFlush();
  }

  #scheduleFlush(): void {
    if (this.#flushScheduled) {
      return;
    }
    this.#flushScheduled = true;
    Promise.resolve().then(() => {
      this.#flush();
    });
  }

  #flush(): void {
    if (this.#closed) {
      return;
    }
    this.#flushScheduled = false;
    let delivered = 0;
    if (this.#dropped > 0) {
      const dropped = this.#dropped;
      this.#dropped = 0;
      this.#dispatch("queueOverflow", { dropped }, { dropped });
      delivered += 1;
    }
    while (delivered < EVENT_FLUSH_BATCH) {
      const item = this.#queue.shift();
      if (item === undefined) {
        break;
      }
      if (item.source === "native") {
        try {
          this.#dispatchNative(item.event);
        } finally {
          this.#releaseQueueItem(item);
        }
      } else {
        this.#dispatch(item.type, item.payload, item.payload);
      }
      delivered += 1;
      if (this.#closed) {
        return;
      }
    }
    if (this.#queue.length > 0) {
      this.#flushScheduled = true;
      setTimeout(() => {
        this.#flush();
      }, 0);
    }
  }

  #dispatchNative(event: P2pEvent): void {
    if (event.tag === P2pEvent_Tags.DriverFailed) {
      const failure = new DriverFailedError(
        event.inner.kind,
        event.inner.detail
      );
      this.#dispatch("driverFailed", event.inner, event.inner);
      this.#teardown({ error: failure, reason: "driverFailed" }, failure);
      return;
    }

    if (event.tag === P2pEvent_Tags.StreamReady) {
      this.#streamReady(event.inner);
      return;
    }
    if (
      event.tag === P2pEvent_Tags.StreamData ||
      event.tag === P2pEvent_Tags.StreamRemoteWriteClosed ||
      event.tag === P2pEvent_Tags.StreamClosed
    ) {
      this.#streamEvent(event);
      return;
    }
    if (event.tag === P2pEvent_Tags.EndpointError) {
      this.#correlateOpenError(event.inner);
    }
    if (event.tag === P2pEvent_Tags.ConnectionClosed) {
      this.#connectionClosed(event.inner.peerId, event.inner.connId);
    }
    if (
      event.tag === P2pEvent_Tags.PathEstablished ||
      event.tag === P2pEvent_Tags.ConnectFailed
    ) {
      this.#connectTerminal(event);
    }

    const normalized = normalizeEvent(event);
    if (normalized !== undefined) {
      this.#dispatch(
        normalized.type as never,
        normalized.payload as never,
        normalized.payload as never
      );
    }
  }

  #dispatch<Kind extends EventKind>(
    type: Kind,
    payload: Minip2pNamedEventMap[Kind],
    catchPayload: Kind extends keyof Minip2pCatchAllEventMap
      ? Minip2pCatchAllEventMap[Kind]
      : never
  ): boolean {
    let claimed = false;
    const result = eventResult(type, payload);
    for (const waiter of [...this.#waiters]) {
      if (waiter.type !== type) {
        continue;
      }
      let matched = false;
      try {
        matched = waiter.predicate(result as never);
      } catch (error) {
        this.#settleWaiter(waiter, error);
        continue;
      }
      if (matched) {
        claimed = true;
        this.#waiters.delete(waiter);
        clearTimeout(waiter.timer);
        waiter.removeAbort?.();
        waiter.resolve(result as never);
      }
    }

    const handlers = [...(this.#named.get(type) ?? [])];
    for (const handler of handlers) {
      try {
        handler(payload as AnyPayload);
        if (type === "stream") {
          claimed = true;
        }
      } catch (error) {
        this.#handlerFailed(type, payload, error);
      }
    }
    if (type !== "stream") {
      const catchEvent = eventResult(
        type as keyof Minip2pCatchAllEventMap,
        catchPayload as Minip2pCatchAllEventMap[keyof Minip2pCatchAllEventMap]
      ) as Minip2pEvent;
      for (const handler of [...this.#catchAll]) {
        try {
          handler(catchEvent);
        } catch (error) {
          this.#handlerFailed(type, payload, error);
        }
      }
    }
    return claimed;
  }

  #handlerFailed(type: EventKind, payload: AnyPayload, error: unknown): void {
    if (type === "handlerError") {
      return;
    }
    this.#enqueueHigh("handlerError", {
      error,
      eventType: type,
      metadata:
        type === "stream"
          ? { ...streamMeta(payload as Stream) }
          : safeMetadata(payload),
    });
  }

  #streamReady(meta: InboundStreamMeta): void {
    const key = streamKey(meta.peerId, meta.connId, meta.streamId);
    const stream = new Stream(this.#backend, meta, () => {
      this.#streams.delete(key);
    });
    this.#streams.set(key, stream);
    const pendingKey = pendingOpenKey(meta.peerId, meta.connId, meta.streamId);
    const pending = this.#pendingOpens.get(pendingKey);
    if (pending !== undefined && meta.initiatedLocally) {
      this.#pendingOpens.delete(pendingKey);
      clearPendingOpen(pending);
      pending.resolve(stream);
      return;
    }
    if (meta.initiatedLocally) {
      stream.abandon();
      return;
    }
    const claimed = this.#dispatch("stream", stream, undefined as never);
    const inbound = streamMeta(stream);
    this.#dispatchCatchOnly("inboundStream", inbound);
    if (!claimed) {
      stream.abandon();
    }
  }

  #dispatchCatchOnly<Kind extends keyof Minip2pCatchAllEventMap>(
    type: Kind,
    payload: Minip2pCatchAllEventMap[Kind]
  ): void {
    const event = eventResult(type, payload) as unknown as Minip2pEvent;
    for (const handler of [...this.#catchAll]) {
      try {
        handler(event);
      } catch (error) {
        this.#enqueueHigh("handlerError", {
          error,
          eventType: type,
          metadata: safeMetadata(payload),
        });
      }
    }
  }

  #streamEvent(
    event: Extract<
      P2pEvent,
      {
        readonly tag:
          | typeof P2pEvent_Tags.StreamData
          | typeof P2pEvent_Tags.StreamRemoteWriteClosed
          | typeof P2pEvent_Tags.StreamClosed;
      }
    >
  ): void {
    const { peerId, connId, streamId } = event.inner;
    const stream = this.#streams.get(streamKey(peerId, connId, streamId));
    if (event.tag === P2pEvent_Tags.StreamClosed) {
      const pendingKey = pendingOpenKey(peerId, connId, streamId);
      const pending = this.#pendingOpens.get(pendingKey);
      if (pending !== undefined) {
        this.#pendingOpens.delete(pendingKey);
        clearPendingOpen(pending);
        pending.reject(new StreamClosedError());
      }
      stream?.terminal(new StreamClosedError("The stream closed"));
    } else if (event.tag === P2pEvent_Tags.StreamData) {
      stream?.receive(event.inner.data);
    } else {
      stream?.remoteWriteClosed();
    }
  }

  #correlateOpenError(
    error: Extract<
      P2pEvent,
      { readonly tag: typeof P2pEvent_Tags.EndpointError }
    >["inner"]
  ): void {
    if (error.streamId === undefined) {
      return;
    }
    const candidates = [...this.#pendingOpens.values()].filter(
      (pending) =>
        pending.streamId === error.streamId &&
        (error.peerId === undefined || error.peerId === pending.peerId) &&
        (error.connId === undefined || error.connId === pending.connId)
    );
    if (candidates.length !== 1) {
      return;
    }
    const [pending] = candidates;
    if (pending === undefined) {
      return;
    }
    this.#pendingOpens.delete(
      pendingOpenKey(pending.peerId, pending.connId, pending.streamId)
    );
    clearPendingOpen(pending);
    pending.reject(
      new OpenStreamError({
        connId: error.connId,
        detail: error.detail,
        kind: error.kind,
        peerId: pending.peerId,
        streamId: error.streamId,
      })
    );
  }

  #connectionClosed(peerId: string, connId: number): void {
    for (const [key, stream] of [...this.#streams]) {
      if (stream.peerId === peerId && stream.connId === connId) {
        stream.terminal(new PeerDisconnectedError(peerId, "stream"));
        this.#streams.delete(key);
      }
    }
    for (const pending of [...this.#pendingOpens.values()]) {
      if (pending.peerId === peerId && pending.connId === connId) {
        this.#pendingOpens.delete(
          pendingOpenKey(pending.peerId, pending.connId, pending.streamId)
        );
        clearPendingOpen(pending);
        pending.reject(new PeerDisconnectedError(peerId, "openStream"));
      }
    }
  }

  #connectTerminal(
    event: Extract<
      P2pEvent,
      {
        readonly tag:
          | typeof P2pEvent_Tags.PathEstablished
          | typeof P2pEvent_Tags.ConnectFailed;
      }
    >
  ): void {
    const attempt = this.#connects.get(event.inner.connectId);
    if (attempt === undefined) {
      return;
    }
    const terminal: ConnectTerminal =
      event.tag === P2pEvent_Tags.PathEstablished
        ? {
            ok: true,
            result: {
              connectId: event.inner.connectId,
              path: normalizePath(event.inner.path),
              peerId: event.inner.peerId,
            },
          }
        : {
            error: new ConnectFailedError(
              event.inner.connectId,
              event.inner.peerId,
              event.inner.kind,
              event.inner.detail
            ),
            ok: false,
          };
    if (attempt.waiting) {
      if (terminal.ok) {
        attempt.resolve?.(terminal.result);
      } else {
        attempt.reject?.(terminal.error);
      }
    } else {
      attempt.terminal = terminal;
      this.#terminalConnects.delete(event.inner.connectId);
      this.#terminalConnects.add(event.inner.connectId);
      while (this.#terminalConnects.size > CONNECT_TERMINAL_CAP) {
        const oldest = this.#terminalConnects.values().next().value;
        if (oldest === undefined) {
          break;
        }
        this.#terminalConnects.delete(oldest);
        this.#connects.delete(oldest);
      }
    }
  }

  #expireOpen(pending: PendingOpen, error: unknown): void {
    const key = pendingOpenKey(
      pending.peerId,
      pending.connId,
      pending.streamId
    );
    if (this.#pendingOpens.get(key) !== pending) {
      return;
    }
    this.#pendingOpens.delete(key);
    clearPendingOpen(pending);
    pending.reject(error);
    try {
      this.#backend.abandonStream(pending.peerId, pending.streamId);
    } catch {
      // Cleanup failure must not replace the caller's timeout or abort.
    }
  }

  #settleWaiter(waiter: EventWaiter, error: unknown): void {
    this.#waiters.delete(waiter);
    clearTimeout(waiter.timer);
    waiter.removeAbort?.();
    waiter.reject(error);
  }

  #releaseQueueItem(item: QueueItem): void {
    if (item.source === "native") {
      this.#backend.eventHandled?.(item.event);
    }
  }

  #clearQueue(): void {
    let item = this.#queue.shift();
    while (item !== undefined) {
      this.#releaseQueueItem(item);
      item = this.#queue.shift();
    }
  }

  #teardown(reason: CloseReason, error: Error): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    const closeHandlers = [...this.#closeHandlers];
    this.#closeHandlers.clear();
    this.#clearQueue();
    this.#dropped = 0;
    this.#named.clear();
    this.#catchAll.clear();
    for (const waiter of [...this.#waiters]) {
      this.#settleWaiter(waiter, error);
    }
    for (const attempt of this.#connects.values()) {
      attempt.reject?.(error);
    }
    this.#connects.clear();
    this.#terminalConnects.clear();
    for (const pending of this.#pendingOpens.values()) {
      clearPendingOpen(pending);
      pending.reject(error);
    }
    this.#pendingOpens.clear();
    for (const stream of this.#streams.values()) {
      stream.terminal(error);
    }
    this.#streams.clear();
    for (const ping of this.#pings.values()) {
      ping.cancel(error);
    }
    this.#pings.clear();
    try {
      this.#backend.close();
    } finally {
      for (const handler of closeHandlers) {
        try {
          handler(reason);
        } catch {
          // Close notification is outside the now-closed event queue.
        }
      }
    }
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new ClosedError();
    }
  }
}

function normalizeEvent(
  event: Exclude<
    P2pEvent,
    {
      readonly tag:
        | typeof P2pEvent_Tags.DriverFailed
        | typeof P2pEvent_Tags.StreamReady
        | typeof P2pEvent_Tags.StreamData
        | typeof P2pEvent_Tags.StreamRemoteWriteClosed
        | typeof P2pEvent_Tags.StreamClosed;
    }
  >
):
  | {
      type: Exclude<
        EventKind,
        "stream" | "queueOverflow" | "handlerError" | "driverFailed"
      >;
      payload: AnyPayload;
    }
  | undefined {
  const names: Partial<Record<string, EventKind>> = {
    [P2pEvent_Tags.EventsDropped]: "eventsDropped",
    [P2pEvent_Tags.ConnectionEstablished]: "connectionEstablished",
    [P2pEvent_Tags.ConnectionClosed]: "connectionClosed",
    [P2pEvent_Tags.PeerReady]: "peerReady",
    [P2pEvent_Tags.IdentifyReceived]: "identifyReceived",
    [P2pEvent_Tags.PingRttMeasured]: "pingRttMeasured",
    [P2pEvent_Tags.PingTimeout]: "pingTimeout",
    [P2pEvent_Tags.EndpointError]: "endpointError",
    [P2pEvent_Tags.ReachabilityChanged]: "reachabilityChanged",
    [P2pEvent_Tags.PublicAddressesChanged]: "publicAddressesChanged",
    [P2pEvent_Tags.RelayReserved]: "relayReserved",
    [P2pEvent_Tags.RelayReservationLost]: "relayReservationLost",
    [P2pEvent_Tags.PathEstablished]: "pathEstablished",
    [P2pEvent_Tags.InboundPathEstablished]: "inboundPathEstablished",
    [P2pEvent_Tags.PathUpgraded]: "pathUpgraded",
    [P2pEvent_Tags.HolePunchFailed]: "holePunchFailed",
    [P2pEvent_Tags.FellBackToRelay]: "fellBackToRelay",
    [P2pEvent_Tags.ConnectFailed]: "connectFailed",
    [P2pEvent_Tags.InboundDirectUpgrade]: "inboundDirectUpgrade",
    [P2pEvent_Tags.Message]: "message",
    [P2pEvent_Tags.PeerSubscribed]: "peerSubscribed",
    [P2pEvent_Tags.PeerUnsubscribed]: "peerUnsubscribed",
    [P2pEvent_Tags.PubsubOutboundFailure]: "pubsubOutboundFailure",
    [P2pEvent_Tags.PubsubProtocolViolation]: "pubsubProtocolViolation",
    [P2pEvent_Tags.PeerDiscovered]: "peerDiscovered",
    [P2pEvent_Tags.PeerUpdated]: "peerUpdated",
    [P2pEvent_Tags.PeerExpired]: "peerExpired",
    [P2pEvent_Tags.DiscoveryDialFailed]: "discoveryDialFailed",
    [P2pEvent_Tags.DiscoveryProtocolViolation]: "discoveryProtocolViolation",
  };
  const type = names[event.tag];
  if (type === undefined) {
    return undefined;
  }
  let payload: unknown = event.inner;
  if (event.tag === P2pEvent_Tags.PathEstablished) {
    payload = { ...event.inner, path: normalizePath(event.inner.path) };
  } else if (event.tag === P2pEvent_Tags.InboundPathEstablished) {
    payload = { ...event.inner, path: normalizePath(event.inner.path) };
  } else if (event.tag === P2pEvent_Tags.PathUpgraded) {
    payload = {
      ...event.inner,
      from: normalizePath(event.inner.from),
      to: normalizePath(event.inner.to),
    };
  }
  return { payload: payload as AnyPayload, type: type as never };
}

function normalizePath(path: PathKind): Path {
  switch (path.tag) {
    case PathKind_Tags.DirectDialed: {
      return { kind: "directDialed" };
    }
    case PathKind_Tags.DirectPunched: {
      return { kind: "directPunched" };
    }
    case PathKind_Tags.Relayed: {
      return { kind: "relayed", relayPeerId: path.inner.relayPeerId };
    }
  }
}

function streamKey(peerId: string, connId: number, streamId: number): string {
  return `${peerId}\u0000${connId}\u0000${streamId}`;
}

function pendingOpenKey(
  peerId: string,
  connId: number,
  streamId: number
): string {
  return streamKey(peerId, connId, streamId);
}

function streamMeta(stream: Stream): InboundStreamMeta {
  return {
    connId: stream.connId,
    initiatedLocally: stream.initiatedLocally,
    peerId: stream.peerId,
    protocolId: stream.protocolId,
    streamId: stream.streamId,
  };
}

function safeMetadata(payload: unknown): Record<string, unknown> {
  if (payload === null || typeof payload !== "object") {
    return {};
  }
  const metadata: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      value === undefined
    ) {
      metadata[key] = value;
    } else if (
      Array.isArray(value) &&
      value.every((item) => typeof item === "string")
    ) {
      metadata[key] = [...value];
    }
  }
  return metadata;
}

function eventResult<Kind extends string, Payload>(
  type: Kind,
  payload: Payload
): { readonly type: Kind } & Payload {
  if (payload instanceof Stream) {
    Object.defineProperty(payload, "type", {
      configurable: true,
      enumerable: false,
      value: type,
    });
    return payload as unknown as { readonly type: Kind } & Payload;
  }
  if (typeof payload === "object" && payload !== null) {
    return { type, ...payload };
  }
  return { type } as { readonly type: Kind } & Payload;
}

function subscribe<Value>(set: Set<Value>, value: Value): Unsubscribe {
  set.add(value);
  let active = true;
  return () => {
    if (active) {
      active = false;
      set.delete(value);
    }
  };
}

function listenAbort(
  signal: AbortSignal | undefined,
  handler: () => void
): (() => void) | undefined {
  if (signal === undefined) {
    return undefined;
  }
  signal.addEventListener("abort", handler, { once: true });
  return () => {
    signal.removeEventListener("abort", handler);
  };
}

function withOptions<Value>(
  promise: Promise<Value>,
  options: OpOptions,
  onCancel?: () => void
): Promise<Value> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  assertTimeout(timeoutMs);
  if (options.signal?.aborted === true) {
    onCancel?.();
    return Promise.reject(new AbortError());
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (callback: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      removeAbort?.();
      callback();
    };
    const removeAbort = listenAbort(options.signal, () => {
      finish(() => {
        onCancel?.();
        reject(new AbortError());
      });
    });
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        finish(() => {
          onCancel?.();
          reject(new TimeoutError(timeoutMs));
        });
      }, timeoutMs);
    }
    void promise.then(
      (value) => {
        finish(() => resolve(value));
      },
      (error: unknown) => {
        finish(() => reject(error));
      }
    );
  });
}

function clearPendingOpen(pending: PendingOpen): void {
  clearTimeout(pending.timer);
  pending.removeAbort?.();
}

function toUint8Array(value: string | Bytes): Uint8Array {
  if (typeof value === "string") {
    return new TextEncoder().encode(value);
  }
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function assertId(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}

function assertTimeout(timeoutMs: number): void {
  assertId(timeoutMs, "timeoutMs");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
