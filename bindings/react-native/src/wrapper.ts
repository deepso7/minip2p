import {
  FfiError_Tags,
  P2pEndpoint,
  P2pEvent_Tags,
  circuitAddress as buildCircuitAddress,
  type DiscoveryOptions as NativeDiscoveryOptions,
  type EndpointConfig as NativeEndpointConfig,
  type KnownPeerInfo as NativeKnownPeerInfo,
  type P2pEvent as NativeP2pEvent,
  type P2pEventListener,
  type RelayReservationInfo as NativeRelayReservationInfo,
} from './native';

declare const TextEncoder: {
  new (): { encode(input: string): Uint8Array };
};

const QUEUE_CAP = 4096;
const FLUSH_BATCH = 256;
const REPLACEABLE_EVENTS = new Set<P2pEvent_Tags>([
  P2pEvent_Tags.ReachabilityChanged,
  P2pEvent_Tags.PublicAddressesChanged,
]);

type NormalizeBigInts<T> = T extends bigint
  ? number
  : T extends ArrayBuffer
    ? ArrayBuffer
    : T extends ReadonlyArray<infer Item>
      ? Array<NormalizeBigInts<Item>>
      : T extends object
        ? { [Key in keyof T]: NormalizeBigInts<T[Key]> }
        : T;

type EventShape<Event> = Event extends {
  readonly tag: infer Tag;
  readonly inner: infer Inner;
}
  ? { readonly tag: Tag; readonly inner: NormalizeBigInts<Inner> }
  : Event extends { readonly tag: infer Tag }
    ? { readonly tag: Tag }
    : never;

/** A generated native event with every `u64` checked and converted to number. */
export type P2pEvent = EventShape<NativeP2pEvent>;

/** Host-side notification that the TypeScript event queue discarded events. */
export type QueueOverflowEvent = {
  readonly type: 'queueOverflow';
  readonly dropped: number;
};

/** An event emitted by the high-level wrapper. */
export type MiniP2pEvent = P2pEvent | QueueOverflowEvent;

/** Removes an event subscription. */
export type Unsubscribe = () => void;

/** Signed-discovery settings accepted by the high-level wrapper. */
export type MiniP2pDiscoveryOptions = Omit<
  NativeDiscoveryOptions,
  'beaconIntervalMs' | 'peerTtlMs'
> & {
  beaconIntervalMs: number;
  peerTtlMs: number;
};

/** Configuration accepted by {@link MiniP2p.create}. */
export type MiniP2pConfig = Omit<NativeEndpointConfig, 'discovery'> & {
  secretKey: ArrayBuffer;
  discovery?: MiniP2pDiscoveryOptions;
};

type EventHandler = (event: MiniP2pEvent) => void;

type Waiter = {
  predicate: (event: MiniP2pEvent) => boolean;
  resolve: (event: MiniP2pEvent) => void;
  reject: (error: Error) => void;
  timer?: ReturnType<typeof setTimeout>;
};

/** The native pubsub queue rejected work because it is full. */
export class BackpressureError extends Error {
  constructor() {
    super('The native pubsub queue is full');
    this.name = 'BackpressureError';
  }
}

/** The payload exceeds the native pubsub protocol limit. */
export class MessageTooLargeError extends Error {
  constructor() {
    super('The message exceeds the native pubsub size limit');
    this.name = 'MessageTooLargeError';
  }
}

/** A valid operation was rejected by endpoint policy. */
export class NotPermittedError extends Error {
  constructor(message = 'The operation is not permitted') {
    super(message);
    this.name = 'NotPermittedError';
  }
}

/** A bounded wrapper wait elapsed without a matching event. */
export class TimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Timed out after ${timeoutMs} ms`);
    this.name = 'TimeoutError';
  }
}

/** The wrapper was closed before an operation could complete. */
export class ClosedError extends Error {
  constructor() {
    super('The minip2p endpoint is closed');
    this.name = 'ClosedError';
  }
}

/**
 * High-level React Native owner for one native minip2p endpoint.
 *
 * Native callbacks are buffered and flushed on the next microtask, allowing a
 * handler attached synchronously after `create` to observe immediate events.
 */
export class MiniP2p {
  readonly #endpoint: P2pEndpoint;
  readonly #listener: P2pEventListener;
  readonly #relayAddrs: ReadonlyArray<string>;
  readonly #handlers = new Set<EventHandler>();
  readonly #waiters = new Set<Waiter>();
  readonly #queue: Array<P2pEvent> = [];
  #overflowDropped = 0;
  #flushScheduled = false;
  #closed = false;

  private constructor(endpoint: P2pEndpoint, relays: ReadonlyArray<string>) {
    this.#endpoint = endpoint;
    this.#relayAddrs = relays;
    this.#listener = {
      onEvent: (event) => {
        try {
          this.#enqueue(normalizeEvent(event));
        } catch {
          // A malformed native value must not unwind through the foreign
          // callback boundary. The generated layer already validates shape.
        }
      },
    };
  }

  /** Constructs and starts an endpoint with loss-free same-tick attachment. */
  static create(config: MiniP2pConfig): MiniP2p {
    const { secretKey, discovery, ...endpointConfig } = config;
    const nativeConfig: NativeEndpointConfig = {
      ...endpointConfig,
      discovery:
        discovery === undefined
          ? undefined
          : {
              ...discovery,
              beaconIntervalMs: numberToU64(
                discovery.beaconIntervalMs,
                'beaconIntervalMs'
              ),
              peerTtlMs: numberToU64(discovery.peerTtlMs, 'peerTtlMs'),
            },
    };
    const wrapper = new MiniP2p(
      translateErrors(() => new P2pEndpoint(secretKey, nativeConfig)),
      nativeConfig.relays
    );
    translateErrors(() => wrapper.#endpoint.start(wrapper.#listener));
    return wrapper;
  }

  /** Adds an event subscriber and returns an idempotent unsubscribe function. */
  on(handler: EventHandler): Unsubscribe {
    this.#assertOpen();
    this.#handlers.add(handler);
    let subscribed = true;
    return () => {
      if (subscribed) {
        subscribed = false;
        this.#handlers.delete(handler);
      }
    };
  }

  /** Resolves with the first event matching `predicate`. */
  waitFor(
    predicate: (event: MiniP2pEvent) => boolean,
    timeoutMs = 65_000
  ): Promise<MiniP2pEvent> {
    this.#assertOpen();
    assertSafeUnsignedInteger(timeoutMs, 'timeoutMs');

    return new Promise((resolve, reject) => {
      const waiter: Waiter = { predicate, resolve, reject };
      if (timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          this.#waiters.delete(waiter);
          reject(new TimeoutError(timeoutMs));
        }, timeoutMs);
      }
      this.#waiters.add(waiter);
    });
  }

  /** Requests native shutdown and immediately releases the UniFFI object. */
  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#queue.length = 0;
    this.#overflowDropped = 0;
    this.#handlers.clear();
    for (const waiter of this.#waiters) {
      clearWaiterTimer(waiter);
      waiter.reject(new ClosedError());
    }
    this.#waiters.clear();
    this.#endpoint.stop();
    this.#endpoint.uniffiDestroy();
  }

  /** Returns the endpoint's base58 peer ID. */
  peerId(): string {
    this.#assertOpen();
    return this.#endpoint.peerId();
  }

  /** Returns the endpoint's bound peer addresses. */
  listenAddrs(): Array<string> {
    this.#assertOpen();
    return this.#endpoint.listenAddrs();
  }

  /** Returns currently connected peer IDs. */
  connectedPeers(): Array<string> {
    this.#assertOpen();
    return translateErrors(() => this.#endpoint.connectedPeers());
  }

  /** Returns the normalized signed-discovery address book. */
  knownPeers(): Array<NormalizeBigInts<NativeKnownPeerInfo>> {
    this.#assertOpen();
    return translateErrors(() =>
      this.#endpoint.knownPeers().map((peer) => normalizeBigInts(peer))
    );
  }

  /** Returns the active relay reservation, if one exists. */
  activeReservation():
    NormalizeBigInts<NativeRelayReservationInfo> | undefined {
    this.#assertOpen();
    const reservation = translateErrors(() =>
      this.#endpoint.activeReservation()
    );
    return reservation === undefined
      ? undefined
      : normalizeBigInts(reservation);
  }

  /** Returns this endpoint's currently usable circuit address, if known. */
  get circuitAddress(): string | undefined {
    const reservation = this.activeReservation();
    if (reservation === undefined) {
      return undefined;
    }
    const suffix = `/p2p/${reservation.relayPeerId}`;
    const relayAddr = this.#relayAddrs.find((addr) => addr.endsWith(suffix));
    return relayAddr === undefined
      ? undefined
      : translateErrors(() => buildCircuitAddress(relayAddr, this.peerId()));
  }

  /** Returns the current native reachability enum. */
  reachability() {
    this.#assertOpen();
    return translateErrors(() => this.#endpoint.reachability());
  }

  /** Returns whether the native driver is accepting work. */
  isRunning(): boolean {
    return !this.#closed && this.#endpoint.isRunning();
  }

  /** Selects foreground or idle native polling. */
  setActive(active: boolean): void {
    this.#assertOpen();
    this.#endpoint.setActive(active);
  }

  /** Subscribes to a pubsub topic. */
  subscribe(topic: string): boolean {
    this.#assertOpen();
    return translateErrors(() => this.#endpoint.subscribe(topic));
  }

  /** Withdraws a pubsub subscription. */
  unsubscribe(topic: string): boolean {
    this.#assertOpen();
    return translateErrors(() => this.#endpoint.unsubscribe(topic));
  }

  /** Publishes UTF-8 text or an existing byte buffer. */
  publish(topic: string, data: string | ArrayBuffer): void {
    this.#assertOpen();
    const payload =
      typeof data === 'string'
        ? (new Uint8Array(new TextEncoder().encode(data)).buffer as ArrayBuffer)
        : data;
    translateErrors(() => this.#endpoint.publish(topic, payload));
  }

  /** Starts a connection attempt and returns its safe endpoint-local ID. */
  connect(peerId: string): number {
    this.#assertOpen();
    return u64ToNumber(
      translateErrors(() => this.#endpoint.connect(peerId)),
      'connectId'
    );
  }

  /** Starts a direct-address connection attempt. */
  connectAddr(address: string): number {
    this.#assertOpen();
    return u64ToNumber(
      translateErrors(() => this.#endpoint.connectAddr(address)),
      'connectId'
    );
  }

  /** Suppresses future events for a known connection attempt. */
  cancelConnect(id: number): void {
    this.#assertOpen();
    translateErrors(() =>
      this.#endpoint.cancelConnect(numberToU64(id, 'connectId'))
    );
  }

  /** Closes an established connection to a peer. */
  disconnect(peerId: string): void {
    this.#assertOpen();
    translateErrors(() => this.#endpoint.disconnect(peerId));
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new ClosedError();
    }
  }

  #enqueue(event: P2pEvent): void {
    if (this.#closed) {
      return;
    }
    if (this.#queue.length >= QUEUE_CAP) {
      this.#compactReplaceableEvents();
    }
    if (this.#queue.length >= QUEUE_CAP) {
      const messageIndex = this.#queue.findIndex(
        (queued) => queued.tag === P2pEvent_Tags.Message
      );
      if (messageIndex >= 0) {
        this.#queue.splice(messageIndex, 1);
      } else {
        this.#queue.shift();
      }
      this.#overflowDropped += 1;
    }
    this.#queue.push(event);
    this.#scheduleFlush();
  }

  #compactReplaceableEvents(): void {
    const latest = new Set<P2pEvent_Tags>();
    const compacted: Array<P2pEvent> = [];
    for (let index = this.#queue.length - 1; index >= 0; index -= 1) {
      const event = this.#queue[index];
      if (event === undefined) {
        continue;
      }
      if (REPLACEABLE_EVENTS.has(event.tag)) {
        if (latest.has(event.tag)) {
          this.#overflowDropped += 1;
          continue;
        }
        latest.add(event.tag);
      }
      compacted.push(event);
    }
    compacted.reverse();
    this.#queue.length = 0;
    this.#queue.push(...compacted);
  }

  #scheduleFlush(): void {
    if (this.#flushScheduled) {
      return;
    }
    this.#flushScheduled = true;
    Promise.resolve().then(() => this.#flush());
  }

  #flush(): void {
    if (this.#closed) {
      return;
    }
    this.#flushScheduled = false;
    let delivered = 0;

    if (this.#overflowDropped > 0) {
      const dropped = this.#overflowDropped;
      this.#overflowDropped = 0;
      this.#dispatch({ type: 'queueOverflow', dropped });
      delivered += 1;
    }

    while (delivered < FLUSH_BATCH) {
      const event = this.#queue.shift();
      if (event === undefined) {
        break;
      }
      this.#dispatch(event);
      delivered += 1;
      if (this.#closed) {
        return;
      }
    }

    if (this.#queue.length > 0 || this.#overflowDropped > 0) {
      this.#flushScheduled = true;
      setTimeout(() => {
        this.#flush();
      }, 0);
    }
  }

  #dispatch(event: MiniP2pEvent): void {
    for (const handler of [...this.#handlers]) {
      try {
        handler(event);
      } catch {
        // One host handler cannot interrupt fan-out or unwind into Rust.
      }
    }

    for (const waiter of [...this.#waiters]) {
      let matched: boolean;
      try {
        matched = waiter.predicate(event);
      } catch (error) {
        this.#waiters.delete(waiter);
        clearWaiterTimer(waiter);
        waiter.reject(asError(error));
        continue;
      }
      if (matched) {
        this.#waiters.delete(waiter);
        clearWaiterTimer(waiter);
        waiter.resolve(event);
      }
    }
  }
}

function normalizeEvent(event: NativeP2pEvent): P2pEvent {
  return {
    tag: event.tag,
    inner: normalizeBigInts(event.inner),
  } as P2pEvent;
}

function normalizeBigInts<T>(value: T): NormalizeBigInts<T> {
  if (typeof value === 'bigint') {
    return u64ToNumber(value, 'native u64') as NormalizeBigInts<T>;
  }
  if (value instanceof ArrayBuffer) {
    return value as NormalizeBigInts<T>;
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeBigInts(item)) as NormalizeBigInts<T>;
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, normalizeBigInts(item)])
    ) as NormalizeBigInts<T>;
  }
  return value as NormalizeBigInts<T>;
}

function numberToU64(value: number, name: string): bigint {
  assertSafeUnsignedInteger(value, name);
  return BigInt(value);
}

function u64ToNumber(value: bigint, name: string): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new RangeError(`${name} exceeds JavaScript's safe integer range`);
  }
  return number;
}

function assertSafeUnsignedInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}

function translateErrors<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    const tag = getErrorTag(error);
    switch (tag) {
      case FfiError_Tags.Backpressure:
        throw new BackpressureError();
      case FfiError_Tags.MessageTooLarge:
        throw new MessageTooLargeError();
      case FfiError_Tags.NotPermitted:
        throw new NotPermittedError(getErrorDetail(error));
      default:
        throw error;
    }
  }
}

function getErrorTag(error: unknown): FfiError_Tags | undefined {
  return typeof error === 'object' && error !== null && 'tag' in error
    ? (error.tag as FfiError_Tags)
    : undefined;
}

function getErrorDetail(error: unknown): string | undefined {
  if (
    typeof error === 'object' &&
    error !== null &&
    'inner' in error &&
    typeof error.inner === 'object' &&
    error.inner !== null &&
    'detail' in error.inner &&
    typeof error.inner.detail === 'string'
  ) {
    return error.inner.detail;
  }
  return undefined;
}

function clearWaiterTimer(waiter: Waiter): void {
  if (waiter.timer !== undefined) {
    clearTimeout(waiter.timer);
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
