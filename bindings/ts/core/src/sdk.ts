/* oxlint-disable func-style, max-classes-per-file, no-use-before-define, promise/avoid-new, promise/prefer-await-to-then, unicorn/no-useless-spread -- The SDK uses a private queue class, hoisted helpers and Promise adapters, schedules same-tick events on a microtask, and snapshots observer sets before callbacks mutate them. */

import type { MiniP2pBackend } from "./backend.js";
import {
  ClosedError,
  ConnectCancelledError,
  DriverFailedError,
  PeerDisconnectedError,
  TimeoutError,
} from "./errors.js";
import { P2pEvent_Tags } from "./types.js";
import type {
  Bytes,
  IdentifyInfo,
  KnownPeerInfo,
  MiniP2pEvent,
  P2pEvent,
  P2pEventByTag,
  Reachability,
  RelayReservationInfo,
  Unsubscribe,
} from "./types.js";

declare const TextEncoder: new () => {
  encode: (input: string) => Uint8Array;
};

const QUEUE_CAP = 4096;
const FLUSH_BATCH = 256;
const CONNECT_RESULT_CAP = 1024;
const CANCELLED_CONNECT_CAP = 1024;
const REPLACEABLE_EVENTS = new Set<P2pEvent_Tags>([
  P2pEvent_Tags.ReachabilityChanged,
  P2pEvent_Tags.PublicAddressesChanged,
]);

type EventHandler = (event: MiniP2pEvent) => void;
interface Waiter {
  connectId?: number;
  predicate: (event: MiniP2pEvent) => boolean;
  resolve: (event: MiniP2pEvent) => void;
  reject: (error: Error) => void;
  timer?: ReturnType<typeof setTimeout>;
}

interface EventNode {
  readonly event: P2pEvent;
  previous?: EventNode;
  next?: EventNode;
}

/**
 * A bounded FIFO with constant-time front removal and payload eviction.
 *
 * Replaceable-event indexes let overflow compaction visit only candidates
 * that can actually be discarded rather than rebuilding the entire queue.
 */
class EventQueue {
  readonly #payloads = new Set<EventNode>();
  readonly #replaceable = new Map<P2pEvent_Tags, Set<EventNode>>();
  #head?: EventNode;
  #tail?: EventNode;
  #size = 0;

  get size(): number {
    return this.#size;
  }

  clear(): void {
    this.#head = undefined;
    this.#tail = undefined;
    this.#size = 0;
    this.#payloads.clear();
    this.#replaceable.clear();
  }

  push(event: P2pEvent): number {
    let dropped = 0;
    if (this.#size >= QUEUE_CAP) {
      dropped += this.#compactReplaceable();
    }
    if (this.#size >= QUEUE_CAP) {
      const payload = this.#payloads.values().next().value;
      if (payload === undefined) {
        this.shift();
      } else {
        this.#remove(payload);
      }
      dropped += 1;
    }

    const node: EventNode = { event, previous: this.#tail };
    if (this.#tail === undefined) {
      this.#head = node;
    } else {
      this.#tail.next = node;
    }
    this.#tail = node;
    this.#size += 1;
    this.#index(node);
    return dropped;
  }

  shift(): P2pEvent | undefined {
    const node = this.#head;
    if (node === undefined) {
      return undefined;
    }
    this.#remove(node);
    return node.event;
  }

  #compactReplaceable(): number {
    let dropped = 0;
    for (const nodes of this.#replaceable.values()) {
      if (nodes.size < 2) {
        continue;
      }
      const latest = [...nodes].at(-1);
      for (const node of [...nodes]) {
        if (node !== latest) {
          this.#remove(node);
          dropped += 1;
        }
      }
    }
    return dropped;
  }

  #index(node: EventNode): void {
    if (
      node.event.tag === P2pEvent_Tags.Message ||
      node.event.tag === P2pEvent_Tags.StreamData
    ) {
      this.#payloads.add(node);
    }
    if (REPLACEABLE_EVENTS.has(node.event.tag)) {
      let nodes = this.#replaceable.get(node.event.tag);
      if (nodes === undefined) {
        nodes = new Set();
        this.#replaceable.set(node.event.tag, nodes);
      }
      nodes.add(node);
    }
  }

  #remove(node: EventNode): void {
    if (node.previous === undefined) {
      this.#head = node.next;
    } else {
      node.previous.next = node.next;
    }
    if (node.next === undefined) {
      this.#tail = node.previous;
    } else {
      node.next.previous = node.previous;
    }

    this.#payloads.delete(node);
    const replaceable = this.#replaceable.get(node.event.tag);
    replaceable?.delete(node);
    if (replaceable?.size === 0) {
      this.#replaceable.delete(node.event.tag);
    }
    this.#size -= 1;
  }
}

/**
 * Platform-neutral owner for one native minip2p endpoint.
 *
 * Platform packages extend this class and expose a zero-argument `create`
 * method backed by their native adapter.
 */
export class MiniP2pBase {
  readonly #backend: MiniP2pBackend;
  readonly #relayAddrs: readonly string[];
  readonly #handlers = new Set<EventHandler>();
  readonly #waiters = new Set<Waiter>();
  readonly #queue = new EventQueue();
  readonly #connectResults = new Map<
    number,
    | P2pEventByTag<P2pEvent_Tags.PathEstablished>
    | P2pEventByTag<P2pEvent_Tags.ConnectFailed>
  >();
  readonly #cancelledConnectIds = new Set<number>();
  #overflowDropped = 0;
  #flushScheduled = false;
  #closed = false;

  protected constructor(
    backend: MiniP2pBackend,
    relayAddresses: readonly string[]
  ) {
    this.#backend = backend;
    this.#relayAddrs = relayAddresses;
    try {
      this.#backend.start((event) => {
        this.#enqueue(event);
      });
    } catch (error) {
      this.#backend.close();
      throw error;
    }
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
  waitFor<EventType extends MiniP2pEvent>(
    predicate: (event: MiniP2pEvent) => event is EventType,
    timeoutMs?: number
  ): Promise<EventType>;
  waitFor(
    predicate: (event: MiniP2pEvent) => boolean,
    timeoutMs?: number
  ): Promise<MiniP2pEvent>;
  waitFor(
    predicate: (event: MiniP2pEvent) => boolean,
    timeoutMs = 65_000
  ): Promise<MiniP2pEvent> {
    return this.#waitFor(predicate, timeoutMs);
  }

  #waitFor<EventType extends MiniP2pEvent>(
    predicate: (event: MiniP2pEvent) => event is EventType,
    timeoutMs: number,
    connectId?: number
  ): Promise<EventType>;
  #waitFor(
    predicate: (event: MiniP2pEvent) => boolean,
    timeoutMs: number,
    connectId?: number
  ): Promise<MiniP2pEvent>;
  #waitFor(
    predicate: (event: MiniP2pEvent) => boolean,
    timeoutMs: number,
    connectId?: number
  ): Promise<MiniP2pEvent> {
    this.#assertOpen();
    assertSafeUnsignedInteger(timeoutMs, "timeoutMs");

    return new Promise((resolve, reject) => {
      const waiter: Waiter = { connectId, predicate, reject, resolve };
      if (timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          this.#waiters.delete(waiter);
          reject(new TimeoutError(timeoutMs));
        }, timeoutMs);
      }
      this.#waiters.add(waiter);
    });
  }

  /** Requests native shutdown and releases the platform backend. */
  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#queue.clear();
    this.#connectResults.clear();
    this.#cancelledConnectIds.clear();
    this.#overflowDropped = 0;
    this.#handlers.clear();
    for (const waiter of this.#waiters) {
      clearWaiterTimer(waiter);
      waiter.reject(new ClosedError());
    }
    this.#waiters.clear();
    this.#backend.close();
  }

  /** Returns the endpoint's base58 peer ID. */
  peerId(): string {
    this.#assertOpen();
    return this.#backend.peerId();
  }

  /** Returns the endpoint's bound peer addresses. */
  listenAddrs(): string[] {
    this.#assertOpen();
    return this.#backend.listenAddrs();
  }

  /** Returns currently connected peer IDs. */
  connectedPeers(): string[] {
    this.#assertOpen();
    return this.#backend.connectedPeers();
  }

  /** Returns whether Identify has completed for a connected peer. */
  isPeerReady(peerId: string): boolean {
    this.#assertOpen();
    return this.#backend.isPeerReady(peerId);
  }

  /** Returns the latest Identify snapshot for a connected peer. */
  peerInfo(peerId: string): IdentifyInfo | undefined {
    this.#assertOpen();
    return this.#backend.peerInfo(peerId);
  }

  /** Returns the normalized discovery address book. */
  knownPeers(): KnownPeerInfo[] {
    this.#assertOpen();
    return this.#backend.knownPeers();
  }

  /** Returns the native discovery monotonic clock, when discovery is enabled. */
  discoveryNowMs(): number | undefined {
    this.#assertOpen();
    return this.#backend.discoveryNowMs();
  }

  /** Returns the active relay reservation, if one exists. */
  activeReservation(): RelayReservationInfo | undefined {
    this.#assertOpen();
    return this.#backend.activeReservation();
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
      : this.#backend.circuitAddress(relayAddr, this.peerId());
  }

  /** Returns the current native reachability state. */
  reachability(): Reachability {
    this.#assertOpen();
    return this.#backend.reachability();
  }

  /** Returns whether the native driver is accepting work. */
  isRunning(): boolean {
    return !this.#closed && this.#backend.isRunning();
  }

  /** Selects foreground or idle native polling. */
  setActive(active: boolean): void {
    this.#assertOpen();
    this.#backend.setActive(active);
  }

  /** Subscribes to a pubsub topic. */
  subscribe(topic: string): boolean {
    this.#assertOpen();
    return this.#backend.subscribe(topic);
  }

  /** Withdraws a pubsub subscription. */
  unsubscribe(topic: string): boolean {
    this.#assertOpen();
    return this.#backend.unsubscribe(topic);
  }

  /** Publishes UTF-8 text or bytes. */
  publish(topic: string, data: string | Bytes): void {
    this.#assertOpen();
    this.#backend.publish(topic, toUint8Array(data));
  }

  /** Sends an explicit ping; the result is emitted as a ping event. */
  ping(peerId: string): void {
    this.#assertOpen();
    this.#backend.ping(peerId);
  }

  /** Waits until Identify completes for `peerId`. */
  waitPeerReady(
    peerId: string,
    timeoutMs = 65_000
  ): Promise<P2pEventByTag<P2pEvent_Tags.PeerReady>> {
    const info = this.isPeerReady(peerId) ? this.peerInfo(peerId) : undefined;
    if (info !== undefined) {
      return Promise.resolve({
        inner: { peerId, protocols: info.protocols },
        tag: P2pEvent_Tags.PeerReady,
      });
    }
    return this.waitFor(
      (
        event
      ): event is
        | P2pEventByTag<P2pEvent_Tags.PeerReady>
        | P2pEventByTag<P2pEvent_Tags.ConnectionClosed> =>
        "tag" in event &&
        (event.tag === P2pEvent_Tags.PeerReady ||
          event.tag === P2pEvent_Tags.ConnectionClosed) &&
        event.inner.peerId === peerId &&
        (event.tag === P2pEvent_Tags.PeerReady ||
          !this.#backend.connectedPeers().includes(peerId)),
      timeoutMs
    ).then((event) => {
      if (event.tag === P2pEvent_Tags.ConnectionClosed) {
        throw new PeerDisconnectedError(peerId);
      }
      return event;
    });
  }

  /** Waits for the next explicit or keepalive ping RTT for `peerId`. */
  waitPingRtt(
    peerId: string,
    timeoutMs = 65_000
  ): Promise<P2pEventByTag<P2pEvent_Tags.PingRttMeasured>> {
    return this.waitFor(
      (event): event is P2pEventByTag<P2pEvent_Tags.PingRttMeasured> =>
        "tag" in event &&
        event.tag === P2pEvent_Tags.PingRttMeasured &&
        event.inner.peerId === peerId,
      timeoutMs
    );
  }

  /** Registers an application protocol at runtime. */
  addProtocol(protocolId: string): void {
    this.#assertOpen();
    this.#backend.addProtocol(protocolId);
  }

  /** Opens a negotiated custom-protocol stream. */
  openStream(peerId: string, protocolId: string): number {
    this.#assertOpen();
    return this.#backend.openStream(peerId, protocolId);
  }

  /** Sends UTF-8 text or bytes on a custom-protocol stream. */
  sendStream(peerId: string, streamId: number, data: string | Bytes): void {
    this.#assertOpen();
    assertSafeUnsignedInteger(streamId, "streamId");
    this.#backend.sendStream(peerId, streamId, toUint8Array(data));
  }

  /** Half-closes the local write side of a stream. */
  closeStreamWrite(peerId: string, streamId: number): void {
    this.#assertOpen();
    assertSafeUnsignedInteger(streamId, "streamId");
    this.#backend.closeStreamWrite(peerId, streamId);
  }

  /** Resets a stream while retaining later close events. */
  resetStream(peerId: string, streamId: number): void {
    this.#assertOpen();
    assertSafeUnsignedInteger(streamId, "streamId");
    this.#backend.resetStream(peerId, streamId);
  }

  /** Resets and forgets a stream, suppressing later stream events. */
  abandonStream(peerId: string, streamId: number): void {
    this.#assertOpen();
    assertSafeUnsignedInteger(streamId, "streamId");
    this.#backend.abandonStream(peerId, streamId);
  }

  /** Starts a connection attempt and returns its endpoint-local ID. */
  connect(peerId: string): number {
    this.#assertOpen();
    return this.#backend.connect(peerId);
  }

  /** Starts a NAT connection attempt using an explicit ordered address set. */
  connectWithAddrs(peerId: string, addresses: readonly string[]): number {
    this.#assertOpen();
    return this.#backend.connectWithAddrs(peerId, addresses);
  }

  /** Waits for a connection attempt's first usable path or terminal failure. */
  waitConnectResult(
    connectId: number,
    timeoutMs = 65_000
  ): Promise<
    | P2pEventByTag<P2pEvent_Tags.PathEstablished>
    | P2pEventByTag<P2pEvent_Tags.ConnectFailed>
  > {
    assertSafeUnsignedInteger(connectId, "connectId");
    this.#assertOpen();
    if (this.#cancelledConnectIds.has(connectId)) {
      return Promise.reject(new ConnectCancelledError(connectId));
    }
    const result = this.#connectResults.get(connectId);
    if (result !== undefined) {
      this.#connectResults.delete(connectId);
      return Promise.resolve(result);
    }
    return this.#waitFor(
      (
        event
      ): event is
        | P2pEventByTag<P2pEvent_Tags.PathEstablished>
        | P2pEventByTag<P2pEvent_Tags.ConnectFailed> =>
        "tag" in event &&
        (event.tag === P2pEvent_Tags.PathEstablished ||
          event.tag === P2pEvent_Tags.ConnectFailed) &&
        event.inner.connectId === connectId,
      timeoutMs,
      connectId
    );
  }

  /** Starts a direct-address connection attempt. */
  connectAddr(address: string): number {
    this.#assertOpen();
    return this.#backend.connectAddr(address);
  }

  /** Dials a direct address on every applicable local address family. */
  dial(address: string): number[] {
    this.#assertOpen();
    return this.#backend.dial(address);
  }

  /** Dials a direct address using IPv4. */
  dialIp4(address: string): number {
    this.#assertOpen();
    return this.#backend.dialIp4(address);
  }

  /** Dials a direct address using IPv6. */
  dialIp6(address: string): number {
    this.#assertOpen();
    return this.#backend.dialIp6(address);
  }

  /** Suppresses future events for a known connection attempt. */
  cancelConnect(id: number): void {
    this.#assertOpen();
    assertSafeUnsignedInteger(id, "connectId");
    this.#backend.cancelConnect(id);
    this.#connectResults.delete(id);
    rememberBoundedSet(this.#cancelledConnectIds, id, CANCELLED_CONNECT_CAP);
    for (const waiter of [...this.#waiters]) {
      if (waiter.connectId !== id) {
        continue;
      }
      this.#waiters.delete(waiter);
      clearWaiterTimer(waiter);
      waiter.reject(new ConnectCancelledError(id));
    }
  }

  /** Closes an established connection to a peer. */
  disconnect(peerId: string): void {
    this.#assertOpen();
    this.#backend.disconnect(peerId);
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
    this.#overflowDropped += this.#queue.push(event);
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

    if (this.#overflowDropped > 0) {
      const dropped = this.#overflowDropped;
      this.#overflowDropped = 0;
      this.#dispatch({ dropped, type: "queueOverflow" });
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

    if (this.#queue.size > 0 || this.#overflowDropped > 0) {
      this.#flushScheduled = true;
      setTimeout(() => {
        this.#flush();
      }, 0);
    }
  }

  #dispatch(event: MiniP2pEvent): void {
    if (
      "tag" in event &&
      (event.tag === P2pEvent_Tags.PathEstablished ||
        event.tag === P2pEvent_Tags.ConnectFailed)
    ) {
      if (this.#cancelledConnectIds.has(event.inner.connectId)) {
        return;
      }
      rememberBoundedMap(
        this.#connectResults,
        event.inner.connectId,
        event,
        CONNECT_RESULT_CAP
      );
    }

    if ("tag" in event && event.tag === P2pEvent_Tags.DriverFailed) {
      this.#terminateDriver(event);
      return;
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
        if (waiter.connectId !== undefined) {
          this.#connectResults.delete(waiter.connectId);
        }
        waiter.resolve(event);
      }
    }

    for (const handler of [...this.#handlers]) {
      try {
        handler(event);
      } catch {
        // One host handler cannot interrupt fan-out or unwind into Rust.
      }
    }
  }

  #terminateDriver(event: P2pEventByTag<P2pEvent_Tags.DriverFailed>): void {
    this.#closed = true;
    this.#queue.clear();
    this.#connectResults.clear();
    this.#cancelledConnectIds.clear();
    this.#overflowDropped = 0;
    const handlers = [...this.#handlers];
    this.#handlers.clear();
    const failure = new DriverFailedError(event.inner.kind, event.inner.detail);
    for (const waiter of this.#waiters) {
      clearWaiterTimer(waiter);
      waiter.reject(failure);
    }
    this.#waiters.clear();

    for (const handler of handlers) {
      try {
        handler(event);
      } catch {
        // One host handler cannot interrupt fan-out or unwind into Rust.
      }
    }
    this.#backend.close();
  }
}

function rememberBoundedMap<Value>(
  map: Map<number, Value>,
  key: number,
  value: Value,
  capacity: number
): void {
  map.delete(key);
  map.set(key, value);
  if (map.size > capacity) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) {
      map.delete(oldest);
    }
  }
}

function rememberBoundedSet(
  set: Set<number>,
  value: number,
  capacity: number
): void {
  set.delete(value);
  set.add(value);
  if (set.size > capacity) {
    const oldest = set.values().next().value;
    if (oldest !== undefined) {
      set.delete(oldest);
    }
  }
}

function toUint8Array(value: string | Bytes): Uint8Array {
  if (typeof value === "string") {
    return new TextEncoder().encode(value);
  }
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function assertSafeUnsignedInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}

function clearWaiterTimer(waiter: Waiter): void {
  if (waiter.timer !== undefined) {
    clearTimeout(waiter.timer);
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
