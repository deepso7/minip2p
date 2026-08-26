/* oxlint-disable class-methods-use-this, func-style, max-classes-per-file, no-use-before-define, prefer-destructuring, unicorn/no-useless-undefined -- The adapter keeps the contract-complete native endpoint, value conversion, handle maps, and drain loop together at the binding boundary. */

import { Minip2pBase, PubsubRouter } from "@minip2p/core";
import type {
  Bytes,
  IdentifyInfo,
  KnownPeerInfo,
  Minip2pConfig,
  Minip2pDiscoveryOptions,
  Minip2pMdnsOptions,
  Minip2pTransportOptions,
  Reachability,
  RelayReservationInfo,
} from "@minip2p/core";
import type {
  BackendOpenStream,
  Minip2pBackend,
  PathKind,
  P2pEvent,
} from "@minip2p/core/backend";

import { nativeBinding } from "./native.js";
import type { NativeEndpoint } from "./native.js";

class NodeBackend implements Minip2pBackend {
  readonly #connectionIds = new IdMap();
  readonly #connectIds = new IdMap();
  readonly #endpoint: NativeEndpoint;
  readonly #events: EventDrain;
  readonly #streamIds = new IdMap();

  constructor(config: Minip2pConfig) {
    const transports = resolveTransports(config);
    const discovery = toNativeDiscovery(config.discovery);
    const mdns = toNativeMdns(config.mdns, config.discovery);
    this.#endpoint = new nativeBinding.NodeEndpoint(
      toUint8Array(config.secretKey),
      {
        agentVersion: config.agentVersion,
        allowUnsigned: config.allowUnsigned ?? false,
        autonatServers: [...(config.autonatServers ?? [])],
        discovery,
        forceRelay: config.forceRelay ?? false,
        mdns,
        protocols: [...(config.protocols ?? [])],
        pubsubRouter: config.pubsubRouter ?? PubsubRouter.Gossipsub,
        quic: toNativeTransport(transports.quic),
        relays: [...(config.relays ?? [])],
        tcp: toNativeTransport(transports.tcp),
      }
    );
    this.#events = new EventDrain(
      () => this.#endpoint.drainEvents(256),
      (event) =>
        normalizeEvent(
          event,
          this.#connectionIds,
          this.#connectIds,
          this.#streamIds
        )
    );
  }

  start(listener: (event: P2pEvent) => void): void {
    this.#events.start(listener);
    this.#endpoint.start(() => {
      this.#events.ring();
    });
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
    return this.#endpoint.connectedPeers();
  }

  isPeerReady(peerId: string): boolean {
    return this.#endpoint.isPeerReady(peerId);
  }

  peerInfo(peerId: string): IdentifyInfo | undefined {
    const info = this.#endpoint.peerInfo(peerId);
    return info === null || info === undefined
      ? undefined
      : normalizeIdentifyInfo(info);
  }

  knownPeers(): KnownPeerInfo[] {
    return this.#endpoint
      .knownPeers()
      .map((peer) => normalizeRecord<KnownPeerInfo>(peer));
  }

  discoveryNowMs(): number | undefined {
    const value = this.#endpoint.discoveryNowMs();
    return value === undefined ? undefined : bigintToNumber(value, "clock");
  }

  activeReservation(): RelayReservationInfo | undefined {
    return normalizeOptional<RelayReservationInfo>(
      this.#endpoint.activeReservation()
    );
  }

  path(peerId: string): PathKind | undefined {
    return normalizeOptional<PathKind>(this.#endpoint.path(peerId));
  }

  circuitAddress(relayAddress: string, peerId: string): string {
    return nativeBinding.circuitAddress(relayAddress, peerId);
  }

  reachability(): Reachability {
    return this.#endpoint.reachability() as Reachability;
  }

  setActive(active: boolean): void {
    this.#endpoint.setActive(active);
  }

  subscribe(topic: string): boolean {
    return this.#endpoint.subscribe(topic);
  }

  unsubscribe(topic: string): boolean {
    return this.#endpoint.unsubscribe(topic);
  }

  publish(topic: string, data: Uint8Array): void {
    this.#endpoint.publish(topic, data);
  }

  ping(peerId: string): void {
    this.#endpoint.ping(peerId);
  }

  addProtocol(protocolId: string): void {
    this.#endpoint.addProtocol(protocolId);
  }

  openStream(peerId: string, protocolId: string): BackendOpenStream {
    const stream = this.#endpoint.openStream(peerId, protocolId);
    return {
      connId: this.#connectionIds.toPublic(stream.connId),
      streamId: this.#streamIds.toPublic(stream.streamId),
    };
  }

  sendStream(peerId: string, streamId: number, data: Uint8Array): void {
    this.#endpoint.sendStream(peerId, this.#streamIds.toNative(streamId), data);
  }

  closeStreamWrite(peerId: string, streamId: number): void {
    this.#endpoint.closeStreamWrite(peerId, this.#streamIds.toNative(streamId));
  }

  resetStream(peerId: string, streamId: number): void {
    this.#endpoint.resetStream(peerId, this.#streamIds.toNative(streamId));
  }

  abandonStream(peerId: string, streamId: number): void {
    this.#endpoint.abandonStream(peerId, this.#streamIds.toNative(streamId));
  }

  connect(peerId: string): number {
    return this.#connectIds.toPublic(this.#endpoint.connect(peerId));
  }

  connectWithAddrs(peerId: string, addresses: readonly string[]): number {
    return this.#connectIds.toPublic(
      this.#endpoint.connectWithAddrs(peerId, [...addresses])
    );
  }

  connectAddr(address: string): number {
    return this.#connectIds.toPublic(this.#endpoint.connectAddr(address));
  }

  dial(address: string): number[] {
    return this.#endpoint
      .dial(address)
      .map((id) => this.#connectionIds.toPublic(id));
  }

  dialIp4(address: string): number {
    return this.#connectionIds.toPublic(this.#endpoint.dialIp4(address));
  }

  dialIp6(address: string): number {
    return this.#connectionIds.toPublic(this.#endpoint.dialIp6(address));
  }

  cancelConnect(id: number): void {
    this.#endpoint.cancelConnect(this.#connectIds.toNative(id));
  }

  disconnect(peerId: string): void {
    this.#endpoint.disconnect(peerId);
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
  return nativeBinding.peerIdFromSecretKey(toUint8Array(secretKey));
}

/** Builds a circuit multiaddress through a direct relay address. */
export function circuitAddress(relayAddress: string, peerId: string): string {
  return nativeBinding.circuitAddress(relayAddress, peerId);
}

function resolveTransports(config: Minip2pConfig) {
  const transports = config.transports;
  if (
    transports === undefined ||
    (transports.quic === undefined && transports.tcp === undefined)
  ) {
    return { quic: true } as const;
  }
  return transports;
}

function toNativeTransport(
  transport: true | Minip2pTransportOptions | undefined
): { readonly listenAddrs?: string[] } | undefined {
  if (transport === undefined) {
    return undefined;
  }
  if (transport === true || transport.listen === undefined) {
    return {};
  }
  return { listenAddrs: [...transport.listen] };
}

function toNativeDiscovery(discovery: Minip2pDiscoveryOptions | undefined) {
  return discovery === undefined
    ? undefined
    : {
        autoDial: discovery.autoDial ?? true,
        beaconIntervalMs: numberToBigInt(discovery.beaconIntervalMs ?? 10_000),
        peerTtlMs: numberToBigInt(discovery.peerTtlMs ?? 35_000),
        topic: discovery.topic,
      };
}

function toNativeMdns(
  mdns: boolean | Minip2pMdnsOptions | undefined,
  discovery: Minip2pDiscoveryOptions | undefined
) {
  const options = mdns === true ? {} : mdns;
  if (options === undefined || options === false) {
    return undefined;
  }
  return {
    autoDial: options.autoDial ?? discovery?.autoDial ?? true,
    enableIpv6: options.enableIpv6 ?? false,
    interfaceRefreshMs: numberToBigInt(options.interfaceRefreshMs ?? 10_000),
    maxAnnouncedAddrs: options.maxAnnouncedAddrs ?? 16,
    maxPacketBytes: options.maxPacketBytes ?? 1400,
    queryIntervalMs: numberToBigInt(options.queryIntervalMs ?? 300_000),
    socketPollIntervalMs: numberToBigInt(options.socketPollIntervalMs ?? 100),
    ttlMs: numberToBigInt(options.ttlMs ?? 120_000),
  };
}

function toUint8Array(value: Bytes): Uint8Array {
  return value instanceof Uint8Array
    ? Uint8Array.from(value)
    : new Uint8Array(value);
}

function numberToBigInt(value: number): bigint {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(
      "Native identifiers must be non-negative safe integers"
    );
  }
  return BigInt(value);
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
      publicKey: Uint8Array.from(publicKey).buffer,
    } as unknown as IdentifyInfo;
  }
  throw new TypeError(
    "The native addon returned an invalid Identify public key"
  );
}

function normalizeNativeValue(
  value: unknown,
  key?: string,
  maps?: NativeIdMaps
): unknown {
  if (typeof value === "number" && maps !== undefined) {
    if (key === "connId") {
      return maps.connectionIds.toPublic(BigInt(value));
    }
    if (key === "connectId") {
      return maps.connectIds.toPublic(BigInt(value));
    }
    if (key === "streamId") {
      return maps.streamIds.toPublic(BigInt(value));
    }
  }
  if (typeof value === "bigint") {
    if (key === "connId" && maps !== undefined) {
      return maps.connectionIds.toPublic(value);
    }
    if (key === "connectId" && maps !== undefined) {
      return maps.connectIds.toPublic(value);
    }
    if (key === "streamId" && maps !== undefined) {
      return maps.streamIds.toPublic(value);
    }
    return bigintToNumber(value, "native value");
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeNativeValue(item, undefined, maps));
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== null)
        .map(([itemKey, item]) => [
          itemKey,
          normalizeNativeValue(item, itemKey, maps),
        ])
    );
  }
  return value;
}

function normalizeEvent(
  value: unknown,
  connectionIds: IdMap,
  connectIds: IdMap,
  streamIds: IdMap
): P2pEvent {
  const event = normalizeNativeValue(value, undefined, {
    connectIds,
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
  return event as P2pEvent;
}

function normalizeEventBytes(tag: string, value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  const inner = { ...value };
  if (tag === "StreamData") {
    const data = Reflect.get(inner, "data");
    if (Array.isArray(data) || data instanceof Uint8Array) {
      Reflect.set(inner, "data", Uint8Array.from(data).buffer);
    }
  }
  if (tag === "Message") {
    for (const key of ["data", "seqno"] as const) {
      const bytes = Reflect.get(inner, key);
      if (Array.isArray(bytes) || bytes instanceof Uint8Array) {
        Reflect.set(inner, key, Uint8Array.from(bytes).buffer);
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

class EventDrain {
  readonly #drain: () => unknown[];
  readonly #normalize: (event: unknown) => P2pEvent;
  #listener: ((event: P2pEvent) => void) | undefined;
  #scheduled = false;
  #stopped = false;

  constructor(drain: () => unknown[], normalize: (event: unknown) => P2pEvent) {
    this.#drain = drain;
    this.#normalize = normalize;
  }

  start(listener: (event: P2pEvent) => void): void {
    this.#listener = listener;
  }

  ring(): void {
    if (this.#scheduled || this.#stopped) {
      return;
    }
    this.#scheduled = true;
    setImmediate(() => {
      this.#run();
    });
  }

  stop(): void {
    this.#stopped = true;
    this.#listener = undefined;
  }

  #run(): void {
    this.#scheduled = false;
    if (this.#stopped) {
      return;
    }
    const events = this.#drain();
    for (const event of events) {
      this.#listener?.(this.#normalize(event));
    }
    if (events.length > 0) {
      this.ring();
    }
  }
}

interface NativeIdMaps {
  readonly connectionIds: IdMap;
  readonly connectIds: IdMap;
  readonly streamIds: IdMap;
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
}
