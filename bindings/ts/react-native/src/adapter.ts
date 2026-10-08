/* oxlint-disable class-methods-use-this, complexity, func-style, max-classes-per-file, no-use-before-define -- The adapter keeps its contract-complete native endpoint and public SDK subclass together, and uses hoisted conversion helpers. */

import {
  DiscoverySource,
  DriverFailureKind,
  EndpointErrorKind,
  Minip2pBase,
  NatErrorKind,
  Reachability,
} from "@minip2p/core";
import type {
  Bytes,
  ConnectionInfo,
  IdentifyInfo,
  KnownPeerInfo,
  Minip2pConfig,
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
  Minip2pBackend,
  Minip2pBackendFactory,
  BackendOpenStream,
  P2pEvent,
  PathKind,
} from "@minip2p/core/backend";

import {
  ConnectTarget,
  DiscoverySource as NativeDiscoverySource,
  DriverFailureKind as NativeDriverFailureKind,
  EndpointErrorKind as NativeEndpointErrorKind,
  NatErrorKind as NativeNatErrorKind,
  P2pEndpoint,
  Reachability as NativeReachability,
  circuitAddress as nativeCircuitAddress,
  generateSecretKey as nativeGenerateSecretKey,
  peerIdFromSecretKey as nativePeerIdFromSecretKey,
} from "./native";
import type {
  IdentifyInfo as NativeIdentifyInfo,
  KnownPeerInfo as NativeKnownPeerInfo,
  P2pEvent as NativeP2pEvent,
  P2pEventDoorbell,
  RelayReservationInfo as NativeRelayReservationInfo,
} from "./native";
import nativeModule from "./NativeMinip2p";

class ReactNativeBackend implements Minip2pBackend {
  readonly #endpoint: P2pEndpoint;
  readonly #mdnsEnabled: boolean;
  readonly #connectionIds = new ConnectionIdMap();
  #doorbell: P2pEventDoorbell | undefined;
  #events: EventDrain<NativeP2pEvent> | undefined;

  constructor(config: Minip2pConfig) {
    this.#mdnsEnabled = config.mdns !== undefined && config.mdns !== false;
    if (this.#mdnsEnabled) {
      nativeModule.setMdnsEnabled(true);
    }
    try {
      this.#endpoint = translateErrors(
        () =>
          new P2pEndpoint(
            toArrayBuffer(config.secretKey),
            resolveEndpointConfig(config)
          )
      );
    } catch (error) {
      if (this.#mdnsEnabled) {
        nativeModule.setMdnsEnabled(false);
      }
      throw error;
    }
  }

  start(listener: (event: P2pEvent) => void): void {
    this.#events = new EventDrain(
      (limit) => this.#endpoint.drainEvents(limit),
      (event) => listener(normalizeEvent(event, this.#connectionIds))
    );
    this.#doorbell = {
      onEventsReady: () => {
        this.#events?.ring();
      },
    };
    translateErrors(() => {
      this.#endpoint.start(this.#doorbell as P2pEventDoorbell);
    });
  }

  close(): void {
    try {
      this.#endpoint.stop();
      this.#events?.stop();
      this.#endpoint.uniffiDestroy();
      this.#events = undefined;
      this.#doorbell = undefined;
    } finally {
      if (this.#mdnsEnabled) {
        nativeModule.setMdnsEnabled(false);
      }
    }
  }

  peerId(): string {
    return this.#endpoint.peerId();
  }

  listenAddrs(): string[] {
    return this.#endpoint.listenAddrs();
  }

  connectedPeers(): string[] {
    return translateErrors(() => this.#endpoint.connectedPeers());
  }

  isPeerReady(peerId: string): boolean {
    return translateErrors(() => this.#endpoint.isPeerReady(peerId));
  }

  peerInfo(peerId: string): IdentifyInfo | undefined {
    const info = translateErrors(() => this.#endpoint.peerInfo(peerId));
    return info === undefined ? undefined : normalizeIdentifyInfo(info);
  }

  knownPeers(): KnownPeerInfo[] {
    return translateErrors(() =>
      this.#endpoint.knownPeers().map(normalizeKnownPeer)
    );
  }

  discoveryNowMs(): number | undefined {
    const now = translateErrors(() => this.#endpoint.discoveryNowMs());
    return now === undefined ? undefined : u64ToNumber(now, "discoveryNowMs");
  }

  activeReservation(): RelayReservationInfo | undefined {
    const reservation = translateErrors(() =>
      this.#endpoint.activeReservation()
    );
    return reservation === undefined
      ? undefined
      : normalizeReservation(reservation);
  }

  path(peerId: string): PathKind | undefined {
    const path = translateErrors(() => this.#endpoint.path(peerId));
    return path === undefined
      ? undefined
      : (normalizeBigInts(path) as PathKind);
  }

  connectionInfo(peerId: string): ConnectionInfo | undefined {
    const info = translateErrors(() => this.#endpoint.connectionInfo(peerId));
    if (info === undefined) {
      return undefined;
    }
    return {
      connId: this.#connectionIds.toPublic(info.connId),
      ...(info.remoteAddr !== undefined && { remoteAddr: info.remoteAddr }),
      ...(info.readyProtocols !== undefined && {
        readyProtocols: info.readyProtocols,
      }),
    };
  }

  circuitAddress(relayAddress: string, peerId: string): string {
    return translateErrors(() => nativeCircuitAddress(relayAddress, peerId));
  }

  reachability(): Reachability {
    return sdkName(
      Reachability,
      NativeReachability,
      translateErrors(() => this.#endpoint.reachability())
    );
  }

  isRunning(): boolean {
    return this.#endpoint.isRunning();
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
      this.#endpoint.publish(topic, toArrayBuffer(data));
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
    const result = translateErrors(() =>
      this.#endpoint.openStream(peerId, protocolId)
    );
    return {
      connId: this.#connectionIds.toPublic(result.connId),
      streamId: u64ToNumber(result.streamId, "streamId"),
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
        this.#connectionIds.toNative(connId),
        numberToU64(streamId, "streamId"),
        toArrayBuffer(data)
      )
    );
  }

  closeStreamWrite(peerId: string, connId: number, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.closeStreamWrite(
        peerId,
        this.#connectionIds.toNative(connId),
        numberToU64(streamId, "streamId")
      );
    });
  }

  resetStream(peerId: string, connId: number, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.resetStream(
        peerId,
        this.#connectionIds.toNative(connId),
        numberToU64(streamId, "streamId")
      );
    });
  }

  abandonStream(peerId: string, connId: number, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.abandonStream(
        peerId,
        this.#connectionIds.toNative(connId),
        numberToU64(streamId, "streamId")
      );
    });
  }

  streamConsumer(connId: number, streamId: number): (bytes: number) => void {
    const nativeConn = this.#connectionIds.toNative(connId);
    const nativeStream = numberToU64(streamId, "streamId");
    return (bytes) => {
      translateErrors(() => {
        this.#endpoint.streamConsumed(
          nativeConn,
          nativeStream,
          numberToU64(bytes, "bytes")
        );
      });
    };
  }

  connect(target: BackendConnectTarget): number {
    const native =
      target.kind === "peer"
        ? new ConnectTarget.Peer({ peerId: target.peerId })
        : new ConnectTarget.Addresses({ addresses: [...target.addresses] });
    return u64ToNumber(
      translateErrors(() => this.#endpoint.connect(native)),
      "connectId"
    );
  }

  cancelConnect(id: number): void {
    translateErrors(() => {
      this.#endpoint.cancelConnect(numberToU64(id, "connectId"));
    });
  }

  disconnect(peerId: string): void {
    translateErrors(() => {
      this.#endpoint.disconnect(peerId);
    });
  }
}

const backendFactory: Minip2pBackendFactory = {
  circuitAddress: (relayAddress, peerId) =>
    translateErrors(() => nativeCircuitAddress(relayAddress, peerId)),
  create: (config) => new ReactNativeBackend(config),
  generateSecretKey: () => new Uint8Array(nativeGenerateSecretKey()),
  peerIdFromSecretKey: (secretKey) =>
    translateErrors(() => nativePeerIdFromSecretKey(toArrayBuffer(secretKey))),
};

/** High-level React Native owner for one native minip2p endpoint. */
export class Minip2p extends Minip2pBase {
  private constructor(backend: Minip2pBackend, relays: readonly string[]) {
    super(backend, relays);
  }

  /** Constructs and starts a React Native endpoint. */
  static create(config: Minip2pConfig): Minip2p {
    return new Minip2p(backendFactory.create(config), config.relays ?? []);
  }
}

/** Generates a new 32-byte Ed25519 secret key. */
export function generateSecretKey(): Uint8Array {
  return backendFactory.generateSecretKey();
}

/** Derives a peer ID from raw Ed25519 secret key material. */
export function peerIdFromSecretKey(secretKey: Bytes): string {
  return backendFactory.peerIdFromSecretKey(secretKey);
}

/** Builds a circuit multiaddress through a direct QUIC or TCP relay address. */
export function circuitAddress(relayAddress: string, peerId: string): string {
  return backendFactory.circuitAddress(relayAddress, peerId);
}

/**
 * A generated UniFFI enum: numeric members plus TypeScript's reverse mapping
 * from each number to its variant name.
 */
type NativeEnum = Readonly<Record<number, string>>;

/** An SDK enum: each variant name maps to itself. */
type SdkEnum<Name extends string> = Readonly<Record<Name, Name>>;

/**
 * The SDK name of a generated enum value. UniFFI numbers flat enums while
 * the SDK uses the Rust variant names, so this goes through the generated
 * reverse mapping rather than a parallel numeric table.
 */
function sdkName<Name extends string>(
  names: SdkEnum<Name>,
  native: NativeEnum,
  value: number
): Name {
  const name = native[value];
  const isName = (candidate: string): candidate is Name =>
    Object.hasOwn(names, candidate);
  if (name === undefined || !isName(name)) {
    throw new TypeError(
      `The native endpoint returned an unknown enum ${value}`
    );
  }
  return names[name];
}

/** Event fields carrying a generated enum, with its SDK counterpart. */
const ENUM_FIELDS: Readonly<
  Record<
    string,
    Readonly<Record<string, readonly [SdkEnum<string>, NativeEnum]>>
  >
> = {
  ConnectFailed: { kind: [NatErrorKind, NativeNatErrorKind] },
  DiscoveryProtocolViolation: {
    source: [DiscoverySource, NativeDiscoverySource],
  },
  DriverFailed: { kind: [DriverFailureKind, NativeDriverFailureKind] },
  EndpointError: { kind: [EndpointErrorKind, NativeEndpointErrorKind] },
  PeerDiscovered: { source: [DiscoverySource, NativeDiscoverySource] },
  PeerUpdated: { source: [DiscoverySource, NativeDiscoverySource] },
  ReachabilityChanged: {
    current: [Reachability, NativeReachability],
    previous: [Reachability, NativeReachability],
  },
};

function normalizeEvent(
  event: NativeP2pEvent,
  connectionIds: ConnectionIdMap
): P2pEvent {
  const inner = normalizeBigInts(event.inner, connectionIds);
  if (inner === null || typeof inner !== "object") {
    throw new TypeError("The native endpoint returned an invalid event");
  }
  const enumFields = Object.entries(ENUM_FIELDS[event.tag] ?? {}).map(
    ([field, [names, native]]) => {
      const value: unknown = Reflect.get(inner, field);
      if (typeof value !== "number") {
        throw new TypeError(`The native ${event.tag} has an invalid ${field}`);
      }
      return [field, sdkName(names, native, value)] as const;
    }
  );
  // The generated event and the SDK event share one shape (see the
  // `minip2p-ffi-core` UniFFI derives) once integers and enums are converted.
  const normalized = {
    inner: { ...inner, ...Object.fromEntries(enumFields) },
    tag: event.tag,
  } as P2pEvent;
  if (normalized.tag === P2pEvent_Tags.ConnectionClosed) {
    connectionIds.release(normalized.inner.connId);
  } else if (normalized.tag === P2pEvent_Tags.ConnectionReplaced) {
    connectionIds.release(normalized.inner.oldConnId);
  }
  return normalized;
}

function normalizeKnownPeer(peer: NativeKnownPeerInfo): KnownPeerInfo {
  return normalizeBigInts(peer) as KnownPeerInfo;
}

function normalizeIdentifyInfo(info: NativeIdentifyInfo): IdentifyInfo {
  return normalizeBigInts(info) as IdentifyInfo;
}

function normalizeReservation(
  reservation: NativeRelayReservationInfo
): RelayReservationInfo {
  return normalizeBigInts(reservation) as RelayReservationInfo;
}

/** Event fields carrying a native connection ID. */
const CONNECTION_ID_KEYS: ReadonlySet<string> = new Set([
  "connId",
  "oldConnId",
  "newConnId",
]);

/**
 * Converts native `bigint` fields to numbers. Connection ID fields go through
 * the endpoint's connection map when one is supplied; every other `u64` keeps
 * the checked conversion.
 */
function normalizeBigInts(
  value: unknown,
  connectionIds?: ConnectionIdMap,
  key?: string
): unknown {
  if (typeof value === "bigint") {
    // A QUIC stop code is a 62-bit varint the remote picks: keep it whole.
    if (key === "errorCode") {
      return value;
    }
    return key !== undefined &&
      CONNECTION_ID_KEYS.has(key) &&
      connectionIds !== undefined
      ? connectionIds.toPublic(value)
      : u64ToNumber(value, "native u64");
  }
  if (value instanceof ArrayBuffer) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeBigInts(item, connectionIds));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([itemKey, item]) => [
        itemKey,
        normalizeBigInts(item, connectionIds, itemKey),
      ])
    );
  }
  return value;
}

function toArrayBuffer(value: Bytes): ArrayBuffer {
  if (value instanceof ArrayBuffer) {
    return value;
  }
  return Uint8Array.from(value).buffer;
}

function numberToU64(value: number, name: string): bigint {
  assertSafeUnsignedInteger(value, name);
  return BigInt(value);
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
    throw typedFfiError(getErrorTag(error), getErrorDetail(error)) ?? error;
  }
}

function getErrorTag(error: unknown): string | undefined {
  return typeof error === "object" &&
    error !== null &&
    "tag" in error &&
    typeof error.tag === "string"
    ? error.tag
    : undefined;
}

function getErrorDetail(error: unknown): string | undefined {
  if (
    typeof error === "object" &&
    error !== null &&
    "inner" in error &&
    typeof error.inner === "object" &&
    error.inner !== null &&
    "detail" in error.inner &&
    typeof error.inner.detail === "string"
  ) {
    return error.inner.detail;
  }
  return undefined;
}
