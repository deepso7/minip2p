/* oxlint-disable class-methods-use-this, func-style, max-classes-per-file, no-use-before-define -- The adapter keeps its contract-complete native endpoint and public SDK subclass together, and uses hoisted conversion helpers. */

import {
  BackpressureError,
  MessageTooLargeError,
  MiniP2pBase,
  NotPermittedError,
  PubsubRouter,
} from "@minip2p/core";
import type {
  Bytes,
  IdentifyInfo,
  KnownPeerInfo,
  MiniP2pConfig,
  P2pEvent,
  Reachability,
  RelayReservationInfo,
} from "@minip2p/core";
import type {
  MiniP2pBackend,
  MiniP2pBackendFactory,
} from "@minip2p/core/backend";

import {
  FfiError_Tags,
  P2pEndpoint,
  circuitAddress as nativeCircuitAddress,
  generateSecretKey as nativeGenerateSecretKey,
  peerIdFromSecretKey as nativePeerIdFromSecretKey,
} from "./native";
import type {
  DiscoveryOptions as NativeDiscoveryOptions,
  EndpointConfig as NativeEndpointConfig,
  IdentifyInfo as NativeIdentifyInfo,
  KnownPeerInfo as NativeKnownPeerInfo,
  MdnsOptions as NativeMdnsOptions,
  P2pEvent as NativeP2pEvent,
  P2pEventListener,
  RelayReservationInfo as NativeRelayReservationInfo,
} from "./native";
import nativeModule from "./NativeMinip2p";

class ReactNativeBackend implements MiniP2pBackend {
  readonly #endpoint: P2pEndpoint;
  readonly #mdnsEnabled: boolean;
  #listener: P2pEventListener | undefined;

  constructor(config: MiniP2pConfig) {
    this.#mdnsEnabled = config.mdns !== undefined && config.mdns !== false;
    if (this.#mdnsEnabled) {
      nativeModule.setMdnsEnabled(true);
    }
    try {
      this.#endpoint = translateErrors(
        () =>
          new P2pEndpoint(
            toArrayBuffer(config.secretKey),
            toNativeConfig(config)
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
    this.#listener = {
      onEvent: (event) => {
        try {
          listener(normalizeEvent(event));
        } catch {
          // A malformed native value cannot unwind through the callback ABI.
        }
      },
    };
    translateErrors(() => {
      this.#endpoint.start(this.#listener as P2pEventListener);
    });
  }

  close(): void {
    try {
      this.#endpoint.stop();
      this.#endpoint.uniffiDestroy();
      this.#listener = undefined;
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

  circuitAddress(relayAddress: string, peerId: string): string {
    return translateErrors(() => nativeCircuitAddress(relayAddress, peerId));
  }

  reachability(): Reachability {
    return translateErrors(() => this.#endpoint.reachability()) as Reachability;
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

  openStream(peerId: string, protocolId: string): number {
    return u64ToNumber(
      translateErrors(() => this.#endpoint.openStream(peerId, protocolId)),
      "streamId"
    );
  }

  sendStream(peerId: string, streamId: number, data: Uint8Array): void {
    translateErrors(() => {
      this.#endpoint.sendStream(
        peerId,
        numberToU64(streamId, "streamId"),
        toArrayBuffer(data)
      );
    });
  }

  closeStreamWrite(peerId: string, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.closeStreamWrite(
        peerId,
        numberToU64(streamId, "streamId")
      );
    });
  }

  resetStream(peerId: string, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.resetStream(peerId, numberToU64(streamId, "streamId"));
    });
  }

  abandonStream(peerId: string, streamId: number): void {
    translateErrors(() => {
      this.#endpoint.abandonStream(peerId, numberToU64(streamId, "streamId"));
    });
  }

  connect(peerId: string): number {
    return u64ToNumber(
      translateErrors(() => this.#endpoint.connect(peerId)),
      "connectId"
    );
  }

  connectWithAddrs(peerId: string, addresses: readonly string[]): number {
    return u64ToNumber(
      translateErrors(() =>
        this.#endpoint.connectWithAddrs(peerId, [...addresses])
      ),
      "connectId"
    );
  }

  connectAddr(address: string): number {
    return u64ToNumber(
      translateErrors(() => this.#endpoint.connectAddr(address)),
      "connectId"
    );
  }

  dial(address: string): number[] {
    return translateErrors(() => this.#endpoint.dial(address)).map((id) =>
      u64ToNumber(id, "connectionId")
    );
  }

  dialIp4(address: string): number {
    return u64ToNumber(
      translateErrors(() => this.#endpoint.dialIp4(address)),
      "connectionId"
    );
  }

  dialIp6(address: string): number {
    return u64ToNumber(
      translateErrors(() => this.#endpoint.dialIp6(address)),
      "connectionId"
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

const backendFactory: MiniP2pBackendFactory = {
  circuitAddress: (relayAddress, peerId) =>
    translateErrors(() => nativeCircuitAddress(relayAddress, peerId)),
  create: (config) => new ReactNativeBackend(config),
  generateSecretKey: () => new Uint8Array(nativeGenerateSecretKey()),
  peerIdFromSecretKey: (secretKey) =>
    translateErrors(() => nativePeerIdFromSecretKey(toArrayBuffer(secretKey))),
};

/** High-level React Native owner for one native minip2p endpoint. */
export class MiniP2p extends MiniP2pBase {
  private constructor(backend: MiniP2pBackend, relays: readonly string[]) {
    super(backend, relays);
  }

  /** Constructs and starts a React Native endpoint. */
  static create(config: MiniP2pConfig): MiniP2p {
    return new MiniP2p(backendFactory.create(config), config.relays ?? []);
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

/** Builds a circuit multiaddress through a direct QUIC relay address. */
export function circuitAddress(relayAddress: string, peerId: string): string {
  return backendFactory.circuitAddress(relayAddress, peerId);
}

function toNativeConfig(config: MiniP2pConfig): NativeEndpointConfig {
  const discovery: NativeDiscoveryOptions | undefined =
    config.discovery === undefined
      ? undefined
      : {
          autoDial: config.discovery.autoDial,
          beaconIntervalMs: numberToU64(
            config.discovery.beaconIntervalMs,
            "beaconIntervalMs"
          ),
          peerTtlMs: numberToU64(config.discovery.peerTtlMs, "peerTtlMs"),
          topic: config.discovery.topic,
        };
  const mdnsOptions = config.mdns === true ? {} : config.mdns;
  const mdns: NativeMdnsOptions | undefined =
    mdnsOptions === undefined || mdnsOptions === false
      ? undefined
      : {
          autoDial: mdnsOptions.autoDial ?? true,
          enableIpv6: mdnsOptions.enableIpv6 ?? false,
          interfaceRefreshMs: numberToU64(
            mdnsOptions.interfaceRefreshMs ?? 10_000,
            "interfaceRefreshMs"
          ),
          maxAnnouncedAddrs: numberToU32(
            mdnsOptions.maxAnnouncedAddrs ?? 16,
            "maxAnnouncedAddrs"
          ),
          maxPacketBytes: numberToU32(
            mdnsOptions.maxPacketBytes ?? 1400,
            "maxPacketBytes"
          ),
          queryIntervalMs: numberToU64(
            mdnsOptions.queryIntervalMs ?? 300_000,
            "queryIntervalMs"
          ),
          socketPollIntervalMs: numberToU64(
            mdnsOptions.socketPollIntervalMs ?? 100,
            "socketPollIntervalMs"
          ),
          ttlMs: numberToU64(mdnsOptions.ttlMs ?? 120_000, "ttlMs"),
        };
  return {
    agentVersion: config.agentVersion,
    allowUnsigned: config.allowUnsigned ?? false,
    autonatServers: [...(config.autonatServers ?? [])],
    discovery,
    forceRelay: config.forceRelay ?? false,
    listenAddr: config.listenAddr,
    mdns,
    protocols: [...(config.protocols ?? [])],
    pubsubRouter: (config.pubsubRouter ??
      PubsubRouter.Gossipsub) as NativeEndpointConfig["pubsubRouter"],
    relays: [...(config.relays ?? [])],
  };
}

function normalizeEvent(event: NativeP2pEvent): P2pEvent {
  return normalizeBigInts({
    inner: event.inner,
    tag: event.tag,
  }) as P2pEvent;
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

function normalizeBigInts(value: unknown): unknown {
  if (typeof value === "bigint") {
    return u64ToNumber(value, "native u64");
  }
  if (value instanceof ArrayBuffer) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeBigInts(item));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, normalizeBigInts(item)])
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

function numberToU32(value: number, name: string): number {
  assertSafeUnsignedInteger(value, name);
  if (value > 0xff_ff_ff_ff) {
    throw new RangeError(`${name} exceeds the unsigned 32-bit range`);
  }
  return value;
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
      case FfiError_Tags.Backpressure: {
        throw new BackpressureError();
      }
      case FfiError_Tags.MessageTooLarge: {
        throw new MessageTooLargeError();
      }
      case FfiError_Tags.NotPermitted: {
        throw new NotPermittedError(getErrorDetail(error));
      }
      default: {
        throw error;
      }
    }
  }
}

function getErrorTag(error: unknown): FfiError_Tags | undefined {
  return typeof error === "object" && error !== null && "tag" in error
    ? (error.tag as FfiError_Tags)
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
