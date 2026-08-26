import { Minip2pBase, PubsubRouter } from "@minip2p/core";
import type {
  Bytes,
  IdentifyInfo,
  KnownPeerInfo,
  Minip2pConfig,
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
  readonly #endpoint: NativeEndpoint;

  constructor(config: Minip2pConfig) {
    const transports = resolveTransports(config);
    this.#endpoint = new nativeBinding.NodeEndpoint(
      toUint8Array(config.secretKey),
      {
        agentVersion: config.agentVersion,
        allowUnsigned: config.allowUnsigned ?? false,
        autonatServers: [...(config.autonatServers ?? [])],
        forceRelay: config.forceRelay ?? false,
        protocols: [...(config.protocols ?? [])],
        pubsubRouter: config.pubsubRouter ?? PubsubRouter.Gossipsub,
        quic: toNativeTransport(transports.quic),
        relays: [...(config.relays ?? [])],
        tcp: toNativeTransport(transports.tcp),
      }
    );
  }

  start(_listener: (event: P2pEvent) => void): void {
    this.#endpoint.start(() => {});
  }

  close(): void {
    this.#endpoint.close();
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
    return unsupported();
  }

  isPeerReady(_peerId: string): boolean {
    return unsupported();
  }

  peerInfo(_peerId: string): IdentifyInfo | undefined {
    return unsupported();
  }

  knownPeers(): KnownPeerInfo[] {
    return unsupported();
  }

  discoveryNowMs(): number | undefined {
    return unsupported();
  }

  activeReservation(): RelayReservationInfo | undefined {
    return unsupported();
  }

  path(_peerId: string): PathKind | undefined {
    return unsupported();
  }

  circuitAddress(relayAddress: string, peerId: string): string {
    return nativeBinding.circuitAddress(relayAddress, peerId);
  }

  reachability(): Reachability {
    return unsupported();
  }

  setActive(_active: boolean): void {
    unsupported();
  }

  subscribe(_topic: string): boolean {
    return unsupported();
  }

  unsubscribe(_topic: string): boolean {
    return unsupported();
  }

  publish(_topic: string, _data: Uint8Array): void {
    unsupported();
  }

  ping(_peerId: string): void {
    unsupported();
  }

  addProtocol(_protocolId: string): void {
    unsupported();
  }

  openStream(_peerId: string, _protocolId: string): BackendOpenStream {
    return unsupported();
  }

  sendStream(_peerId: string, _streamId: number, _data: Uint8Array): void {
    unsupported();
  }

  closeStreamWrite(_peerId: string, _streamId: number): void {
    unsupported();
  }

  resetStream(_peerId: string, _streamId: number): void {
    unsupported();
  }

  abandonStream(_peerId: string, _streamId: number): void {
    unsupported();
  }

  connect(_peerId: string): number {
    return unsupported();
  }

  connectWithAddrs(_peerId: string, _addresses: readonly string[]): number {
    return unsupported();
  }

  connectAddr(_address: string): number {
    return unsupported();
  }

  dial(_address: string): number[] {
    return unsupported();
  }

  dialIp4(_address: string): number {
    return unsupported();
  }

  dialIp6(_address: string): number {
    return unsupported();
  }

  cancelConnect(_id: number): void {
    unsupported();
  }

  disconnect(_peerId: string): void {
    unsupported();
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

function toUint8Array(value: Bytes): Uint8Array {
  return value instanceof Uint8Array
    ? Uint8Array.from(value)
    : new Uint8Array(value);
}

function unsupported(): never {
  throw new Error("The native Node backend method is not implemented");
}
