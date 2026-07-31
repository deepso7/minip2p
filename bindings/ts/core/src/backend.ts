import type {
  Bytes,
  IdentifyInfo,
  KnownPeerInfo,
  Minip2pConfig,
  PathKind,
  P2pEvent,
  Reachability,
  RelayReservationInfo,
} from "./types.js";

/** Native endpoint operations required by the platform-neutral SDK. */
export interface BackendOpenStream {
  readonly connId: number;
  readonly streamId: number;
}

export interface Minip2pBackend {
  start: (listener: (event: P2pEvent) => void) => void;
  close: () => void;
  peerId: () => string;
  listenAddrs: () => string[];
  connectedPeers: () => string[];
  isPeerReady: (peerId: string) => boolean;
  peerInfo: (peerId: string) => IdentifyInfo | undefined;
  knownPeers: () => KnownPeerInfo[];
  discoveryNowMs: () => number | undefined;
  activeReservation: () => RelayReservationInfo | undefined;
  path: (peerId: string) => PathKind | undefined;
  circuitAddress: (relayAddress: string, peerId: string) => string;
  reachability: () => Reachability;
  isRunning: () => boolean;
  setActive: (active: boolean) => void;
  subscribe: (topic: string) => boolean;
  unsubscribe: (topic: string) => boolean;
  publish: (topic: string, data: Uint8Array) => void;
  ping: (peerId: string) => void;
  addProtocol: (protocolId: string) => void;
  openStream: (peerId: string, protocolId: string) => BackendOpenStream;
  sendStream: (peerId: string, streamId: number, data: Uint8Array) => void;
  closeStreamWrite: (peerId: string, streamId: number) => void;
  resetStream: (peerId: string, streamId: number) => void;
  abandonStream: (peerId: string, streamId: number) => void;
  connect: (peerId: string) => number;
  connectWithAddrs: (peerId: string, addresses: readonly string[]) => number;
  connectAddr: (address: string) => number;
  dial: (address: string) => number[];
  dialIp4: (address: string) => number;
  dialIp6: (address: string) => number;
  cancelConnect: (id: number) => void;
  disconnect: (peerId: string) => void;
}

export {
  P2pEvent_Tags,
  PathKind_Tags,
  type P2pEvent,
  type P2pEventByTag,
  type PathKind,
} from "./types.js";

/** Platform implementation used to construct endpoints and identity helpers. */
export interface Minip2pBackendFactory {
  create: (config: Minip2pConfig) => Minip2pBackend;
  generateSecretKey: () => Uint8Array;
  peerIdFromSecretKey: (secretKey: Bytes) => string;
  circuitAddress: (relayAddress: string, peerId: string) => string;
}
