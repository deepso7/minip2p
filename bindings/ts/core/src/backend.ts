import type {
  Bytes,
  IdentifyInfo,
  KnownPeerInfo,
  MiniP2pConfig,
  P2pEvent,
  Reachability,
  RelayReservationInfo,
} from "./types.js";

/** Native endpoint operations required by the platform-neutral SDK. */
export interface MiniP2pBackend {
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
  circuitAddress: (relayAddress: string, peerId: string) => string;
  reachability: () => Reachability;
  isRunning: () => boolean;
  setActive: (active: boolean) => void;
  subscribe: (topic: string) => boolean;
  unsubscribe: (topic: string) => boolean;
  publish: (topic: string, data: Uint8Array) => void;
  ping: (peerId: string) => void;
  addProtocol: (protocolId: string) => void;
  openStream: (peerId: string, protocolId: string) => number;
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

/** Platform implementation used to construct endpoints and identity helpers. */
export interface MiniP2pBackendFactory {
  create: (config: MiniP2pConfig) => MiniP2pBackend;
  generateSecretKey: () => Uint8Array;
  peerIdFromSecretKey: (secretKey: Bytes) => string;
  circuitAddress: (relayAddress: string, peerId: string) => string;
}
