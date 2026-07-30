import type {
  Bytes,
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
  knownPeers: () => KnownPeerInfo[];
  activeReservation: () => RelayReservationInfo | undefined;
  circuitAddress: (relayAddress: string, peerId: string) => string;
  reachability: () => Reachability;
  isRunning: () => boolean;
  setActive: (active: boolean) => void;
  subscribe: (topic: string) => boolean;
  unsubscribe: (topic: string) => boolean;
  publish: (topic: string, data: Uint8Array) => void;
  connect: (peerId: string) => number;
  connectAddr: (address: string) => number;
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
