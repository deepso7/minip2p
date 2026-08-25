/* oxlint-disable class-methods-use-this, no-empty-function, no-plusplus -- A contract-complete test double must implement inert backend methods directly. */

import type {
  BackendOpenStream,
  Minip2pBackend,
  P2pEvent,
} from "../../core/src/backend.js";
import { Reachability } from "../../core/src/index.js";

export type MockBackendOperation =
  | readonly ["abandon" | "closeWrite" | "reset", string, number]
  | readonly ["cancelConnect", number]
  | readonly ["write", string, number, readonly number[]];

/** Scriptable, contract-complete backend for package-level SDK tests. */
export class MockBackend implements Minip2pBackend {
  abandonError: unknown;
  closed = false;
  connected: string[] = [];
  nextConnectId = 1;
  nextStreamId = 3;
  openResults: BackendOpenStream[] = [];
  operations: MockBackendOperation[] = [];
  pingCalls = 0;

  private listener?: (event: P2pEvent) => void;

  start(listener: (event: P2pEvent) => void): void {
    this.listener = listener;
  }

  emit(event: P2pEvent): void {
    if (this.listener === undefined) {
      throw new Error("MockBackend.start() must be called before emit()");
    }
    this.listener(event);
  }

  close(): void {
    this.closed = true;
  }

  peerId(): string {
    return "local-peer";
  }

  listenAddrs(): string[] {
    return ["/ip4/127.0.0.1/udp/1/quic-v1/p2p/local-peer"];
  }

  connectedPeers(): string[] {
    return [...this.connected];
  }

  isPeerReady(_peerId: string): boolean {
    return false;
  }

  peerInfo(): undefined {
    return undefined;
  }

  knownPeers(): [] {
    return [];
  }

  discoveryNowMs(): undefined {
    return undefined;
  }

  activeReservation(): undefined {
    return undefined;
  }

  path(): undefined {
    return undefined;
  }

  circuitAddress(relayAddress: string, peerId: string): string {
    return `${relayAddress}/p2p-circuit/p2p/${peerId}`;
  }

  reachability(): Reachability {
    return Reachability.Unknown;
  }

  isRunning(): boolean {
    return !this.closed;
  }

  setActive(_active: boolean): void {}

  subscribe(_topic: string): boolean {
    return true;
  }

  unsubscribe(_topic: string): boolean {
    return true;
  }

  publish(_topic: string, _data: Uint8Array): void {}

  ping(_peerId: string): void {
    this.pingCalls += 1;
  }

  addProtocol(_protocolId: string): void {}

  openStream(_peerId: string, _protocolId: string): BackendOpenStream {
    return (
      this.openResults.shift() ?? {
        connId: 2,
        streamId: this.nextStreamId++,
      }
    );
  }

  sendStream(peerId: string, streamId: number, data: Uint8Array): void {
    this.operations.push(["write", peerId, streamId, [...data]]);
  }

  closeStreamWrite(peerId: string, streamId: number): void {
    this.operations.push(["closeWrite", peerId, streamId]);
  }

  resetStream(peerId: string, streamId: number): void {
    this.operations.push(["reset", peerId, streamId]);
  }

  abandonStream(peerId: string, streamId: number): void {
    this.operations.push(["abandon", peerId, streamId]);
    if (this.abandonError !== undefined) {
      throw this.abandonError;
    }
  }

  connect(_peerId: string): number {
    return this.nextConnectId++;
  }

  connectWithAddrs(_peerId: string, _addresses: readonly string[]): number {
    return this.nextConnectId++;
  }

  connectAddr(_address: string): number {
    return this.nextConnectId++;
  }

  dial(_address: string): number[] {
    return [10];
  }

  dialIp4(_address: string): number {
    return 11;
  }

  dialIp6(_address: string): number {
    return 12;
  }

  cancelConnect(id: number): void {
    this.operations.push(["cancelConnect", id]);
  }

  disconnect(_peerId: string): void {}
}
