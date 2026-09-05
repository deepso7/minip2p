/* oxlint-disable class-methods-use-this -- The fake mirrors the generated endpoint surface; methods no test reaches throw by name. */
/** In-memory stand-in for the UniFFI `P2pEndpoint` used by adapter tests. */

import { vi } from "vitest";

import type {
  OpenStreamResult,
  P2pEndpointLike,
  P2pEvent,
  P2pEventDoorbell,
} from "../src/native";

/**
 * Hand-written stand-in for a generated event class instance. The adapter
 * only reads `tag` and `inner`, so tests enqueue plain literals.
 */
export interface FakeEvent {
  readonly tag: string;
  readonly inner: Readonly<Record<string, unknown>>;
}

const notFaked = (method: keyof P2pEndpointLike): never => {
  throw new Error(`FakeNativeEndpoint does not fake ${method}`);
};

/**
 * Implements the full generated endpoint surface so interface drift fails
 * `typecheck`. Only the methods the adapter tests reach have behavior; the
 * rest throw by name so an unexpected call is loud rather than "not a
 * function".
 */
export class FakeNativeEndpoint implements P2pEndpointLike {
  static latest: FakeNativeEndpoint | undefined;

  readonly drainLimits: number[] = [];
  /** Native identities returned by the next `openStream` call. */
  nextStream = { connId: 1n, streamId: 1n };
  /** Native connection identities returned by the dial methods. */
  dialResults: bigint[] = [1n];
  /** Native discovery clock returned by `discoveryNowMs`. */
  discoveryNow: bigint | undefined = undefined;
  readonly #batches: FakeEvent[][] = [];
  #doorbell: P2pEventDoorbell | undefined;

  constructor() {
    FakeNativeEndpoint.latest = this;
  }

  /** Returns the endpoint constructed by the most recent `Minip2p.create`. */
  static current(): FakeNativeEndpoint {
    if (FakeNativeEndpoint.latest === undefined) {
      throw new Error("native endpoint was not constructed");
    }
    return FakeNativeEndpoint.latest;
  }

  enqueue(...batches: FakeEvent[][]): void {
    this.#batches.push(...batches);
  }

  ring(): void {
    this.#doorbell?.onEventsReady();
  }

  start(doorbell: P2pEventDoorbell): void {
    this.#doorbell = doorbell;
  }

  drainEvents(limit: number): P2pEvent[] {
    this.drainLimits.push(limit);
    return (this.#batches.shift() ?? []) as unknown as P2pEvent[];
  }

  openStream(): OpenStreamResult {
    return this.nextStream;
  }

  dial(): bigint[] {
    return this.dialResults;
  }

  dialIp4(): bigint {
    return this.dialResults[0] ?? 0n;
  }

  dialIp6(): bigint {
    return this.dialResults[0] ?? 0n;
  }

  discoveryNowMs(): bigint | undefined {
    return this.discoveryNow;
  }

  stop(): void {
    this.#doorbell = undefined;
  }

  uniffiDestroy(): void {
    this.#batches.length = 0;
  }

  abandonStream(): never {
    return notFaked("abandonStream");
  }

  activeReservation(): never {
    return notFaked("activeReservation");
  }

  addProtocol(): never {
    return notFaked("addProtocol");
  }

  cancelConnect(): never {
    return notFaked("cancelConnect");
  }

  closeStreamWrite(): never {
    return notFaked("closeStreamWrite");
  }

  connect(): never {
    return notFaked("connect");
  }

  connectAddr(): never {
    return notFaked("connectAddr");
  }

  connectWithAddrs(): never {
    return notFaked("connectWithAddrs");
  }

  connectedPeers(): never {
    return notFaked("connectedPeers");
  }

  disconnect(): never {
    return notFaked("disconnect");
  }

  isPeerReady(): never {
    return notFaked("isPeerReady");
  }

  isRunning(): never {
    return notFaked("isRunning");
  }

  knownPeers(): never {
    return notFaked("knownPeers");
  }

  listenAddrs(): never {
    return notFaked("listenAddrs");
  }

  path(): never {
    return notFaked("path");
  }

  peerId(): never {
    return notFaked("peerId");
  }

  peerInfo(): never {
    return notFaked("peerInfo");
  }

  ping(): never {
    return notFaked("ping");
  }

  publish(): never {
    return notFaked("publish");
  }

  reachability(): never {
    return notFaked("reachability");
  }

  resetStream(): never {
    return notFaked("resetStream");
  }

  sendStream(): never {
    return notFaked("sendStream");
  }

  setActive(): never {
    return notFaked("setActive");
  }

  subscribe(): never {
    return notFaked("subscribe");
  }

  unsubscribe(): never {
    return notFaked("unsubscribe");
  }

  waitStopped(): never {
    return notFaked("waitStopped");
  }
}

/** Factory for `vi.mock("../src/native", nativeModuleMock)`. */
export const nativeModuleMock = () => ({
  FfiError_Tags: {},
  P2pEndpoint: FakeNativeEndpoint,
  circuitAddress: vi.fn(),
  generateSecretKey: vi.fn(),
  peerIdFromSecretKey: vi.fn(),
});
