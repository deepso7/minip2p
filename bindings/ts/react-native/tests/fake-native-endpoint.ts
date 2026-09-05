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

/** Endpoint methods the fake implements with the generated signatures. */
type FakedMethods =
  | "dial"
  | "dialIp4"
  | "dialIp6"
  | "discoveryNowMs"
  | "drainEvents"
  | "openStream"
  | "start"
  | "stop";

export class FakeNativeEndpoint implements Pick<P2pEndpointLike, FakedMethods> {
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
}

/** Factory for `vi.mock("../src/native", nativeModuleMock)`. */
export const nativeModuleMock = () => ({
  FfiError_Tags: {},
  P2pEndpoint: FakeNativeEndpoint,
  circuitAddress: vi.fn(),
  generateSecretKey: vi.fn(),
  peerIdFromSecretKey: vi.fn(),
});
