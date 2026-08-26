import { afterEach, describe, expect, test, vi } from "vitest";

import { Minip2p } from "../src/adapter";

const native = vi.hoisted(() => {
  interface Event {
    readonly tag: string;
    readonly inner: Readonly<Record<string, unknown>>;
  }
  interface Doorbell {
    onEventsReady: () => void;
  }

  class FakeNativeEndpoint {
    static latest: FakeNativeEndpoint | undefined;

    readonly drainLimits: number[] = [];
    readonly #batches: Event[][] = [];
    #doorbell: Doorbell | undefined;

    constructor() {
      FakeNativeEndpoint.latest = this;
    }

    enqueue(...batches: Event[][]): void {
      this.#batches.push(...batches);
    }

    ring(): void {
      this.#doorbell?.onEventsReady();
    }

    start(doorbell: Doorbell): void {
      this.#doorbell = doorbell;
    }

    drainEvents(limit: number): Event[] {
      this.drainLimits.push(limit);
      return this.#batches.shift() ?? [];
    }

    stop(): void {
      this.#doorbell = undefined;
    }

    uniffiDestroy(): void {
      this.#batches.length = 0;
    }
  }

  return { FakeNativeEndpoint };
});

vi.mock("../src/native", () => ({
  FfiError_Tags: {},
  P2pEndpoint: native.FakeNativeEndpoint,
  circuitAddress: vi.fn(),
  generateSecretKey: vi.fn(),
  peerIdFromSecretKey: vi.fn(),
}));

vi.mock("../src/NativeMinip2p", () => ({
  default: {
    setMdnsEnabled: vi.fn(),
  },
}));

const event = (peerId: string) => ({
  inner: { peerId },
  tag: "PeerReady",
});

const settle = async (): Promise<void> => {
  await vi.runAllTimersAsync();
};

describe("React Native event delivery", () => {
  afterEach(() => {
    vi.useRealTimers();
    native.FakeNativeEndpoint.latest = undefined;
  });

  test("start drains to empty and does not lose a re-ring", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = native.FakeNativeEndpoint.latest;
    if (fake === undefined) {
      throw new Error("native endpoint was not constructed");
    }
    const peers: string[] = [];
    endpoint.on("peerReady", ({ peerId }) => peers.push(peerId));
    fake.enqueue([event("first")], [], [event("second")], []);

    fake.ring();
    await vi.advanceTimersToNextTimerAsync();
    fake.ring();
    await settle();

    expect(peers).toEqual(["first", "second"]);
    expect(fake.drainLimits).toEqual([256, 256, 256, 256]);
    endpoint.close();
  });

  test("an event flood coalesces into one native drain pass", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = native.FakeNativeEndpoint.latest;
    if (fake === undefined) {
      throw new Error("native endpoint was not constructed");
    }

    for (let index = 0; index < 10_000; index += 1) {
      fake.ring();
    }
    await settle();

    expect(fake.drainLimits).toEqual([256]);
    endpoint.close();
  });
});
