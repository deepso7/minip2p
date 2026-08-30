/* oxlint-disable class-methods-use-this, max-classes-per-file, promise/avoid-new -- The fake implements the native endpoint boundary used by the adapter, including one deferred drain observation. */

import { afterEach, describe, expect, test, vi } from "vitest";

import { Minip2p } from "../src/adapter";

const native = vi.hoisted(() => {
  interface Event {
    readonly inner?: Readonly<Record<string, unknown>>;
    readonly tag?: string;
  }

  class FakeNativeEndpoint {
    static latest: FakeNativeEndpoint | undefined;

    readonly config: Readonly<Record<string, unknown>>;
    readonly drainLimits: number[] = [];
    readonly #batches: Event[][] = [];
    #doorbell: (() => void) | undefined;
    #drainCalls = 0;
    discoveryClock: bigint | null = null;
    onDrain: ((call: number) => void) | undefined;

    constructor(
      _secretKey: Uint8Array,
      config: Readonly<Record<string, unknown>>
    ) {
      this.config = config;
      FakeNativeEndpoint.latest = this;
    }

    enqueue(...batches: Event[][]): void {
      this.#batches.push(...batches);
    }

    ring(): void {
      this.#doorbell?.();
    }

    start(doorbell: () => void): void {
      this.#doorbell = doorbell;
    }

    drainEvents(limit: number): Event[] {
      this.drainLimits.push(limit);
      this.#drainCalls += 1;
      this.onDrain?.(this.#drainCalls);
      return this.#batches.shift() ?? [];
    }

    close(): void {
      this.#doorbell = undefined;
      this.#batches.length = 0;
    }

    discoveryNowMs(): bigint | null {
      return this.discoveryClock;
    }

    activeReservation(): null {
      return null;
    }

    addProtocol(): void {}

    abandonStream(): void {}

    cancelConnect(): void {}

    circuitAddress(): string {
      return "";
    }

    closeStreamWrite(): void {}

    connect(): bigint {
      return 30n;
    }

    connectAddr(): bigint {
      return 30n;
    }

    connectedPeers(): string[] {
      return [];
    }

    connectWithAddrs(): bigint {
      return 30n;
    }

    dial(): bigint[] {
      return [];
    }

    dialIp4(): bigint {
      return 10n;
    }

    dialIp6(): bigint {
      return 10n;
    }

    disconnect(): void {}

    isPeerReady(): boolean {
      return false;
    }

    isRunning(): boolean {
      return true;
    }

    knownPeers(): unknown[] {
      return [];
    }

    listenAddrs(): string[] {
      return [];
    }

    openStream(): { readonly connId: bigint; readonly streamId: bigint } {
      return { connId: 10n, streamId: 20n };
    }

    path(): null {
      return null;
    }

    peerId(): string {
      return "local";
    }

    peerInfo(): null {
      return null;
    }

    ping(): void {}

    publish(): void {}

    reachability(): number {
      return 0;
    }

    resetStream(): void {}

    sendStream(): void {}

    setActive(): void {}

    subscribe(): boolean {
      return true;
    }

    unsubscribe(): boolean {
      return true;
    }
  }

  return { FakeNativeEndpoint };
});

vi.mock("../src/native", () => ({
  nativeBinding: {
    NodeEndpoint: native.FakeNativeEndpoint,
    circuitAddress: vi.fn(),
    generateSecretKey: vi.fn(() => new Uint8Array(32)),
    peerIdFromSecretKey: vi.fn(),
  },
}));

const createEndpoint = () => Minip2p.create({ secretKey: new Uint8Array(32) });

const fakeEndpoint = (): InstanceType<typeof native.FakeNativeEndpoint> => {
  const fake = native.FakeNativeEndpoint.latest;
  if (fake === undefined) {
    throw new Error("native endpoint was not constructed");
  }
  return fake;
};

const settle = async (): Promise<void> => {
  await vi.runAllTimersAsync();
  await Promise.resolve();
};

describe("Node adapter", () => {
  afterEach(() => {
    vi.useRealTimers();
    native.FakeNativeEndpoint.latest = undefined;
  });

  test("continues draining after a malformed native event", async () => {
    vi.useFakeTimers();
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();
    const peers: string[] = [];
    endpoint.on("peerReady", ({ peerId }) => peers.push(peerId));
    fake.enqueue(
      [{}],
      [{ inner: { peerId: "remote", protocols: [] }, tag: "PeerReady" }],
      []
    );

    fake.ring();
    await settle();

    expect(peers).toEqual(["remote"]);
    expect(fake.drainLimits).toEqual([256, 256, 256]);
    endpoint.close();
  });

  test("reuses exact native event buffers without exposing sliced bytes", async () => {
    vi.useFakeTimers();
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();
    const exact = Uint8Array.of(1, 2, 3);
    const backing = Uint8Array.of(9, 4, 5, 8);
    const sliced = backing.subarray(1, 3);
    const received: ArrayBuffer[] = [];
    endpoint.on("message", ({ data }) => received.push(data));
    fake.enqueue(
      [
        {
          inner: {
            data: exact,
            fromPeerId: "remote",
            seqno: Uint8Array.of(1),
            signed: false,
            topics: ["test"],
          },
          tag: "Message",
        },
        {
          inner: {
            data: sliced,
            fromPeerId: "remote",
            seqno: Uint8Array.of(2),
            signed: false,
            topics: ["test"],
          },
          tag: "Message",
        },
      ],
      []
    );

    fake.ring();
    await settle();

    expect(received[0]).toBe(exact.buffer);
    expect([...new Uint8Array(received[1])]).toEqual([4, 5]);
    expect(received[1]).not.toBe(backing.buffer);
    endpoint.close();
  });

  test("gives the event loop a turn between non-empty native batches", async () => {
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();
    let immediateRan = false;
    let immediateRanBeforeSecondDrain = false;
    const secondDrain = new Promise<void>((resolve) => {
      fake.onDrain = (call) => {
        if (call === 1) {
          setImmediate(() => {
            immediateRan = true;
          });
        }
        if (call === 2) {
          immediateRanBeforeSecondDrain = immediateRan;
          resolve();
        }
      };
    });
    fake.enqueue(
      [{ inner: { peerId: "remote", protocols: [] }, tag: "PeerReady" }],
      []
    );

    fake.ring();
    await secondDrain;

    expect(immediateRanBeforeSecondDrain).toBe(true);
    endpoint.close();
  });

  test("passes discovery and mDNS configuration to the native endpoint", () => {
    const endpoint = Minip2p.create({
      discovery: {
        autoDial: false,
        beaconIntervalMs: 1234,
        peerTtlMs: 5678,
        topic: "node-discovery",
      },
      mdns: {
        autoDial: false,
        enableIpv6: true,
        interfaceRefreshMs: 111,
        maxAnnouncedAddrs: 12,
        maxPacketBytes: 1300,
        queryIntervalMs: 222,
        socketPollIntervalMs: 333,
        ttlMs: 444,
      },
      secretKey: new Uint8Array(32),
    });

    expect(fakeEndpoint().config).toMatchObject({
      discovery: {
        autoDial: false,
        beaconIntervalMs: 1234n,
        peerTtlMs: 5678n,
        topic: "node-discovery",
      },
      mdns: {
        autoDial: false,
        enableIpv6: true,
        interfaceRefreshMs: 111n,
        maxAnnouncedAddrs: 12,
        maxPacketBytes: 1300,
        queryIntervalMs: 222n,
        socketPollIntervalMs: 333n,
        ttlMs: 444n,
      },
    });
    endpoint.close();
  });

  test("returns no discovery clock when the native option is null", () => {
    const endpoint = createEndpoint();

    expect(endpoint.discoveryNowMs()).toBeUndefined();
    endpoint.close();
  });

  test("forgets connection identifiers after ConnectionClosed", async () => {
    vi.useFakeTimers();
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();
    const ids: number[] = [];
    endpoint.on("connectionEstablished", ({ connId }) => ids.push(connId));
    fake.enqueue(
      [
        {
          inner: { connId: 10n, peerId: "remote" },
          tag: "ConnectionEstablished",
        },
        { inner: { connId: 10n, peerId: "remote" }, tag: "ConnectionClosed" },
        {
          inner: { connId: 10n, peerId: "remote" },
          tag: "ConnectionEstablished",
        },
      ],
      []
    );

    fake.ring();
    await settle();

    expect(ids).toEqual([1, 2]);
    endpoint.close();
  });

  test("forgets connect identifiers after ConnectFailed", async () => {
    vi.useFakeTimers();
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();
    const first = endpoint.startConnect("remote");
    fake.enqueue(
      [
        {
          inner: {
            connectId: 30n,
            detail: "no route",
            kind: 0,
            peerId: "remote",
          },
          tag: "ConnectFailed",
        },
      ],
      []
    );

    fake.ring();
    await settle();
    const second = endpoint.startConnect("remote");

    expect([first, second]).toEqual([1, 2]);
    endpoint.close();
  });

  test("forgets connect identifiers after cancellation", () => {
    const endpoint = createEndpoint();
    const first = endpoint.startConnect("remote");

    endpoint.cancelConnect(first);
    const second = endpoint.startConnect("remote");

    expect([first, second]).toEqual([1, 2]);
    endpoint.close();
  });

  test("forgets connect identifiers after a direct PathEstablished", async () => {
    vi.useFakeTimers();
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();
    const first = endpoint.startConnect("remote");
    fake.enqueue(
      [
        {
          inner: {
            connectId: 30n,
            path: { tag: "DirectDialed" },
            peerId: "remote",
          },
          tag: "PathEstablished",
        },
      ],
      []
    );

    fake.ring();
    await settle();
    const second = endpoint.startConnect("remote");

    expect([first, second]).toEqual([1, 2]);
    endpoint.close();
  });

  test("keeps a relayed connect identifier through PathUpgraded", async () => {
    vi.useFakeTimers();
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();
    const ids: number[] = [];
    endpoint.on("pathEstablished", ({ connectId }) => ids.push(connectId));
    endpoint.on("pathUpgraded", ({ connectId }) => ids.push(connectId));
    const first = endpoint.startConnect("remote");
    fake.enqueue(
      [
        {
          inner: {
            connectId: 30n,
            path: {
              inner: { relayPeerId: "relay" },
              tag: "Relayed",
            },
            peerId: "remote",
          },
          tag: "PathEstablished",
        },
        {
          inner: {
            connectId: 30n,
            from: {
              inner: { relayPeerId: "relay" },
              tag: "Relayed",
            },
            peerId: "remote",
            to: { tag: "DirectPunched" },
          },
          tag: "PathUpgraded",
        },
      ],
      []
    );

    fake.ring();
    await settle();
    const second = endpoint.startConnect("remote");

    expect(ids).toEqual([first, first]);
    expect(second).toBe(2);
    endpoint.close();
  });

  test("forgets stream identifiers after StreamClosed", async () => {
    vi.useFakeTimers();
    const endpoint = createEndpoint();
    const fake = fakeEndpoint();

    const firstPending = endpoint.openStream("remote", "/test/1");
    fake.enqueue(
      [
        {
          inner: {
            connId: 10n,
            initiatedLocally: true,
            peerId: "remote",
            protocolId: "/test/1",
            streamId: 20n,
          },
          tag: "StreamReady",
        },
      ],
      []
    );
    fake.ring();
    await settle();
    const first = await firstPending;

    fake.enqueue(
      [
        {
          inner: { connId: 10n, peerId: "remote", streamId: 20n },
          tag: "StreamClosed",
        },
      ],
      []
    );
    fake.ring();
    await settle();

    const secondPending = endpoint.openStream("remote", "/test/1");
    fake.enqueue(
      [
        {
          inner: {
            connId: 10n,
            initiatedLocally: true,
            peerId: "remote",
            protocolId: "/test/1",
            streamId: 20n,
          },
          tag: "StreamReady",
        },
      ],
      []
    );
    fake.ring();
    await settle();
    const second = await secondPending;

    expect([first.streamId, second.streamId]).toEqual([1, 2]);
    endpoint.close();
  });

  test.each([
    ["maxPacketBytes", 0x1_00_00_00_00],
    ["maxAnnouncedAddrs", -1],
  ] as const)("rejects an invalid mDNS %s", (name, value) => {
    expect(() =>
      Minip2p.create({
        mdns: { [name]: value },
        secretKey: new Uint8Array(32),
      })
    ).toThrow(RangeError);
  });
});
