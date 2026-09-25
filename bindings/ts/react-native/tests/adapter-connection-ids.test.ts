import { afterEach, describe, expect, test, vi } from "vitest";

import { Minip2p } from "../src/adapter";
import { FakeNativeEndpoint } from "./fake-native-endpoint";
import type { FakeEvent } from "./fake-native-endpoint";

vi.mock("../src/native", async () => {
  const { nativeModuleMock } = await import("./fake-native-endpoint");
  return nativeModuleMock();
});

vi.mock("../src/NativeMinip2p", () => ({
  default: { setMdnsEnabled: vi.fn() },
}));

const PEER = "12D3KooWPeer";
const NATIVE_IDS = [1n, 2n ** 56n + 1n, 2n ** 63n + 1n, 2n ** 63n + 2n];

const established = (connId: bigint): FakeEvent => ({
  inner: { connId, peerId: PEER },
  tag: "ConnectionEstablished",
});

const closed = (connId: bigint): FakeEvent => ({
  inner: { connId, peerId: PEER },
  tag: "ConnectionClosed",
});

const isSafeId = (value: number): boolean =>
  Number.isSafeInteger(value) && value >= 0;

describe("React Native connection identities", () => {
  afterEach(() => {
    vi.useRealTimers();
    FakeNativeEndpoint.latest = undefined;
  });

  test("full-range native connection IDs reach listeners as distinct safe numbers", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = FakeNativeEndpoint.current();
    const opened: number[] = [];
    const closedIds: number[] = [];
    const lateErrors: (number | undefined)[] = [];
    endpoint.on("connectionEstablished", ({ connId }) => opened.push(connId));
    endpoint.on("connectionClosed", ({ connId }) => closedIds.push(connId));
    endpoint.on("endpointError", ({ connId }) => lateErrors.push(connId));
    fake.enqueue(
      NATIVE_IDS.map(established),
      [closed(2n ** 63n + 1n), closed(1n)],
      [
        {
          inner: { connId: 1n, detail: "late", kind: 0 },
          tag: "EndpointError",
        },
        established(5n),
      ],
      []
    );

    fake.ring();
    await vi.runAllTimersAsync();

    expect(opened).toHaveLength(NATIVE_IDS.length + 1);
    expect(opened.every(isSafeId)).toBe(true);
    expect(closedIds).toEqual([opened[2], opened[0]]);
    // A released ID never comes back: the late error and the new connection
    // both get numbers distinct from every ID handed out before.
    const seen = [...opened, ...lateErrors];
    expect(new Set(seen).size).toBe(seen.length);
    endpoint.close();
  });

  test("openStream and stream events share the connection event's public ID", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = FakeNativeEndpoint.current();
    const nativeConnId = 2n ** 63n + 1n;
    const opened: number[] = [];
    const errors: (number | undefined)[] = [];
    endpoint.on("connectionEstablished", ({ connId }) => opened.push(connId));
    endpoint.on("endpointError", ({ connId }) => errors.push(connId));
    fake.nextStream = { connId: nativeConnId, streamId: 7n };
    const pending = endpoint.openStream(PEER, "/echo/1.0.0");
    const streamInner = { connId: nativeConnId, peerId: PEER, streamId: 7n };
    fake.enqueue(
      [
        established(nativeConnId),
        {
          inner: {
            ...streamInner,
            initiatedLocally: true,
            protocolId: "/echo/1.0.0",
          },
          tag: "StreamReady",
        },
        {
          inner: { ...streamInner, data: new ArrayBuffer(1) },
          tag: "StreamData",
        },
        {
          inner: {
            ...streamInner,
            detail: "boom",
            kind: 0,
          },
          tag: "EndpointError",
        },
      ],
      []
    );
    const stream = await (async () => {
      fake.ring();
      await vi.runAllTimersAsync();
      return pending;
    })();
    const chunk = await stream.read();

    expect(opened).toEqual([stream.connId]);
    expect(isSafeId(stream.connId)).toBe(true);
    expect(stream.streamId).toBe(7);
    expect(chunk?.byteLength).toBe(1);
    expect(errors).toEqual([stream.connId]);
    stream.abandon();
    endpoint.close();
  });

  test("dial results map the full u64 range consistently with events", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = FakeNativeEndpoint.current();
    const opened: number[] = [];
    endpoint.on("connectionEstablished", ({ connId }) => opened.push(connId));

    fake.dialResults = [2n ** 64n - 1n, 2n ** 63n + 2n];
    const dialed = endpoint.dial("/ip4/127.0.0.1/udp/4001/quic-v1");
    fake.dialResults = [2n ** 63n + 2n];
    const ip4 = endpoint.dialIp4("/ip4/127.0.0.1/udp/4001/quic-v1");
    fake.dialResults = [2n ** 53n];
    const ip6 = endpoint.dialIp6("/ip6/::1/udp/4001/quic-v1");
    fake.enqueue([
      established(2n ** 63n + 2n),
      established(2n ** 64n - 1n),
      established(2n ** 53n),
    ]);
    fake.ring();
    await vi.runAllTimersAsync();

    expect([...dialed, ip6].every(isSafeId)).toBe(true);
    expect(new Set([...dialed, ip6]).size).toBe(3);
    expect(ip4).toBe(dialed[1]);
    expect(opened).toEqual([dialed[1], dialed[0], ip6]);
    endpoint.close();
  });

  test("other native u64 fields keep their range checks without blocking the batch", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = FakeNativeEndpoint.current();
    fake.discoveryNow = 2n ** 63n;
    const peers: string[] = [];
    endpoint.on("peerReady", ({ peerId }) => peers.push(peerId));
    fake.enqueue([
      {
        inner: { peerId: PEER, rttMs: 2n ** 63n },
        tag: "PingRttMeasured",
      },
      { inner: { peerId: PEER, protocols: [] }, tag: "PeerReady" },
    ]);

    fake.ring();
    await vi.runAllTimersAsync();

    expect(() => endpoint.discoveryNowMs()).toThrow(RangeError);
    expect(peers).toEqual([PEER]);
    endpoint.close();
  });
});
