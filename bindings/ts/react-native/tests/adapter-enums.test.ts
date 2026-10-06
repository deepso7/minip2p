import { afterEach, describe, expect, test, vi } from "vitest";

import { Minip2p } from "../src/adapter";
import {
  DiscoverySource,
  DriverFailureKind,
  EndpointErrorKind,
  NatErrorKind,
  Reachability,
} from "../src/generated/minip2p_ffi_core";
import { FakeNativeEndpoint } from "./fake-native-endpoint";

vi.mock("../src/native", async () => {
  const { nativeModuleMock } = await import("./fake-native-endpoint");
  return nativeModuleMock();
});

vi.mock("../src/NativeMinip2p", () => ({
  default: { setMdnsEnabled: vi.fn() },
}));

const PEER = "12D3KooWPeer";

describe("React Native enum values", () => {
  afterEach(() => {
    vi.useRealTimers();
    FakeNativeEndpoint.latest = undefined;
  });

  test("generated numeric enums reach listeners as SDK names", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = FakeNativeEndpoint.current();
    const seen: string[] = [];
    endpoint.on("endpointError", ({ kind }) => seen.push(kind));
    endpoint.on("reachabilityChanged", ({ previous, current }) =>
      seen.push(previous, current)
    );
    endpoint.on("peerDiscovered", ({ source }) => seen.push(source));
    endpoint.on("driverFailed", ({ kind }) => seen.push(kind));
    endpoint.on("connectFailed", ({ kind }) => seen.push(kind));
    fake.enqueue(
      [
        {
          inner: {
            detail: "refused",
            kind: EndpointErrorKind.OpenStreamFailed,
          },
          tag: "EndpointError",
        },
        {
          inner: {
            confirmedAddrs: [],
            current: Reachability.Private,
            previous: Reachability.Unknown,
          },
          tag: "ReachabilityChanged",
        },
        {
          inner: { addrs: [], peerId: PEER, source: DiscoverySource.Mdns },
          tag: "PeerDiscovered",
        },
        {
          inner: {
            connectId: 3n,
            detail: "late",
            kind: NatErrorKind.Timeout,
            peerId: PEER,
          },
          tag: "ConnectFailed",
        },
        {
          inner: { detail: "gone", kind: DriverFailureKind.Panic },
          tag: "DriverFailed",
        },
      ],
      []
    );

    fake.ring();
    await vi.runAllTimersAsync();

    expect(seen).toEqual([
      "OpenStreamFailed",
      "Unknown",
      "Private",
      "Mdns",
      "Timeout",
      "Panic",
    ]);
    endpoint.close();
  });

  test("reachability returns the SDK name", () => {
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    FakeNativeEndpoint.current().nativeReachability = Reachability.Public;

    expect(endpoint.reachability()).toBe("Public");
    endpoint.close();
  });
});
