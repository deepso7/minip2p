import { afterEach, describe, expect, test, vi } from "vitest";

import { Minip2p } from "../src/adapter";
import { FakeNativeEndpoint } from "./fake-native-endpoint";

vi.mock("../src/native", async () => {
  const { nativeModuleMock } = await import("./fake-native-endpoint");
  return nativeModuleMock();
});

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
    FakeNativeEndpoint.latest = undefined;
  });

  test("start drains to empty and does not lose a re-ring", async () => {
    vi.useFakeTimers();
    const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
    const fake = FakeNativeEndpoint.current();
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
    const fake = FakeNativeEndpoint.current();

    for (let index = 0; index < 10_000; index += 1) {
      fake.ring();
    }
    await settle();

    expect(fake.drainLimits).toEqual([256]);
    endpoint.close();
  });
});
