import { describeAdapterContract } from "@minip2p/test-fixtures/adapter-contract";
import type { NativeEventLiteral } from "@minip2p/test-fixtures/adapter-contract";
import { afterEach, vi } from "vitest";

import { Minip2p } from "../src/adapter";
import { ConnectTarget_Tags } from "../src/generated/minip2p_ffi";
import { FakeNativeEndpoint } from "./fake-native-endpoint";

vi.mock("../src/native", async () => {
  const { nativeModuleMock } = await import("./fake-native-endpoint");
  return nativeModuleMock();
});

vi.mock("../src/NativeMinip2p", () => ({
  default: { setMdnsEnabled: vi.fn() },
}));

afterEach(() => {
  FakeNativeEndpoint.latest = undefined;
});

describeAdapterContract("React Native", {
  create: (config = {}) =>
    Minip2p.create({ ...config, secretKey: new Uint8Array(32) }),
  native: () => {
    const fake = FakeNativeEndpoint.current();
    return {
      cancelledConnects: fake.cancelledConnects,
      config: fake.config,
      connectTargets: fake.connectTargets.map((target) =>
        target.tag === ConnectTarget_Tags.Peer
          ? { kind: "peer" as const, peerId: target.inner.peerId }
          : { addresses: target.inner.addresses, kind: "addresses" as const }
      ),
      deliver: (events: readonly NativeEventLiteral[]) => {
        fake.enqueue([...events], []);
        fake.ring();
      },
      setConnectionInfo: (connId: bigint, remoteAddr?: string) => {
        fake.connection = { connId, remoteAddr };
      },
    };
  },
});
