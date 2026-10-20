import { describeAdapterContract } from "@minip2p/test-fixtures/adapter-contract";
import type {
  NativeConnectionInfo,
  NativeEventLiteral,
} from "@minip2p/test-fixtures/adapter-contract";
import { afterEach, vi } from "vitest";

import { Minip2p } from "../src/adapter";
import {
  ConfigCapability,
  ConnectTarget_Tags,
  FfiError,
  PathKind,
  TimeoutLimit,
  WindowLimit,
} from "../src/generated/minip2p_ffi_core";
import { FakeNativeEndpoint } from "./fake-native-endpoint";

vi.mock("../src/native", async () => {
  const { nativeModuleMock } = await import("./fake-native-endpoint");
  return nativeModuleMock();
});

vi.mock("../src/NativeMinip2p", () => ({
  default: { setMdnsEnabled: vi.fn() },
}));

/** The generated UniFFI value of a runtime-neutral native path. */
const generatedPath = (path: NativeConnectionInfo["path"]): PathKind => {
  if (path.tag === "Relayed") {
    return PathKind.Relayed.new(path.inner);
  }
  return path.tag === "Punched"
    ? PathKind.Punched.new()
    : PathKind.Direct.new();
};

/**
 * Native limits in the runtime-neutral backend form: generated UniFFI
 * window and timeout enums back to `bigint | "unlimited" | "never"`, unset
 * fields dropped.
 */
const neutralLimits = (value: unknown): unknown => {
  if (typeof value !== "object" || value === null) {
    return value;
  }
  if (value instanceof WindowLimit.Unlimited) {
    return "unlimited";
  }
  if (value instanceof TimeoutLimit.Never) {
    return "never";
  }
  if (value instanceof WindowLimit.Bounded) {
    return value.inner.bytes;
  }
  if (value instanceof TimeoutLimit.AfterMs) {
    return value.inner.ms;
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, field]) => field !== undefined)
      .map(([key, field]) => [key, neutralLimits(field)])
  );
};

afterEach(() => {
  FakeNativeEndpoint.latest = undefined;
});

describeAdapterContract("React Native", {
  create: (config = {}) =>
    Minip2p.create({ ...config, secretKey: new Uint8Array(32) }),
  native: () => {
    const fake = FakeNativeEndpoint.current();
    return {
      abandoned: fake.abandoned,
      cancelledConnects: fake.cancelledConnects,
      closeTimeouts: fake.stopTimeouts,
      config: {
        ...(fake.config as object),
        limits: neutralLimits((fake.config as { limits?: unknown }).limits),
      },
      connectTargets: fake.connectTargets.map((target) =>
        target.tag === ConnectTarget_Tags.Peer
          ? { kind: "peer" as const, peerId: target.inner.peerId }
          : { addresses: target.inner.addresses, kind: "addresses" as const }
      ),
      consumed: fake.consumed,
      deliver: (events: readonly NativeEventLiteral[]) => {
        fake.enqueue([...events], []);
        fake.ring();
      },
      setCloseUnfinished: (unfinished) => {
        fake.closeReport.unfinished = [...unfinished];
      },
      setConnectionInfo: (info) => {
        fake.connection = { ...info, path: generatedPath(info.path) };
      },
      setLiveConnection: (connId) => {
        fake.liveConnId = connId;
      },
      setNextStream: (connId, streamId) => {
        fake.nextStream = { connId, streamId };
      },
      writes: fake.writes,
      writtenData: fake.writtenData,
    };
  },
  rejectNextTransportConfig: (detail) => {
    FakeNativeEndpoint.constructError = new FfiError.InvalidConfig({
      capability: ConfigCapability.Transport,
      detail,
    });
  },
});
