import {
  BackpressureError,
  MessageTooLargeError,
  NotPermittedError,
} from "@minip2p/core";
import { afterEach, describe, expect, test, vi } from "vitest";

import { Minip2p } from "../src/adapter";
import { FfiError } from "../src/generated/minip2p_ffi_core";
import { FakeNativeEndpoint } from "./fake-native-endpoint";

vi.mock("../src/native", async () => {
  const { nativeModuleMock } = await import("./fake-native-endpoint");
  return nativeModuleMock();
});

vi.mock("../src/NativeMinip2p", () => ({
  default: { setMdnsEnabled: vi.fn() },
}));

const publishFailure = (nativeError: Error): unknown => {
  const endpoint = Minip2p.create({ secretKey: new Uint8Array(32) });
  FakeNativeEndpoint.current().publishError = nativeError;
  try {
    endpoint.publish("topic", "data");
  } catch (error) {
    return error;
  } finally {
    endpoint.close();
  }
  throw new Error("publish did not throw");
};

describe("React Native native errors", () => {
  afterEach(() => {
    FakeNativeEndpoint.latest = undefined;
  });

  test("generated FfiError tags map to typed SDK errors", () => {
    expect(publishFailure(new FfiError.Backpressure())).toBeInstanceOf(
      BackpressureError
    );
    expect(publishFailure(new FfiError.MessageTooLarge())).toBeInstanceOf(
      MessageTooLargeError
    );
    const refusal = publishFailure(
      new FfiError.NotPermitted({ detail: "topic is reserved" })
    );
    expect(refusal).toBeInstanceOf(NotPermittedError);
    expect(refusal).toHaveProperty("message", "topic is reserved");
  });

  test("other FfiError variants are rethrown unchanged", () => {
    const invalid = new FfiError.InvalidTopic({ detail: "empty" });
    expect(publishFailure(invalid)).toBe(invalid);
  });
});
