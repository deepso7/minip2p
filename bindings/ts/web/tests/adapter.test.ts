import { ClosedError, DriverFailedError } from "@minip2p/core";
import { describeAdapterContract } from "@minip2p/test-fixtures/adapter-contract";
import {
  FakeSerdeEndpoint,
  latestFakeSerdeEndpoint,
  serdeContractNative,
} from "@minip2p/test-fixtures/fake-serde-endpoint";
import { afterEach, describe, expect, test, vi } from "vitest";

import { Minip2p } from "../src/sdk.js";

/** The wasm `WebEndpoint`: the serde fake plus the pump the adapter drives. */
class FakeWebEndpoint extends FakeSerdeEndpoint {
  /** What successive `pump` calls return; `undefined` once exhausted. */
  pumpDelays: (number | undefined)[] = [];
  pumps = 0;
  /** Makes the next call to `method` trap like a panicking wasm module. */
  trapOn: string | undefined;

  constructor(secretKey: Uint8Array, config: unknown, _io: unknown) {
    super(secretKey, config);
  }

  pump(): number | undefined {
    this.pumps += 1;
    this.#trap("pump");
    return this.pumpDelays.shift();
  }

  override ping(): void {
    this.#trap("ping");
  }

  #trap(method: string): void {
    if (this.trapOn === method) {
      throw new WebAssembly.RuntimeError("unreachable");
    }
  }
}

vi.mock("../src/wasm.js", () => ({
  loadWasm: vi.fn(async () => {}),
  wasm: () => ({
    WebEndpoint: FakeWebEndpoint,
    circuitAddress: vi.fn(),
    generateSecretKey: vi.fn(() => new Uint8Array(32)),
    peerIdFromSecretKey: vi.fn(),
  }),
}));

const create = () => Minip2p.create({ secretKey: new Uint8Array(32) });
const fake = (): FakeWebEndpoint => {
  const endpoint = latestFakeSerdeEndpoint();
  if (!(endpoint instanceof FakeWebEndpoint)) {
    throw new TypeError("not a web endpoint");
  }
  return endpoint;
};

describe("Web adapter", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test("a command pumps once, then at the endpoint's next deadline", async () => {
    vi.useFakeTimers();
    const endpoint = create();
    const native = fake();
    native.pumpDelays = [0, 0, 50];

    endpoint.startConnect("12D3KooWPeer");
    endpoint.startConnect("12D3KooWPeer");
    await vi.advanceTimersByTimeAsync(0);
    // Two commands coalesce into one burst that polls until the deadline.
    expect(native.pumps).toBe(3);

    await vi.advanceTimersByTimeAsync(49);
    expect(native.pumps).toBe(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(native.pumps).toBe(4);
    endpoint.close();
  });

  test("a trapped wasm call fails the endpoint, then calls throw ClosedError", async () => {
    vi.useFakeTimers();
    const endpoint = create();
    const native = fake();
    const failures: string[] = [];
    endpoint.on("driverFailed", ({ kind }) => failures.push(kind));
    const reports: unknown[] = [];
    endpoint.onClose((report) => reports.push(report));
    native.trapOn = "ping";

    expect(() => endpoint.ping("12D3KooWPeer")).toThrow(DriverFailedError);
    await vi.advanceTimersByTimeAsync(0);

    expect(failures).toEqual(["Panic"]);
    expect(reports).toMatchObject([{ reason: "driverFailed" }]);
    expect(() => endpoint.connectedPeers()).toThrow(ClosedError);
    expect(native.closeTimeouts).toEqual([]);
  });

  test("a trap while pumping fails the endpoint", async () => {
    vi.useFakeTimers();
    const endpoint = create();
    const native = fake();
    const failures: string[] = [];
    endpoint.on("driverFailed", ({ detail }) => failures.push(detail));
    native.trapOn = "pump";

    endpoint.startConnect("12D3KooWPeer");
    await vi.advanceTimersByTimeAsync(0);

    expect(failures).toEqual([expect.stringContaining("trapped")]);
    expect(endpoint.isRunning()).toBe(false);
  });
});

describeAdapterContract("Web", {
  create: (config = {}) =>
    Minip2p.create({ ...config, secretKey: new Uint8Array(32) }),
  native: () => serdeContractNative(fake()),
});
