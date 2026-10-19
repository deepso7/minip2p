import { ClosedError, DriverFailedError } from "@minip2p/core";
import { describeAdapterContract } from "@minip2p/test-fixtures/adapter-contract";
import {
  FakeSerdeEndpoint,
  latestFakeSerdeEndpoint,
  serdeContractNative,
} from "@minip2p/test-fixtures/fake-serde-endpoint";
import { afterEach, describe, expect, test, vi } from "vitest";

import type { JsIo, WebTransportSession } from "../src/io.js";
import { Minip2p } from "../src/sdk.js";

/** Sessions {@link PendingWebTransport} closed. */
let sessionCloses = 0;

/**
 * A browser `WebTransport` constructor whose sessions never connect: a
 * `function`, since `new` cannot call an arrow.
 */
const PendingWebTransport =
  function PendingWebTransport(): WebTransportSession {
    const never = Promise.withResolvers<never>().promise;
    return {
      close: () => {
        sessionCloses += 1;
      },
      closed: never,
      createBidirectionalStream: async () => await never,
      incomingBidirectionalStreams: new ReadableStream(),
      ready: never,
    };
  };

/** The wasm `WebEndpoint`: the serde fake plus the pump the adapter drives. */
class FakeWebEndpoint extends FakeSerdeEndpoint {
  /** What successive `pump` calls return; `undefined` once exhausted. */
  pumpDelays: (number | undefined)[] = [];
  pumps = 0;
  /** How many times the wasm object was freed. */
  frees = 0;
  /** Makes the next call to `method` trap like a panicking wasm module. */
  trapOn: string | undefined;
  /** The browser I/O the Rust client would drive. */
  readonly io: JsIo;

  constructor(secretKey: Uint8Array, config: unknown, io: JsIo) {
    super(secretKey, config);
    this.io = io;
  }

  override close(timeoutMs: number): void {
    this.#trap("close");
    super.close(timeoutMs);
  }

  pump(): number | undefined {
    this.pumps += 1;
    this.#trap("pump");
    return this.pumpDelays.shift();
  }

  override ping(): void {
    this.#trap("ping");
  }

  override drainEvents(
    limit: number
  ): ReturnType<FakeSerdeEndpoint["drainEvents"]> {
    this.#trap("drainEvents");
    return super.drainEvents(limit);
  }

  free(): void {
    this.frees += 1;
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
    vi.unstubAllGlobals();
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

  test("a trap closes the browser sessions the wasm endpoint can no longer close", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("WebTransport", PendingWebTransport);
    sessionCloses = 0;
    const endpoint = create();
    const native = fake();
    // What a pending Rust dial leaves open in the browser.
    native.io.connect("https://192.0.2.1:4001/", []);
    native.trapOn = "ping";

    expect(() => endpoint.ping("12D3KooWPeer")).toThrow(DriverFailedError);
    await expect(endpoint.close()).resolves.toMatchObject({
      outcome: "Failed",
    });

    expect(sessionCloses).toBe(1);
    expect(native.io.pollEvent()).toBeUndefined();
    expect(() => native.io.connect("https://192.0.2.1:4001/", [])).toThrow();
  });

  test("a trap in close itself still settles close, releases and notifies observers", async () => {
    vi.useFakeTimers();
    const endpoint = create();
    const native = fake();
    const reports: unknown[] = [];
    endpoint.onClose((report) => reports.push(report));
    native.pumpDelays = [30];
    native.trapOn = "close";

    await expect(endpoint.close()).resolves.toMatchObject({
      outcome: "Failed",
      reason: "close",
    });
    expect(reports).toMatchObject([{ outcome: "Failed", reason: "close" }]);
    // The pump stopped with the release.
    const { pumps } = native;
    await vi.advanceTimersByTimeAsync(100);
    expect(native.pumps).toBe(pumps);
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

  test("a trap while close drains its final events still settles close", async () => {
    vi.useFakeTimers();
    const endpoint = create();
    const native = fake();
    native.trapOn = "drainEvents";

    const closed = endpoint.close();
    await vi.advanceTimersByTimeAsync(0);

    await expect(closed).resolves.toMatchObject({
      outcome: "Failed",
      reason: "close",
    });
  });

  test("close frees the wasm endpoint once its final events drained, and stops pumping", async () => {
    vi.useFakeTimers();
    const endpoint = create();
    const native = fake();
    // The pump close runs arms one more deadline.
    native.pumpDelays = [0, 30];

    const closed = endpoint.close();
    expect(native.frees).toBe(0);
    await vi.advanceTimersByTimeAsync(0);
    await closed;
    expect(native.frees).toBe(1);
    const { pumps } = native;
    // That deadline no longer pumps the freed endpoint.
    await vi.advanceTimersByTimeAsync(100);
    expect(native.pumps).toBe(pumps);
  });
});

describeAdapterContract("Web", {
  create: (config = {}) =>
    Minip2p.create({ ...config, secretKey: new Uint8Array(32) }),
  native: () => serdeContractNative(fake()),
});
