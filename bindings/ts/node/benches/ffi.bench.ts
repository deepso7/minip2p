/* oxlint-disable func-style, no-await-in-loop, no-use-before-define, promise/avoid-new, unicorn/no-useless-undefined -- Benchmark fixtures use bounded polling and hand-rolled waiters to keep the measured native event path explicit. */

import { setTimeout as delay } from "node:timers/promises";

import { afterAll, beforeAll, describe, test } from "vitest";

import { Minip2p, generateSecretKey } from "../src/index.js";
import type { Stream } from "../src/index.js";
import { nativeBinding } from "../src/native.js";
import type { NativeEndpoint } from "../src/native.js";

const BURST = 64;
const TIMEOUT_MS = 10_000;
const PROTOCOL = "/minip2p/node-bench/1";
const TRANSFER_PROTOCOL = "/minip2p/node-bench-transfer/1";
const TRANSFER_CHUNK = new Uint8Array(16 * 1024);
const TRANSFER_CHUNKS = 64;
let sdkA: Minip2p;
let sdkB: Minip2p;
let rawA: NativeEndpoint;
let rawB: NativeEndpoint;
let transfer: Stream;
/** Resolves once `bytes` more transfer bytes reached `sdkB`. */
let awaitTransferred: (bytes: number) => Promise<void>;
const cleanup: (() => void)[] = [];

beforeAll(async () => {
  sdkA = createSdk();
  cleanup.push(() => sdkA.close());
  sdkB = createSdk();
  cleanup.push(() => sdkB.close());
  awaitTransferred = receiveTransfers(sdkB);
  sdkB.on("stream", (stream) => {
    // Match the raw remote, which drains ready events without rejecting them.
    void stream;
  });
  await sdkA.connect(firstAddr(sdkB.listenAddrs()), { timeoutMs: TIMEOUT_MS });
  await Promise.all([
    sdkA.waitPeerReady(sdkB.peerId(), { timeoutMs: TIMEOUT_MS }),
    sdkB.waitPeerReady(sdkA.peerId(), { timeoutMs: TIMEOUT_MS }),
  ]);
  transfer = await sdkA.openStream(sdkB.peerId(), TRANSFER_PROTOCOL, {
    timeoutMs: TIMEOUT_MS,
  });
  rawA = createRaw();
  cleanup.push(() => rawA.close());
  rawB = createRaw(true);
  cleanup.push(() => rawB.close());
  rawA.connect([firstAddr(rawB.listenAddrs())]);
  await Promise.all([
    waitRawReady(rawA, rawB.peerId()),
    waitRawReady(rawB, rawA.peerId()),
  ]);
});

afterAll(() => {
  for (const close of cleanup.splice(0).toReversed()) {
    close();
  }
});

describe("node-ffi", () => {
  test("sdk_drain_flood", async ({ bench }) => {
    await bench("sdk_drain_flood", async () => {
      const streams = await Promise.all(
        Array.from({ length: BURST }, () =>
          sdkA.openStream(sdkB.peerId(), PROTOCOL, { timeoutMs: TIMEOUT_MS })
        )
      );
      for (const stream of streams) {
        stream.abandon();
      }
    }).run();
  });

  // Per-write and per-chunk cost: 1 MiB in 16 KiB writes, read by a flowing
  // `data` handler on the remote.
  test("sdk_stream_transfer", async ({ bench }) => {
    await bench("sdk_stream_transfer", async () => {
      const received = awaitTransferred(
        TRANSFER_CHUNK.byteLength * TRANSFER_CHUNKS
      );
      for (let index = 0; index < TRANSFER_CHUNKS; index += 1) {
        await transfer.write(TRANSFER_CHUNK);
      }
      await received;
    }).run();
  });

  test("raw_drain_events", async ({ bench }) => {
    await bench("raw_drain_events", async () => {
      const streams = Array.from({ length: BURST }, () =>
        rawA.openStream(rawB.peerId(), PROTOCOL)
      );
      let seen = 0;
      const deadline = Date.now() + TIMEOUT_MS;
      while (seen < BURST && Date.now() < deadline) {
        for (const event of rawA.drainEvents(256)) {
          if (isNativeEvent(event) && event.tag === "StreamReady") {
            seen += 1;
          }
        }
        if (seen < BURST) {
          await delay(0);
        }
      }
      if (seen !== BURST) {
        throw new Error(`Timed out draining raw events: ${seen}/${BURST}`);
      }
      for (const stream of streams) {
        rawA.abandonStream(
          rawB.peerId(),
          BigInt(stream.connId),
          BigInt(stream.streamId)
        );
      }
    }).run();
  });

  test("connected_peers_sync", async ({ bench }) => {
    await bench("connected_peers_sync", () => {
      for (let index = 0; index < 1000; index += 1) {
        sdkA.connectedPeers();
      }
    }).run();
  });
});

function createSdk(): Minip2p {
  return Minip2p.create({
    listen: ["/ip4/127.0.0.1/tcp/0"],
    protocols: [PROTOCOL, TRANSFER_PROTOCOL],
    secretKey: generateSecretKey(),
  });
}

function createRaw(drainOnDoorbell = false): NativeEndpoint {
  const endpoint = new nativeBinding.NodeEndpoint(
    nativeBinding.generateSecretKey(),
    {
      allowUnsigned: false,
      autonatServers: [],
      forceRelay: false,
      listen: ["/ip4/127.0.0.1/tcp/0"],
      protocols: [PROTOCOL],
      relays: [],
    }
  );
  endpoint.start(() => {
    if (drainOnDoorbell) {
      drainAllEvents(endpoint);
    }
  });
  return endpoint;
}

/**
 * Reads every transfer stream `sdk` accepts, and returns a waiter for the
 * next `bytes` received.
 */
function receiveTransfers(sdk: Minip2p): (bytes: number) => Promise<void> {
  let received = 0;
  let target = 0;
  let done: (() => void) | undefined;
  sdk.on("stream", (stream) => {
    if (stream.protocolId !== TRANSFER_PROTOCOL) {
      return;
    }
    stream.on("data", (chunk) => {
      received += chunk.byteLength;
      if (done !== undefined && received >= target) {
        done();
        done = undefined;
      }
    });
  });
  return (bytes) => {
    target = received + bytes;
    const promise = new Promise<void>((resolve) => {
      done = resolve;
    });
    return withTimeout(promise, "transfer");
  };
}

async function withTimeout<Value>(
  promise: Promise<Value>,
  what: string
): Promise<Value> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Timed out waiting for ${what}`));
    }, TIMEOUT_MS);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function firstAddr(addrs: readonly string[]): string {
  const [addr] = addrs;
  if (addr === undefined) {
    throw new Error("Endpoint has no listen address");
  }
  return addr;
}

function drainAllEvents(endpoint: NativeEndpoint): void {
  while (endpoint.drainEvents(256).length === 256) {
    // The native doorbell is edge-triggered, so empty the queue before returning.
  }
}

async function waitRawReady(
  endpoint: NativeEndpoint,
  peerId: string
): Promise<void> {
  const deadline = Date.now() + TIMEOUT_MS;
  while (Date.now() < deadline) {
    endpoint.drainEvents(256);
    if (endpoint.isPeerReady(peerId)) {
      return;
    }
    await delay(1);
  }
  throw new Error(`Timed out waiting for ${peerId}`);
}

interface NativeEvent {
  readonly tag: string;
}

function isNativeEvent(value: unknown): value is NativeEvent {
  return (
    value !== null &&
    typeof value === "object" &&
    "tag" in value &&
    typeof value.tag === "string"
  );
}
