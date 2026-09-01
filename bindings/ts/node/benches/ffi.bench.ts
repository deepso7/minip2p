/* oxlint-disable func-style, no-await-in-loop, no-use-before-define, unicorn/no-useless-undefined -- Benchmark fixtures use bounded polling to keep the measured native event path explicit. */

import { setTimeout as delay } from "node:timers/promises";

import { afterAll, beforeAll, bench, describe } from "vitest";

import { Minip2p, generateSecretKey } from "../src/index.js";
import { nativeBinding } from "../src/native.js";
import type { NativeEndpoint } from "../src/native.js";

const BURST = 64;
const TIMEOUT_MS = 10_000;
const PROTOCOL = "/minip2p/node-bench/1";
let sdkA: Minip2p;
let sdkB: Minip2p;
let rawA: NativeEndpoint;
let rawB: NativeEndpoint;

beforeAll(async () => {
  sdkA = createSdk();
  sdkB = createSdk();
  await sdkA.connectAddr(sdkB.listenAddrs()[0], { timeoutMs: TIMEOUT_MS });
  await Promise.all([
    sdkA.waitPeerReady(sdkB.peerId(), { timeoutMs: TIMEOUT_MS }),
    sdkB.waitPeerReady(sdkA.peerId(), { timeoutMs: TIMEOUT_MS }),
  ]);
  rawA = createRaw();
  rawB = createRaw();
  rawA.connectAddr(rawB.listenAddrs()[0]);
  await Promise.all([
    waitRawReady(rawA, rawB.peerId()),
    waitRawReady(rawB, rawA.peerId()),
  ]);
});

afterAll(() => {
  sdkA.close();
  sdkB.close();
  rawA.close();
  rawB.close();
});

describe("node-ffi", () => {
  bench("sdk_drain_flood", async () => {
    await Promise.all(
      Array.from({ length: BURST }, () =>
        sdkA.ping(sdkB.peerId(), { timeoutMs: TIMEOUT_MS })
      )
    );
  });

  bench("raw_drain_events", async () => {
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
      rawA.abandonStream(rawB.peerId(), stream.streamId);
    }
  });

  bench("connected_peers_sync", () => {
    for (let index = 0; index < 1000; index += 1) {
      sdkA.connectedPeers();
    }
  });
});

function createSdk(): Minip2p {
  return Minip2p.create({
    secretKey: generateSecretKey(),
    transports: { tcp: { listen: ["/ip4/127.0.0.1/tcp/0"] } },
  });
}

function createRaw(): NativeEndpoint {
  const endpoint = new nativeBinding.NodeEndpoint(
    nativeBinding.generateSecretKey(),
    {
      allowUnsigned: false,
      autonatServers: [],
      forceRelay: false,
      protocols: [PROTOCOL],
      pubsubRouter: 1,
      relays: [],
      tcp: { listenAddrs: ["/ip4/127.0.0.1/tcp/0"] },
    }
  );
  endpoint.start(() => undefined);
  return endpoint;
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
