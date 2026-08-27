/* oxlint-disable func-style, no-await-in-loop, no-use-before-define, unicorn/no-useless-undefined -- The native integration test keeps its polling helpers below the behavioral cases. */

import { setTimeout as delay } from "node:timers/promises";

import { afterEach, describe, expect, test } from "vitest";

import { nativeBinding } from "../src/native.js";
import type { NativeEndpoint } from "../src/native.js";

const endpoints: NativeEndpoint[] = [];

afterEach(() => {
  for (const endpoint of endpoints.splice(0)) {
    endpoint.close();
  }
});

describe("native event payloads", () => {
  test("delivers stream bytes as a Uint8Array", async () => {
    const protocol = "/minip2p/node-native-events/1";
    const a = createEndpoint(protocol);
    const b = createEndpoint(protocol);
    a.connectAddr(b.listenAddrs()[0]);

    await Promise.all([
      waitPeerReady(a, b.peerId()),
      waitPeerReady(b, a.peerId()),
    ]);

    const stream = a.openStream(b.peerId(), protocol);
    await Promise.all([
      waitForEvent(a, "StreamReady"),
      waitForEvent(b, "StreamReady"),
    ]);
    a.sendStream(b.peerId(), stream.streamId, Uint8Array.of(0, 127, 255));

    const event = await waitForEvent(b, "StreamData");
    const data = Reflect.get(event.inner, "data");
    expect(data).toBeInstanceOf(Uint8Array);
    expect([...data]).toEqual([0, 127, 255]);
  }, 15_000);

  test("delivers pubsub bytes as Uint8Arrays", async () => {
    const a = createEndpoint();
    const b = createEndpoint();
    a.subscribe("native-events");
    b.subscribe("native-events");
    a.connectAddr(b.listenAddrs()[0]);

    await Promise.all([
      waitPeerReady(a, b.peerId()),
      waitPeerReady(b, a.peerId()),
    ]);
    await delay(100);
    a.publish("native-events", Uint8Array.of(1, 128, 254));

    const event = await waitForEvent(b, "Message");
    const data = Reflect.get(event.inner, "data");
    const seqno = Reflect.get(event.inner, "seqno");
    expect(data).toBeInstanceOf(Uint8Array);
    expect([...data]).toEqual([1, 128, 254]);
    expect(seqno).toBeInstanceOf(Uint8Array);
    expect(seqno.byteLength).toBeGreaterThan(0);
  }, 15_000);
});

function createEndpoint(protocol?: string): NativeEndpoint {
  const endpoint = new nativeBinding.NodeEndpoint(
    nativeBinding.generateSecretKey(),
    {
      allowUnsigned: false,
      autonatServers: [],
      forceRelay: false,
      protocols: protocol === undefined ? [] : [protocol],
      pubsubRouter: 1,
      quic: { listenAddrs: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
      relays: [],
    }
  );
  endpoint.start(() => undefined);
  endpoints.push(endpoint);
  return endpoint;
}

async function waitPeerReady(
  endpoint: NativeEndpoint,
  peerId: string
): Promise<void> {
  await waitForEvent(
    endpoint,
    "PeerReady",
    (event) => Reflect.get(event.inner, "peerId") === peerId
  );
}

interface NativeEvent {
  readonly inner: object;
  readonly tag: string;
}

async function waitForEvent(
  endpoint: NativeEndpoint,
  tag: string,
  matches: (event: NativeEvent) => boolean = () => true
): Promise<NativeEvent> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    for (const value of endpoint.drainEvents(256)) {
      if (isNativeEvent(value) && value.tag === tag && matches(value)) {
        return value;
      }
    }
    await delay(5);
  }
  throw new Error(`Timed out waiting for native ${tag} event`);
}

function isNativeEvent(value: unknown): value is NativeEvent {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof Reflect.get(value, "tag") === "string" &&
    Reflect.get(value, "inner") !== null &&
    typeof Reflect.get(value, "inner") === "object"
  );
}
