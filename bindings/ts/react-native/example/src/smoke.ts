/* oxlint-disable func-style, no-await-in-loop, no-use-before-define, promise/avoid-new, unicorn/no-array-sort -- The executable smoke suite uses sequential native lifecycle checks, hoisted test helpers, Promise adapters for event waits and delays, and sorts a fresh latency sample in place. */

import {
  DiscoverySource,
  MiniP2p,
  P2pEvent_Tags,
  generateSecretKey,
} from "@minip2p/react-native";
import type {
  MiniP2pConfig,
  MiniP2pEvent,
  P2pEvent,
} from "@minip2p/react-native";

declare const TextEncoder: new () => {
  encode: (input: string) => Uint8Array;
};

declare const performance: {
  now: () => number;
};

const TOPIC = "/minip2p/react-native-smoke/1";
const STREAM_PROTOCOL = "/minip2p/react-native-smoke-stream/1";
const WAIT_MS = 10_000;
const MDNS_WAIT_MS = 20_000;
const LARGE_PAYLOAD_BYTES = 60 * 1024;
const CYCLE_COUNT = 50;
// This is a smoke-regression gate based on the concurrency spike, not an API
// latency guarantee.
const MAX_SYNC_CALL_LATENCY_MS = 50;

export interface SmokeResult {
  readonly name: string;
  readonly passed: boolean;
  readonly detail?: string;
}

export type SmokeReport = (result: SmokeResult) => void;

export async function runSmokeSuite(
  report: SmokeReport,
  liveEndpoints: Set<MiniP2p>
): Promise<void> {
  let first: MiniP2p | undefined;
  let second: MiniP2p | undefined;

  try {
    first = createEndpoint(liveEndpoints);
    second = createEndpoint(liveEndpoints);
    const firstPeer = first.peerId();
    const secondPeer = second.peerId();

    check(
      first.listenAddrs().length === 1 && second.listenAddrs().length === 1,
      "construct-two-endpoints",
      `${shortPeer(firstPeer)} ↔ ${shortPeer(secondPeer)}`,
      report
    );

    let reentrantPeerSeen = false;
    let throwingHandlerRan = false;
    let observingHandlerMessages = 0;

    first.on((event) => {
      if (isNativeEvent(event, P2pEvent_Tags.PathEstablished)) {
        reentrantPeerSeen =
          first?.connectedPeers().includes(secondPeer) ?? false;
      }
      if (isNativeEvent(event, P2pEvent_Tags.Message)) {
        throwingHandlerRan = true;
        throw new Error("intentional smoke-listener exception");
      }
    });
    first.on((event) => {
      if (isNativeEvent(event, P2pEvent_Tags.Message)) {
        observingHandlerMessages += 1;
      }
    });

    first.subscribe(TOPIC);
    second.subscribe(TOPIC);

    const firstReady = first.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.PeerReady) &&
        event.inner.peerId === secondPeer &&
        event.inner.protocols.some((protocol) => protocol.includes("meshsub")),
      WAIT_MS
    );
    const secondReady = second.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.PeerReady) &&
        event.inner.peerId === firstPeer,
      WAIT_MS
    );
    const subscription = first.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.PeerSubscribed) &&
        event.inner.peerId === secondPeer &&
        event.inner.topic === TOPIC,
      WAIT_MS
    );

    const connectId = first.connectAddr(second.listenAddrs()[0] as string);
    const path = await first.waitConnectResult(connectId, WAIT_MS);
    await Promise.all([firstReady, secondReady, subscription]);

    check(
      isNativeEvent(path, P2pEvent_Tags.PathEstablished),
      "direct-loopback-path",
      `connectId=${connectId}`,
      report
    );
    check(
      reentrantPeerSeen,
      "callback-reentrancy",
      "connectedPeers() succeeded inside PathEstablished",
      report
    );
    check(
      first.peerInfo(secondPeer)?.protocols.includes(STREAM_PROTOCOL) === true,
      "identify-snapshot",
      "custom protocol present in peerInfo()",
      report
    );

    const pingRtt = first.waitPingRtt(secondPeer, WAIT_MS);
    first.ping(secondPeer);
    const ping = await pingRtt;
    check(
      ping.inner.rttMs >= 0,
      "explicit-ping",
      `rtt=${ping.inner.rttMs}ms`,
      report
    );

    const localStreamReady = first.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.StreamReady) &&
        event.inner.peerId === secondPeer &&
        event.inner.protocolId === STREAM_PROTOCOL &&
        event.inner.initiatedLocally,
      WAIT_MS
    );
    const remoteStreamReady = second.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.StreamReady) &&
        event.inner.peerId === firstPeer &&
        event.inner.protocolId === STREAM_PROTOCOL &&
        !event.inner.initiatedLocally,
      WAIT_MS
    );
    const streamId = first.openStream(secondPeer, STREAM_PROTOCOL);
    await Promise.all([localStreamReady, remoteStreamReady]);
    const streamPayload = encodeUtf8("custom stream through UniFFI");
    const streamData = second.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.StreamData) &&
        sameBytes(event.inner.data, streamPayload),
      WAIT_MS
    );
    first.sendStream(secondPeer, streamId, streamPayload);
    first.closeStreamWrite(secondPeer, streamId);
    await streamData;
    check(
      true,
      "custom-protocol-stream",
      `${streamPayload.byteLength} bytes preserved`,
      report
    );

    const unicode = "minip2p says नमस्ते, こんにちは, and 👋";
    const unicodeBytes = encodeUtf8(unicode);
    const unicodeMessage = first.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.Message) &&
        sameBytes(event.inner.data, unicodeBytes),
      WAIT_MS
    );
    second.publish(TOPIC, unicode);
    await unicodeMessage;
    check(true, "unicode-message", `${unicodeBytes.byteLength} bytes`, report);

    const large = new Uint8Array(LARGE_PAYLOAD_BYTES);
    for (let index = 0; index < large.length; index += 1) {
      large[index] = index % 251;
    }
    const largeMessage = first.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.Message) &&
        sameBytes(event.inner.data, large),
      WAIT_MS
    );
    second.publish(TOPIC, large.buffer);
    await largeMessage;
    check(
      true,
      "large-message",
      `${LARGE_PAYLOAD_BYTES} bytes preserved`,
      report
    );
    check(
      throwingHandlerRan && observingHandlerMessages >= 2,
      "throwing-handler-contained",
      "second subscriber and waiters continued receiving",
      report
    );

    const activeSamples = sampleLatencies(50, () => first?.connectedPeers());
    first.setActive(false);
    await delay(650);
    const idleQuery = elapsed(() => first?.connectedPeers());
    first.setActive(false);
    await delay(650);
    const foregroundSignal = elapsed(() => first?.setActive(true));
    const foregroundQuery = elapsed(() => first?.connectedPeers());
    const activeP95 = percentile(activeSamples, 0.95);
    check(
      activeP95 <= MAX_SYNC_CALL_LATENCY_MS &&
        idleQuery <= MAX_SYNC_CALL_LATENCY_MS &&
        foregroundSignal <= MAX_SYNC_CALL_LATENCY_MS &&
        foregroundQuery <= MAX_SYNC_CALL_LATENCY_MS,
      "contention-latency",
      `active p50=${percentile(activeSamples, 0.5).toFixed(1)}ms ` +
        `p95=${activeP95.toFixed(1)}ms; ` +
        `idle=${idleQuery.toFixed(1)}ms; setActive=${foregroundSignal.toFixed(
          1
        )}ms; next=${foregroundQuery.toFixed(1)}ms; ` +
        `budget=${MAX_SYNC_CALL_LATENCY_MS}ms`,
      report
    );

    let closedDuringCallback = false;
    const closeObserved = new Promise<void>((resolve) => {
      first?.on((event) => {
        if (
          isNativeEvent(event, P2pEvent_Tags.Message) &&
          sameBytes(event.inner.data, encodeUtf8("close-during-delivery"))
        ) {
          closedDuringCallback = true;
          first?.close();
          liveEndpoints.delete(first as MiniP2p);
          resolve();
        }
      });
    });
    second.publish(TOPIC, "close-during-delivery");
    await withTimeout(closeObserved, WAIT_MS, "close callback");
    check(
      closedDuringCallback && !first.isRunning(),
      "close-during-delivery",
      "queued tail suppressed without unwinding into Rust",
      report
    );
    first = undefined;

    second.close();
    liveEndpoints.delete(second);
    second = undefined;

    await runMdnsDiscoveryCheck(report, liveEndpoints);

    let endpoint = createEndpoint(liveEndpoints);
    let reboundCycles = 0;
    for (let cycle = 0; cycle < CYCLE_COUNT; cycle += 1) {
      const releasedAddr = transportAddress(
        endpoint.listenAddrs()[0] as string
      );
      endpoint.close();
      liveEndpoints.delete(endpoint);
      endpoint = await createEndpointAtAddress(
        liveEndpoints,
        releasedAddr,
        WAIT_MS
      );
      reboundCycles += 1;
    }
    endpoint.close();
    liveEndpoints.delete(endpoint);
    check(
      reboundCycles === CYCLE_COUNT,
      "create-close-cycles",
      `${reboundCycles} cycles released and rebound the same native UDP socket`,
      report
    );

    const third = createEndpoint(liveEndpoints);
    const fourth = createEndpoint(liveEndpoints);
    fourth.close();
    liveEndpoints.delete(fourth);
    third.close();
    liveEndpoints.delete(third);
    check(
      !third.isRunning() && !fourth.isRunning(),
      "reverse-close-order",
      "second endpoint closed first and both stopped",
      report
    );
  } finally {
    if (first !== undefined) {
      first.close();
      liveEndpoints.delete(first);
    }
    if (second !== undefined) {
      second.close();
      liveEndpoints.delete(second);
    }
  }
}

function createEndpoint(
  liveEndpoints: Set<MiniP2p>,
  listenAddr = "/ip4/127.0.0.1/udp/0/quic-v1"
): MiniP2p {
  const config: MiniP2pConfig = {
    agentVersion: "minip2p-react-native-smoke",
    allowUnsigned: false,
    forceRelay: false,
    listenAddr,
    protocols: [STREAM_PROTOCOL],
    relays: [],
    secretKey: generateSecretKey(),
  };
  const endpoint = MiniP2p.create(config);
  liveEndpoints.add(endpoint);
  return endpoint;
}

async function createEndpointAtAddress(
  liveEndpoints: Set<MiniP2p>,
  listenAddr: string,
  timeoutMs: number
): Promise<MiniP2p> {
  const deadline = performance.now() + timeoutMs;
  let lastError: unknown;
  while (performance.now() < deadline) {
    try {
      return createEndpoint(liveEndpoints, listenAddr);
    } catch (error) {
      lastError = error;
      await delay(10);
    }
  }
  throw new Error(
    `native socket was not released for ${listenAddr}: ${String(lastError)}`
  );
}

function transportAddress(peerAddress: string): string {
  const peerSuffix = peerAddress.lastIndexOf("/p2p/");
  if (peerSuffix === -1) {
    throw new Error(`listen address has no peer ID: ${peerAddress}`);
  }
  return peerAddress.slice(0, peerSuffix);
}

async function runMdnsDiscoveryCheck(
  report: SmokeReport,
  liveEndpoints: Set<MiniP2p>
): Promise<void> {
  let first: MiniP2p | undefined;
  let second: MiniP2p | undefined;

  try {
    first = createMdnsEndpoint(liveEndpoints);
    const discoveredSecond = first.waitFor(
      (event) =>
        isNativeEvent(event, P2pEvent_Tags.PeerDiscovered) &&
        event.inner.source === DiscoverySource.Mdns &&
        event.inner.peerId === second?.peerId() &&
        event.inner.addrs.length > 0,
      MDNS_WAIT_MS
    );
    second = createMdnsEndpoint(liveEndpoints);

    const discovered = await discoveredSecond;
    if (!isNativeEvent(discovered, P2pEvent_Tags.PeerDiscovered)) {
      throw new Error("mDNS waiter returned an unexpected event");
    }
    const known = first
      .knownPeers()
      .find((peer) => peer.peerId === second?.peerId());
    check(
      known !== undefined &&
        known.mdnsAddrs.length > 0 &&
        discovered.inner.addrs.length > 0,
      "mdns-discovery",
      `${discovered.inner.addrs.length} event addrs; ${known?.mdnsAddrs.length ?? 0} known addrs`,
      report
    );
  } finally {
    if (first !== undefined) {
      first.close();
      liveEndpoints.delete(first);
    }
    if (second !== undefined) {
      second.close();
      liveEndpoints.delete(second);
    }
  }
}

function createMdnsEndpoint(liveEndpoints: Set<MiniP2p>): MiniP2p {
  const endpoint = MiniP2p.create({
    agentVersion: "minip2p-react-native-mdns-smoke",
    allowUnsigned: false,
    forceRelay: false,
    mdns: {
      autoDial: false,
      queryIntervalMs: 1000,
      socketPollIntervalMs: 50,
    },
    protocols: [],
    relays: [],
    secretKey: generateSecretKey(),
  });
  liveEndpoints.add(endpoint);
  return endpoint;
}

function isNativeEvent<Tag extends P2pEvent_Tags>(
  event: MiniP2pEvent,
  tag: Tag
): event is Extract<P2pEvent, { tag: Tag }> {
  return "tag" in event && event.tag === tag;
}

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function sameBytes(actual: ArrayBuffer, expected: Uint8Array): boolean {
  const bytes = new Uint8Array(actual);
  if (bytes.length !== expected.length) {
    return false;
  }
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== expected[index]) {
      return false;
    }
  }
  return true;
}

function sampleLatencies(count: number, operation: () => unknown): number[] {
  const samples: number[] = [];
  for (let index = 0; index < count; index += 1) {
    samples.push(elapsed(operation));
  }
  return samples.sort((left, right) => left - right);
}

function elapsed(operation: () => unknown): number {
  const started = performance.now();
  operation();
  return performance.now() - started;
}

function percentile(samples: readonly number[], quantile: number): number {
  if (samples.length === 0) {
    return 0;
  }
  const index = Math.min(
    samples.length - 1,
    Math.ceil(samples.length * quantile) - 1
  );
  return samples[index] as number;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${label} timed out after ${timeoutMs} ms`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

function check(
  condition: boolean,
  name: string,
  detail: string,
  report: SmokeReport
): asserts condition {
  report({ detail, name, passed: condition });
  if (!condition) {
    throw new Error(`${name}: ${detail}`);
  }
}

function shortPeer(peerId: string): string {
  return `${peerId.slice(0, 8)}…${peerId.slice(-6)}`;
}
