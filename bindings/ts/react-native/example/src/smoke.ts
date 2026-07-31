/* oxlint-disable func-style, no-await-in-loop, no-use-before-define -- This is an executable sequential native smoke suite. */

import {
  DiscoverySource,
  Minip2p,
  generateSecretKey,
} from "@minip2p/react-native";
import type { Minip2pConfig } from "@minip2p/react-native";

const TOPIC = "/minip2p/react-native-smoke/1";
const STREAM_PROTOCOL = "/minip2p/react-native-smoke-stream/1";
const WAIT_MS = 10_000;

export interface SmokeResult {
  readonly name: string;
  readonly passed: boolean;
  readonly detail?: string;
}

export type SmokeReport = (result: SmokeResult) => void;

export async function runSmokeSuite(
  report: SmokeReport,
  liveEndpoints: Set<Minip2p>
): Promise<void> {
  let first: Minip2p | undefined;
  let second: Minip2p | undefined;
  try {
    first = createEndpoint(liveEndpoints);
    second = createEndpoint(liveEndpoints);
    const firstPeer = first.peerId();
    const secondPeer = second.peerId();
    report({
      detail: `${shortPeer(firstPeer)} ↔ ${shortPeer(secondPeer)}`,
      name: "construct-two-endpoints",
      passed: first.listenAddrs().length > 0 && second.listenAddrs().length > 0,
    });

    first.subscribe(TOPIC);
    second.subscribe(TOPIC);
    const firstReady = first.waitPeerReady(secondPeer, {
      timeoutMs: WAIT_MS,
    });
    const secondReady = second.waitPeerReady(firstPeer, {
      timeoutMs: WAIT_MS,
    });
    const result = await first.connectAddr(second.listenAddrs()[0] as string, {
      timeoutMs: WAIT_MS,
    });
    await Promise.all([firstReady, secondReady]);
    report({
      detail: `${result.path.kind}; connectId=${result.connectId}`,
      name: "direct-loopback-path",
      passed: first.path(secondPeer)?.kind === "directDialed",
    });

    const rttMs = await first.ping(secondPeer, { timeoutMs: WAIT_MS });
    report({
      detail: `rtt=${rttMs}ms`,
      name: "explicit-ping",
      passed: rttMs >= 0,
    });

    const inbound = second.once("stream", {
      signal: undefined,
      timeoutMs: WAIT_MS,
    });
    const outbound = await first.openStream(secondPeer, STREAM_PROTOCOL, {
      timeoutMs: WAIT_MS,
    });
    const remote = await inbound;
    outbound.write("custom stream through UniFFI");
    outbound.closeWrite();
    const chunk = await remote.read();
    report({
      detail: `${chunk?.byteLength ?? 0} bytes preserved`,
      name: "custom-protocol-stream",
      passed: chunk !== undefined && chunk.byteLength > 0,
    });
    outbound.abandon();
    remote.abandon();

    const message = first.waitFor("message", {
      predicate: (event) => event.fromPeerId === secondPeer,
      timeoutMs: WAIT_MS,
    });
    second.publish(TOPIC, "minip2p says नमस्ते, こんにちは, and 👋");
    const received = await message;
    report({
      detail: `${received.data.byteLength} bytes`,
      name: "unicode-message",
      passed: received.data.byteLength > 0,
    });

    first.close();
    liveEndpoints.delete(first);
    first = undefined;
    second.close();
    liveEndpoints.delete(second);
    second = undefined;

    await runMdnsDiscoveryCheck(report, liveEndpoints);
    await runCreateCloseCycles(report, liveEndpoints);
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
  liveEndpoints: Set<Minip2p>,
  listenAddr = "/ip4/127.0.0.1/udp/0/quic-v1",
  mdns = false
): Minip2p {
  const config: Minip2pConfig = {
    agentVersion: "minip2p-react-native-smoke",
    listenAddr,
    mdns: mdns
      ? { autoDial: false, queryIntervalMs: 1000, socketPollIntervalMs: 50 }
      : undefined,
    protocols: [STREAM_PROTOCOL],
    secretKey: generateSecretKey(),
  };
  const endpoint = Minip2p.create(config);
  liveEndpoints.add(endpoint);
  return endpoint;
}

async function runMdnsDiscoveryCheck(
  report: SmokeReport,
  liveEndpoints: Set<Minip2p>
): Promise<void> {
  const first = createEndpoint(liveEndpoints, undefined, true);
  const second = createEndpoint(liveEndpoints, undefined, true);
  try {
    const discovered = await first.waitFor("peerDiscovered", {
      predicate: (event) =>
        event.peerId === second.peerId() &&
        event.source === DiscoverySource.Mdns,
      timeoutMs: 20_000,
    });
    report({
      detail: `${discovered.addrs.length} addresses`,
      name: "mdns-discovery",
      passed: discovered.addrs.length > 0,
    });
  } finally {
    first.close();
    second.close();
    liveEndpoints.delete(first);
    liveEndpoints.delete(second);
  }
}

async function runCreateCloseCycles(
  report: SmokeReport,
  liveEndpoints: Set<Minip2p>
): Promise<void> {
  let cycles = 0;
  for (let index = 0; index < 10; index += 1) {
    const endpoint = createEndpoint(liveEndpoints);
    endpoint.close();
    liveEndpoints.delete(endpoint);
    cycles += 1;
    await Promise.resolve();
  }
  report({
    detail: `${cycles} clean lifetimes`,
    name: "create-close-cycles",
    passed: cycles === 10,
  });
}

function shortPeer(peerId: string): string {
  return peerId.length <= 12
    ? peerId
    : `${peerId.slice(0, 6)}…${peerId.slice(-6)}`;
}
