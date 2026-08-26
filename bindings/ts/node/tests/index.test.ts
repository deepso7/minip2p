/* oxlint-disable func-style, no-await-in-loop, no-use-before-define, promise/avoid-new -- The real network fixtures bridge process readiness and bounded polling into async tests. */

import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import * as coreSdk from "@minip2p/core";
import { describe, expect, test } from "vitest";

import * as nodeSdk from "../src/index.js";

describe("@minip2p/node", () => {
  test("re-exports every runtime SDK value by identity", () => {
    for (const [name, value] of Object.entries(coreSdk)) {
      expect(nodeSdk, `missing @minip2p/core export ${name}`).toHaveProperty(
        name
      );
      expect(Reflect.get(nodeSdk, name)).toBe(value);
    }
  });

  test("creates, starts, and closes a QUIC endpoint", () => {
    const endpoint = nodeSdk.Minip2p.create({
      secretKey: nodeSdk.generateSecretKey(),
      transports: {
        quic: { listen: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
      },
    });

    expect(endpoint.peerId()).toMatch(/^12D3Koo/u);
    expect(endpoint.listenAddrs()).toHaveLength(1);
    expect(endpoint.isRunning()).toBe(true);

    endpoint.close();
    expect(endpoint.isRunning()).toBe(false);
  });

  test("reserves the configured signed-discovery topic", () => {
    const topic = "node-discovery";
    const endpoint = nodeSdk.Minip2p.create({
      discovery: {
        autoDial: false,
        beaconIntervalMs: 1234,
        peerTtlMs: 5678,
        topic,
      },
      mdns: {
        autoDial: false,
        enableIpv6: false,
        interfaceRefreshMs: 111,
        maxAnnouncedAddrs: 12,
        maxPacketBytes: 1300,
        queryIntervalMs: 222,
        socketPollIntervalMs: 333,
        ttlMs: 444,
      },
      secretKey: nodeSdk.generateSecretKey(),
      transports: {
        quic: { listen: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
      },
    });

    try {
      expect(() => endpoint.unsubscribe(topic)).toThrow(
        "cannot unsubscribe from the discovery topic while discovery is enabled"
      );
    } finally {
      endpoint.close();
    }
  });

  test("passes mDNS limits through native validation", () => {
    expect(() =>
      nodeSdk.Minip2p.create({
        mdns: { maxPacketBytes: 511 },
        secretKey: nodeSdk.generateSecretKey(),
        transports: {
          quic: { listen: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
        },
      })
    ).toThrow("mDNS maximum packet size must be between 512 and 4096 bytes");
  });

  test("two endpoints exchange stream data over QUIC loopback", async () => {
    const protocol = "/minip2p/node-loopback/1";
    const createEndpoint = () =>
      nodeSdk.Minip2p.create({
        protocols: [protocol],
        secretKey: nodeSdk.generateSecretKey(),
        transports: {
          quic: { listen: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
        },
      });
    const a = createEndpoint();
    const b = createEndpoint();

    try {
      await a.connectAddr(b.listenAddrs()[0], { timeoutMs: 10_000 });
      await Promise.all([
        a.waitPeerReady(b.peerId(), { timeoutMs: 10_000 }),
        b.waitPeerReady(a.peerId(), { timeoutMs: 10_000 }),
      ]);

      const publicKey = a.peerInfo(b.peerId())?.publicKey;
      expect(publicKey).toBeInstanceOf(ArrayBuffer);
      if (!(publicKey instanceof ArrayBuffer)) {
        throw new TypeError(
          "Identify did not return an ArrayBuffer public key"
        );
      }
      expect(publicKey.byteLength).toBe(36);
      expect([...new Uint8Array(publicKey).subarray(0, 4)]).toEqual([
        0x08, 0x01, 0x12, 0x20,
      ]);

      const inboundPromise = b.once("stream", { timeoutMs: 10_000 });
      const outbound = await a.openStream(b.peerId(), protocol, {
        timeoutMs: 10_000,
      });
      const inbound = await inboundPromise;

      outbound.write("hello from a");
      expect(new TextDecoder().decode(await inbound.read())).toBe(
        "hello from a"
      );

      inbound.write("hello from b");
      expect(new TextDecoder().decode(await outbound.read())).toBe(
        "hello from b"
      );
    } finally {
      a.close();
      b.close();
    }
  }, 15_000);

  test("two endpoints exchange stream data over TCP loopback", async () => {
    const protocol = "/minip2p/node-tcp-loopback/1";
    const createEndpoint = () =>
      nodeSdk.Minip2p.create({
        protocols: [protocol],
        secretKey: nodeSdk.generateSecretKey(),
        transports: {
          tcp: { listen: ["/ip4/127.0.0.1/tcp/0"] },
        },
      });
    const a = createEndpoint();
    const b = createEndpoint();

    try {
      await a.connectAddr(b.listenAddrs()[0], { timeoutMs: 10_000 });
      await Promise.all([
        a.waitPeerReady(b.peerId(), { timeoutMs: 10_000 }),
        b.waitPeerReady(a.peerId(), { timeoutMs: 10_000 }),
      ]);

      const inboundPromise = b.once("stream", { timeoutMs: 10_000 });
      const outbound = await a.openStream(b.peerId(), protocol, {
        timeoutMs: 10_000,
      });
      const inbound = await inboundPromise;

      outbound.write("hello over tcp");
      expect(new TextDecoder().decode(await inbound.read())).toBe(
        "hello over tcp"
      );
    } finally {
      a.close();
      b.close();
    }
  }, 15_000);

  test("two endpoints establish a circuit-relay path", async () => {
    const relay = await startRelay();
    const createEndpoint = () =>
      nodeSdk.Minip2p.create({
        forceRelay: true,
        relays: [relay.address],
        secretKey: nodeSdk.generateSecretKey(),
        transports: {
          quic: { listen: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
        },
      });
    const a = createEndpoint();
    const b = createEndpoint();

    try {
      await Promise.all([
        a.once("relayReserved", { timeoutMs: 10_000 }),
        b.once("relayReserved", { timeoutMs: 10_000 }),
      ]);
      const result = await a.connect(b.peerId(), { timeoutMs: 10_000 });

      expect(result.path).toEqual({
        kind: "relayed",
        relayPeerId: b.activeReservation()?.relayPeerId,
      });
    } finally {
      a.close();
      b.close();
      await relay.close();
    }
  }, 20_000);

  test("drains a native event flood without losing messages", async () => {
    const deadline = Date.now() + 25_000;
    const topic = "node-event-flood";
    const a = createFloodEndpoint();
    const b = createFloodEndpoint();
    let received = 0;
    b.on("message", () => {
      received += 1;
    });
    a.subscribe(topic);
    b.subscribe(topic);

    try {
      const subscribed = a.once("peerSubscribed", {
        timeoutMs: remainingMs(deadline),
      });
      await Promise.all([
        a.connectAddr(b.listenAddrs()[0], {
          timeoutMs: remainingMs(deadline),
        }),
        a.waitPeerReady(b.peerId(), { timeoutMs: remainingMs(deadline) }),
        b.waitPeerReady(a.peerId(), { timeoutMs: remainingMs(deadline) }),
        subscribed,
      ]);

      const messageCount = 512;
      for (let index = 0; index < messageCount; index += 1) {
        await publishWithBackpressure(
          a,
          topic,
          new TextEncoder().encode(index.toString()),
          deadline
        );
      }
      for (;;) {
        if (received === messageCount || Date.now() >= deadline) {
          break;
        }
        await delay(Math.min(10, remainingMs(deadline)));
      }

      expect(received).toBe(messageCount);
    } finally {
      a.close();
      b.close();
    }
  }, 30_000);
});

function createFloodEndpoint(): nodeSdk.Minip2p {
  return nodeSdk.Minip2p.create({
    pubsubRouter: coreSdk.PubsubRouter.Floodsub,
    secretKey: nodeSdk.generateSecretKey(),
    transports: {
      quic: { listen: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
    },
  });
}

async function publishWithBackpressure(
  endpoint: nodeSdk.Minip2p,
  topic: string,
  data: Uint8Array,
  deadline: number
): Promise<void> {
  for (;;) {
    try {
      endpoint.publish(topic, data);
      return;
    } catch (error) {
      if (
        !(error instanceof Error) ||
        error.message !== "outbound backpressure"
      ) {
        throw error;
      }
      if (Date.now() >= deadline) {
        throw new Error(
          "Timed out publishing flood messages under outbound backpressure",
          { cause: error }
        );
      }
      await delay(Math.min(1, remainingMs(deadline)));
    }
  }
}

function remainingMs(deadline: number): number {
  return Math.max(1, deadline - Date.now());
}

async function startRelay(): Promise<{
  readonly address: string;
  readonly close: () => Promise<void>;
}> {
  const repository = path.resolve(import.meta.dirname, "../../../..");
  const executable = path.resolve(
    repository,
    "target/debug",
    process.platform === "win32" ? "minip2p-relay.exe" : "minip2p-relay"
  );
  const child = spawn(
    executable,
    ["--quic", "127.0.0.1:0", "--tcp", "127.0.0.1:0"],
    { stdio: ["ignore", "pipe", "pipe"] }
  );
  let output = "";
  child.stdout.setEncoding("utf-8");
  child.stderr.setEncoding("utf-8");
  const address = await new Promise<string>((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`Timed out waiting for relay address:\n${output}`));
    }, 10_000);
    const inspect = (chunk: string) => {
      output += chunk;
      const match = output.match(
        /\[relay\] listening=(?<address>\/ip4\/127\.0\.0\.1\/udp\/\d+\/quic-v1\/p2p\/[^\s]+)/u
      );
      if (match?.groups?.address !== undefined) {
        clearTimeout(timeout);
        resolve(match.groups.address);
      }
    };
    child.stdout.on("data", inspect);
    child.stderr.on("data", inspect);
    child.once("error", reject);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`Relay exited with code ${code}:\n${output}`));
    });
  });
  return {
    address,
    close: async () => {
      if (child.exitCode === null) {
        child.kill();
        await once(child, "exit");
      }
    },
  };
}
