/* oxlint-disable func-style, no-use-before-define, promise/avoid-new -- The real relay fixture bridges child-process readiness into the async test. */

import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";

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
});

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
