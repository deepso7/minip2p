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
});
