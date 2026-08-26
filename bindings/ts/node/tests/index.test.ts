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

    expect(endpoint.peerId()).toMatch(/^12D3Koo/);
    expect(endpoint.listenAddrs()).toHaveLength(1);
    expect(endpoint.isRunning()).toBe(true);

    endpoint.close();
    expect(endpoint.isRunning()).toBe(false);
  });
});
