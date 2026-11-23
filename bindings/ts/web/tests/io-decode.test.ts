import { readFile } from "node:fs/promises";

import { resolveEndpointConfig } from "@minip2p/core/backend";
import { beforeAll, describe, expect, test } from "vitest";

import type { IoEvent } from "../src/io.js";
import init, { WebEndpoint } from "../wasm/minip2p_web.js";

/** One of every `IoEvent` kind, so a new kind must be added here. */
const everyEvent = {
  data: { bytes: new Uint8Array([1, 2]), kind: "data", stream: 7 },
  fin: { kind: "fin", stream: 7 },
  incomingStream: { kind: "incomingStream", session: 9, stream: 7 },
  reset: { code: 1, kind: "reset", stream: 7 },
  sessionClosed: { code: 0, kind: "sessionClosed", reason: "", session: 9 },
  sessionFailed: { kind: "sessionFailed", reason: "gone", session: 9 },
  sessionReady: { kind: "sessionReady", session: 9 },
  stopSending: { code: 1, kind: "stopSending", stream: 7 },
  streamOpened: { kind: "streamOpened", stream: 7 },
  writeClosed: { kind: "writeClosed", stream: 7 },
  writeCompleted: { bytes: 2, kind: "writeCompleted", stream: 7 },
} satisfies { [Kind in IoEvent["kind"]]: Extract<IoEvent, { kind: Kind }> };

/**
 * A real wasm `WebEndpoint` over an I/O whose `pollEvent` hands back
 * `events`, pumped once.
 */
const pumpWith = (events: readonly unknown[]) => {
  const queue = [...events];
  const io = {
    close: () => {},
    closeWrite: () => {},
    connect: () => 1,
    grantRead: () => {},
    openStream: () => 1,
    pollEvent: () => queue.shift(),
    reset: () => {},
    stop: () => {},
    write: () => 0,
  };
  const secretKey = new Uint8Array(32).fill(1);
  const endpoint = new WebEndpoint(
    secretKey,
    resolveEndpointConfig({ secretKey }),
    io
  );
  endpoint.start(() => {});
  endpoint.pump();
  const drained: unknown[] = endpoint.drainEvents(64);
  const result = {
    events: drained,
    left: queue.length,
    running: endpoint.isRunning(),
  };
  endpoint.free();
  return result;
};

beforeAll(async () => {
  await init({
    module_or_path: await readFile(
      new URL("../wasm/minip2p_web_bg.wasm", import.meta.url)
    ),
  });
});

describe("JsIo events crossing into Rust", () => {
  test.each(Object.values(everyEvent))(
    "a $kind event decodes",
    (event: IoEvent) => {
      expect(pumpWith([event])).toEqual({ events: [], left: 0, running: true });
    }
  );

  test("a malformed event fails the endpoint, naming its kind and the decode error", () => {
    const { running, events } = pumpWith([{ kind: "data", stream: 7 }]);
    expect(running).toBe(false);
    expect(events[0]).toMatchObject({
      inner: {
        detail: expect.stringMatching(/`data` event.*missing field `bytes`/u),
        kind: "Transport",
      },
      tag: "DriverFailed",
    });
  });
});
