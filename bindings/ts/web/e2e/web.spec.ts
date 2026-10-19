/* oxlint-disable func-style, no-await-in-loop, no-use-before-define -- Fixtures and in-page scripts read best as hoisted helpers and sequential loops. */

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { Minip2p as NativeNode, generateSecretKey } from "@minip2p/node";
import type { ConnectionCloseReason } from "@minip2p/node";
import { expect, test } from "@playwright/test";
import type { Browser, Page } from "@playwright/test";

import type * as Web from "../src/index.js";

declare global {
  interface Window {
    web: typeof Web;
    webReady?: boolean;
    node?: Web.Minip2p;
    sessionEnds: { closeCode?: number; fulfilled: boolean }[];
    closeReasons?: string[];
  }
}

const ECHO = "/minip2p/echo/1";
const TIMEOUT = { timeoutMs: 15_000 };

/** A native node listening on WebTransport and echoing every stream. */
function nativePeer(
  options: { secretKey?: Uint8Array; port?: number; relays?: string[] } = {}
) {
  const node = NativeNode.create({
    listen: [`/ip4/127.0.0.1/udp/${options.port ?? 0}/quic-v1/webtransport`],
    protocols: [ECHO],
    relays: options.relays ?? [],
    secretKey: options.secretKey ?? generateSecretKey(),
  });
  node.on("stream", (stream) => {
    void (async () => {
      try {
        for await (const chunk of stream) {
          await stream.write(chunk);
        }
        stream.closeWrite();
      } catch {
        // A reset echo stream simply ends.
      }
    })();
  });
  const closes: ConnectionCloseReason[] = [];
  node.on("connectionClosed", ({ reason }) => closes.push(reason));
  const [address] = node.listenAddrs();
  if (address === undefined || !address.includes("/webtransport/certhash/")) {
    throw new Error(
      `no WebTransport listen address: ${node.listenAddrs().join(", ")}`
    );
  }
  return { address, closes, node };
}

/** Opens the e2e page and waits for `@minip2p/web` to load. */
async function openPage(page: Page): Promise<void> {
  await page.goto("/");
  await page.waitForFunction(() => window.webReady === true);
}

test.afterEach(async ({ page }) => {
  await page.evaluate(async () => {
    await window.node?.close();
  });
});

test("connects, pings, waits for Identify and echoes a stream with FIN and a reset", async ({
  page,
}) => {
  const native = nativePeer();
  try {
    await openPage(page);
    const result = await page.evaluate(
      async ({ address, protocol, timeout }) => {
        const { Minip2p, generateSecretKey: key } = window.web;
        const node = Minip2p.create({
          protocols: [protocol],
          secretKey: key(),
        });
        window.node = node;
        const path = await node.connect(address, timeout);
        const ready = await node.waitPeerReady(path.peerId, timeout);
        const rtt = await node.ping(path.peerId, timeout);

        const stream = await node.openStream(path.peerId, protocol, timeout);
        await stream.write("hello over webtransport");
        stream.closeWrite();
        const bytes: number[] = [];
        for await (const chunk of stream) {
          bytes.push(...chunk);
        }

        const doomed = await node.openStream(path.peerId, protocol, timeout);
        await doomed.write("x");
        doomed.reset();
        let afterReset = "accepted";
        try {
          await doomed.write("y");
        } catch (error) {
          afterReset = error instanceof Error ? error.name : String(error);
        }
        return {
          afterReset,
          connected: node.connectedPeers(),
          echoed: new TextDecoder().decode(new Uint8Array(bytes)),
          path: path.path.kind,
          peer: path.peerId,
          protocols: ready.protocols,
          rtt,
        };
      },
      { address: native.address, protocol: ECHO, timeout: TIMEOUT }
    );

    expect(result.peer).toBe(native.node.peerId());
    expect(result.path).toBe("direct");
    expect(result.connected).toEqual([native.node.peerId()]);
    expect(result.protocols).toContain(ECHO);
    expect(result.rtt).toBeGreaterThanOrEqual(0);
    expect(result.echoed).toBe("hello over webtransport");
    // A reset stream takes no more writes.
    expect(result.afterReset).not.toBe("accepted");
  } finally {
    await native.node.close();
  }
});

test("a large transfer round-trips under backpressure", async ({ page }) => {
  const native = nativePeer();
  try {
    await openPage(page);
    const result = await page.evaluate(
      async ({ address, protocol, timeout }) => {
        const { Minip2p, generateSecretKey: key } = window.web;
        const node = Minip2p.create({
          protocols: [protocol],
          secretKey: key(),
        });
        window.node = node;
        const path = await node.connect(address, timeout);
        const stream = await node.openStream(path.peerId, protocol, timeout);
        // Well past every window on the way: the JS in-flight cap, the
        // client's send caps and both receive windows.
        const size = 8 * 1024 * 1024;
        const payload = Uint8Array.from({ length: size }, (_, i) => i % 251);
        const writing = (async () => {
          for (let offset = 0; offset < size; offset += 256 * 1024) {
            await stream.write(payload.subarray(offset, offset + 256 * 1024));
          }
          stream.closeWrite();
        })();
        let received = 0;
        let mismatch = -1;
        for await (const chunk of stream) {
          for (const [index, byte] of chunk.entries()) {
            if (mismatch < 0 && byte !== (received + index) % 251) {
              mismatch = received + index;
            }
          }
          received += chunk.byteLength;
        }
        await writing;
        return { mismatch, received, size };
      },
      { address: native.address, protocol: ECHO, timeout: TIMEOUT }
    );

    expect(result.mismatch).toBe(-1);
    expect(result.received).toBe(result.size);
  } finally {
    await native.node.close();
  }
});

test("closes are orderly both ways", async ({ page }) => {
  const native = nativePeer();
  try {
    await openPage(page);
    // The browser closes: the native side sees a clean remote close.
    await page.evaluate(
      async ({ address, timeout }) => {
        const { Minip2p, generateSecretKey: key } = window.web;
        const node = Minip2p.create({ secretKey: key() });
        await node.connect(address, timeout);
        await node.close();
      },
      { address: native.address, timeout: TIMEOUT }
    );
    await expect
      .poll(() => native.closes)
      .toEqual([{ code: 0n, kind: "remote" }]);

    // The native side closes: the browser's `closed` fulfils with code 0.
    const browserPeer = await page.evaluate(
      async ({ address, timeout }) => {
        const { Minip2p, generateSecretKey: key } = window.web;
        const node = Minip2p.create({ secretKey: key() });
        window.node = node;
        window.sessionEnds.length = 0;
        window.closeReasons = [];
        node.on("connectionClosed", ({ reason }) => {
          window.closeReasons?.push(reason.kind);
        });
        await node.connect(address, timeout);
        return node.peerId();
      },
      { address: native.address, timeout: TIMEOUT }
    );
    native.node.disconnect(browserPeer);
    await expect
      .poll(() => page.evaluate(() => window.closeReasons))
      .toEqual(["remote"]);
    await expect
      .poll(() => page.evaluate(() => window.sessionEnds))
      .toEqual([{ closeCode: 0, fulfilled: true }]);
  } finally {
    await native.node.close();
  }
});

test("reconnects to a restarted native node at the same certhash address", async ({
  page,
}) => {
  const secretKey = generateSecretKey();
  const first = nativePeer({ secretKey });
  const port = Number(
    /\/udp\/(?<port>\d+)\//u.exec(first.address)?.groups?.port
  );
  await openPage(page);
  const connect = async (address: string) =>
    await page.evaluate(
      async ({ target, timeout }) => {
        const { Minip2p, generateSecretKey: key } = window.web;
        window.node ??= Minip2p.create({ secretKey: key() });
        const path = await window.node.connect(target, timeout);
        return await window.node.ping(path.peerId, timeout);
      },
      { target: address, timeout: TIMEOUT }
    );

  try {
    await connect(first.address);
  } finally {
    await first.node.close();
  }
  await page.waitForFunction(() => window.node?.connectedPeers().length === 0);

  // Certificates derive from the key and period, so the address is unchanged.
  const second = nativePeer({ port, secretKey });
  try {
    expect(second.address).toBe(first.address);
    expect(await connect(first.address)).toBeGreaterThanOrEqual(0);
  } finally {
    await second.node.close();
  }
});

test("dials the relay-server example's WebTransport address and pings it", async ({
  page,
}) => {
  const relay = await startRelay();
  try {
    await openPage(page);
    const rtt = await page.evaluate(
      async ({ address, timeout }) => {
        const { Minip2p, generateSecretKey: key } = window.web;
        const node = Minip2p.create({ secretKey: key() });
        window.node = node;
        const path = await node.connect(address, timeout);
        return await node.ping(path.peerId, timeout);
      },
      { address: relay.address, timeout: TIMEOUT }
    );
    expect(rtt).toBeGreaterThanOrEqual(0);
  } finally {
    relay.process.kill();
  }
});

/**
 * Spawns `minip2p-relay --webtransport` and reads its WebTransport address
 * (what browsers dial) and its `quic-v1` address (what native nodes dial).
 */
async function startRelay(): Promise<{
  address: string;
  quic: string;
  process: ChildProcess;
}> {
  const binary = fileURLToPath(
    new URL("../../../../target/debug/minip2p-relay", import.meta.url)
  );
  const child = spawn(
    binary,
    ["--quic", "127.0.0.1:0", "--tcp", "127.0.0.1:0", "--webtransport"],
    { stdio: ["ignore", "pipe", "inherit"] }
  );
  if (child.stdout === null) {
    throw new Error("relay stdout is not piped");
  }
  const lines = createInterface({ input: child.stdout });
  let quic: string | undefined;
  for await (const line of lines) {
    quic ??= /^\[relay\] listening=(?<addr>.+\/quic-v1\/p2p\/.+)$/u.exec(line)
      ?.groups?.addr;
    const address = /^\[relay\] webtransport=(?<address>.+)$/u.exec(line)
      ?.groups?.address;
    if (address !== undefined && quic !== undefined) {
      // Keep draining its log so the relay never blocks on a full pipe.
      child.stdout.resume();
      return { address, process: child, quic };
    }
  }
  throw new Error("the relay exited before printing its addresses");
}

/** A UDP port nothing listens on: bound once, then released. */
async function deadUdpPort(): Promise<number> {
  const socket = createSocket("udp4");
  socket.bind(0, "127.0.0.1");
  await once(socket, "listening");
  const { port } = socket.address();
  socket.close();
  await once(socket, "close");
  return port;
}

/** Opens the e2e page in a fresh browser context: a second, separate node. */
async function openSecondPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext();
  const page = await context.newPage();
  await openPage(page);
  return page;
}

/** Closes a page from `openSecondPage`, with its node and context. */
async function closeSecondPage(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await window.node?.close();
  });
  await page.context().close();
}

/**
 * Starts a browser node on `page` that reserves on `relay` and echoes every
 * inbound stream; resolves to its peer ID once the reservation is held.
 */
async function reservingBrowser(page: Page, relay: string): Promise<string> {
  const peerId = await page.evaluate(
    ({ protocol, relayAddress }) => {
      const { Minip2p, generateSecretKey: key } = window.web;
      const node = Minip2p.create({
        protocols: [protocol],
        relays: [relayAddress],
        secretKey: key(),
      });
      window.node = node;
      node.on("stream", (stream) => {
        void (async () => {
          try {
            for await (const chunk of stream) {
              await stream.write(chunk);
            }
            stream.closeWrite();
          } catch {
            // A reset echo stream simply ends.
          }
        })();
      });
      return node.peerId();
    },
    { protocol: ECHO, relayAddress: relay }
  );
  await page.waitForFunction(
    () => window.node?.circuitAddress !== undefined,
    undefined,
    { timeout: 15_000 }
  );
  return peerId;
}

/**
 * Connects a new node on `page`, with `relays` configured, to `target` (a
 * peer ID, reached through the relays, or an address); echoes a message and
 * reports the path.
 */
async function connectAndEcho(
  page: Page,
  target: string,
  relays: string[]
): Promise<{ echoed: string; path: string }> {
  return await page.evaluate(
    async ({ protocol, relayAddrs, targetAddr, timeout }) => {
      const { Minip2p, generateSecretKey: key } = window.web;
      const node = Minip2p.create({
        protocols: [protocol],
        relays: relayAddrs,
        secretKey: key(),
      });
      window.node = node;
      const connected = await node.connect(targetAddr, timeout);
      const stream = await node.openStream(connected.peerId, protocol, timeout);
      await stream.write("echo me");
      stream.closeWrite();
      const bytes: number[] = [];
      for await (const chunk of stream) {
        bytes.push(...chunk);
      }
      return {
        echoed: new TextDecoder().decode(new Uint8Array(bytes)),
        path: connected.path.kind,
      };
    },
    { protocol: ECHO, relayAddrs: relays, targetAddr: target, timeout: TIMEOUT }
  );
}

test("a browser reserves on the relay and another browser echoes through its circuit", async ({
  browser,
  page,
}) => {
  const relay = await startRelay();
  const other = await openSecondPage(browser);
  try {
    await openPage(page);
    const holder = await reservingBrowser(page, relay.address);
    const result = await connectAndEcho(other, holder, [relay.address]);
    expect(result).toEqual({ echoed: "echo me", path: "relayed" });
  } finally {
    await closeSecondPage(other);
    relay.process.kill();
  }
});

test("a native peer dials a browser through its circuit", async ({ page }) => {
  const relay = await startRelay();
  // Relay only: the browser never starts DCUtR, so there is nothing to wait for.
  const native = NativeNode.create({
    forceRelay: true,
    protocols: [ECHO],
    relays: [relay.quic],
    secretKey: generateSecretKey(),
  });
  try {
    await openPage(page);
    const holder = await reservingBrowser(page, relay.address);
    const connected = await native.connect(holder, TIMEOUT);
    expect(connected.path.kind).toBe("relayed");
    const stream = await native.openStream(holder, ECHO, TIMEOUT);
    await stream.write("native to browser");
    stream.closeWrite();
    const chunks: Uint8Array[] = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    expect(Buffer.concat(chunks).toString()).toBe("native to browser");
  } finally {
    await native.close();
    relay.process.kill();
  }
});

test("with relays, a browser dials a native WebTransport address directly and falls back to the relay", async ({
  browser,
  page,
}) => {
  const relay = await startRelay();
  const native = nativePeer({ relays: [relay.quic] });
  const second = await openSecondPage(browser);
  try {
    await expect
      .poll(() => native.node.activeReservation() !== undefined, {
        timeout: 15_000,
      })
      .toBe(true);
    await openPage(page);

    const direct = await connectAndEcho(page, native.address, [relay.address]);
    expect(direct).toEqual({ echoed: "echo me", path: "direct" });

    // The same peer at a port nothing serves: only the relay leg can land.
    const unreachable = native.address.replace(
      /\/udp\/\d+\//u,
      `/udp/${await deadUdpPort()}/`
    );
    const relayed = await connectAndEcho(second, unreachable, [relay.address]);
    expect(relayed).toEqual({ echoed: "echo me", path: "relayed" });
  } finally {
    await closeSecondPage(second);
    await native.node.close();
    relay.process.kill();
  }
});
