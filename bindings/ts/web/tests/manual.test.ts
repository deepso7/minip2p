import { readFile } from "node:fs/promises";

import { afterEach, expect, test, vi } from "vitest";

// The real wasm module (`pnpm wasm:build`), instantiated in Node.
const wasmBytes = async (): Promise<Uint8Array<ArrayBuffer>> =>
  new Uint8Array(
    await readFile(new URL("../wasm/minip2p_web_bg.wasm", import.meta.url))
  );

afterEach(() => {
  vi.unstubAllGlobals();
});

test("the manual entry loads nothing at import, and initMinip2p({ wasm }) loads the given bytes", async () => {
  const fetch = vi.fn(() =>
    Promise.resolve(new Response("missing", { status: 404 }))
  );
  vi.stubGlobal("fetch", fetch);

  const web = await import("../src/manual.js");
  expect(fetch).not.toHaveBeenCalled();
  const secretKey = new Uint8Array(32).fill(1);
  expect(() => web.Minip2p.create({ secretKey })).toThrow(/initMinip2p/u);

  // The default `.wasm` URL 404s; a host-supplied module still loads.
  await expect(web.initMinip2p()).rejects.toThrow();
  expect(fetch).toHaveBeenCalledTimes(1);
  await web.initMinip2p({ wasm: await wasmBytes() });

  const endpoint = web.Minip2p.create({ secretKey });
  expect(endpoint.peerId()).toMatch(/^12D3KooW/u);
  expect(endpoint.peerId()).toBe(web.peerIdFromSecretKey(secretKey));
  expect(web.generateSecretKey()).toHaveLength(32);
  expect(endpoint.listenAddrs()).toEqual([]);
  await expect(endpoint.close()).resolves.toMatchObject({
    outcome: "Drained",
    reason: "close",
  });

  // The browser limits come back as typed SDK errors.
  expect(() =>
    web.Minip2p.create({ listen: ["/ip4/0.0.0.0/udp/0/quic-v1"], secretKey })
  ).toThrow(web.InvalidConfigError);
  expect(() => web.Minip2p.create({ mdns: true, secretKey })).toThrow(
    /multicast/u
  );
});

test("initMinip2p({ wasm }) takes a promised URL", async () => {
  vi.resetModules();
  const url = "https://cdn.example/minip2p_web_bg.wasm";
  const bytes = await wasmBytes();
  const fetch = vi.fn((input: unknown) =>
    Promise.resolve(
      String(input) === url
        ? new Response(bytes, {
            headers: { "Content-Type": "application/wasm" },
          })
        : new Response("missing", { status: 404 })
    )
  );
  vi.stubGlobal("fetch", fetch);

  const web = await import("../src/manual.js");
  await web.initMinip2p({ wasm: Promise.resolve(new URL(url)) });

  expect(fetch).toHaveBeenCalledTimes(1);
  expect(web.generateSecretKey()).toHaveLength(32);
});
