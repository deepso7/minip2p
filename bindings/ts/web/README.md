# @minip2p/web

The browser package for [minip2p](https://minip2p.com): minip2p compiled to WebAssembly, dialing native nodes over libp2p WebTransport, with the same `@minip2p/core` API as `@minip2p/node`. It is ESM-only.

```ts
import { Minip2p, generateSecretKey } from "@minip2p/web";

const endpoint = Minip2p.create({
  protocols: ["/minip2p/echo/1"],
  secretKey: generateSecretKey(),
});

// A native node's WebTransport address, certhashes and peer ID included.
const path = await endpoint.connect(
  "/ip4/192.0.2.1/udp/4001/quic-v1/webtransport/certhash/uEi…/certhash/uEi…/p2p/12D3KooW…"
);
console.log(await endpoint.ping(path.peerId));
```

A native node serves browsers by listening on a `/…/quic-v1/webtransport` address beside (or instead of) its `/quic-v1` one; its `listenAddrs()` then include the full address to hand to the browser. The [browser example](https://github.com/deepso7/minip2p/tree/main/examples/web) runs this against `minip2p-peer`.

## Loading the wasm

- **`@minip2p/web`** loads its `.wasm` (resolved from `import.meta.url`, so bundlers emit it as an asset) with top-level `await`. Once the import resolves, `Minip2p.create` is synchronous, as in Node. Bundlers need an `es2022` target for the top-level `await`; Vite also needs `optimizeDeps.exclude: ["@minip2p/web"]` so pre-bundling keeps the package next to its `.wasm`.
- **`@minip2p/web/manual`** exports the same API plus `initMinip2p({ wasm })` and fetches nothing at import: serve the `.wasm` yourself (a CDN, a strict CSP) and pass a URL, a `Response`, its bytes or a compiled `WebAssembly.Module`. `Minip2p.create` throws until `initMinip2p` has resolved.

## What works in a browser

Dialing native nodes at `/webtransport/certhash` addresses, Identify, ping, custom protocol streams with backpressure, gossipsub, and relay reservations with circuits to and from other browsers and native nodes. The page must be a secure context (HTTPS or `localhost`). Chrome and Firefox are supported; Safari 26.4+ is best-effort.

`Minip2p.create` throws `InvalidConfigError`, with the reason, for what a browser cannot do:

| Option           | Why                                           |
| ---------------- | --------------------------------------------- |
| `listen`         | Browsers cannot listen.                       |
| `mdns`           | Browsers have no multicast sockets.           |
| `discovery`      | Signed discovery is not in the browser build. |
| `autonatServers` | Browsers cannot be dialed back.               |

Other limits:

- Only WebTransport addresses with certhashes dial; a `/quic-v1` or `/tcp` candidate fails as a candidate. There is no CA-certificate mode.
- `listenAddrs()` is always empty (a reservation is `circuitAddress`), `knownPeers()` is empty and `reachability()` stays `unknown`.
- `close()` closes every session at once with WebTransport's close capsule; its timeout is ignored. `setActive()` is ignored as well: the page's own timers drive the endpoint.
- A page on a public origin that dials a private address may trigger Chrome's Local Network Access prompt.
- A trapped wasm module (a Rust panic) fails the endpoint with `DriverFailedError`; its WebTransport sessions are closed from TypeScript, `close()` still resolves (`Failed`), and later calls throw `ClosedError`. Create a new endpoint to carry on.

## Relays

With `relays` (WebTransport addresses with certhashes) the browser holds a reservation on the relay and is reachable at its `/p2p-circuit` address (`node.circuitAddress`), from other browsers and from native nodes. Connecting by peer ID goes through the relay; connecting to a native peer's WebTransport address races the direct dial against the relay leg, so the path is `direct` or `relayed`, never `punched`: browsers never hole punch. `forceRelay: true` skips the direct dial. `activeReservation()` reports the reservation.

## Development

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.128
pnpm wasm:build    # crates/web → wasm/
pnpm test          # unit tests (runs wasm:build first)
pnpm test:e2e      # Playwright: Chromium and Firefox against native nodes
```

`wasm:build` regenerates `wasm/minip2p_web.js` and its `.d.ts`, the checked-in wasm-bindgen glue; commit them, CI fails when they are stale. The `.wasm` is a build output. The e2e suite needs `pnpm build:bindings`, the Node addon (`pnpm --filter @minip2p/node native:build`), the relay-server example (`cargo build -p minip2p-relay-server-example`) and `npx playwright install chromium firefox`.

`src/io.ts` is `JsIo`, the `WebTransportIo` seam the Rust client drives over the browser's `WebTransport`; [`crates/web`](https://github.com/deepso7/minip2p/tree/main/crates/web) is the Rust side.

The release workflow publishes the package with npm trusted publishing. Before the first release that includes it, an owner of the `@minip2p` scope runs `scripts/npm-trusted-publisher-web.sh` once to register the publisher.
