# minip2p-web

The wasm-bindgen shell behind [`@minip2p/web`](../../bindings/ts/web): minip2p compiled for `wasm32-unknown-unknown`, dialing native nodes over libp2p WebTransport. Not published to crates.io; the npm package ships its `.wasm`.

Two layers:

- **`Host`** is the browser endpoint: a `PortableEndpoint` over any `Transport` wrapped in a `CircuitTransport` (relay reservations and circuits through `relay`, with `dcutr = false`), with ffi-core's thread-free host core (`EventCarry`, the stream writer, the `P2pEvent` model). It has the commands, errors and event stream of ffi-core's std `P2pEndpoint`, but no thread: its owner samples time and calls `pump`. It never touches wasm, so `cargo test -p minip2p-web` runs it natively over an in-memory transport.
- **`WebEndpoint`** (wasm32 only) is the JavaScript class, with the same surface as the Node addon's `NodeEndpoint` so both TypeScript adapters share `@minip2p/core/serde-backend`. It wraps `Host<WebTransportClient<JsIo, WebEntropy>>`, where `JsIo` is the TypeScript `WebTransportIo` (`bindings/ts/web/src/io.ts`).

## Runtime

- **Pump.** No async and no thread. The TypeScript owner pumps after each call and each `JsIo` event (one coalesced `queueMicrotask`), polls up to a bounded number of rounds before yielding with `setTimeout(0)`, and re-arms one `setTimeout` for the delay `pump` returns.
- **Time** is `performance.now()` (clamped so it never runs backwards) and `Date.now()`. std's clock is never compiled in: `Instant` panics on wasm32.
- **Entropy** is `crypto.getRandomValues`, through getrandom's `wasm_js` backend.
- **Panics** abort the instance (`WebAssembly.RuntimeError`). The adapter fails the endpoint with `DriverFailedError`, and later calls throw `ClosedError`.
- **Values** cross in ffi-core's serde shape, with every `u64` a `bigint` and an absent value `null`; errors are JS `Error`s tagged with `code`, `detail` and `capability`, as the Node addon throws them.

## Browser limits

The constructor rejects, with `InvalidConfig` and a reason, what a browser cannot run: `listen`, `mdns`, `discovery`, `autonatServers`, and `forceRelay` without `relays`. With relays the host always reserves (`ReservationPolicy::Always`) and never hole punches (`NatConfig::dcutr = false`): a connect to a native peer races the direct dial against the relay leg and settles `Direct` or `Relayed`. Only `/…/quic-v1/webtransport[/certhash/…]/p2p/…` addresses dial (without a certhash, the browser verifies a CA-signed certificate); anything else fails as a connect candidate. `close` closes every session at once (`WebTransport.close()` sends the close capsule), so its timeout is ignored, and `setActive` is ignored too: there is no background driver, only the page's timers.

## Building

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.128   # matches the pinned crate
pnpm --filter @minip2p/web wasm:build                # cargo build + wasm-bindgen
```

The build uses the workspace's `wasm-release` profile (`opt-level = "z"`, LTO, one codegen unit, `panic = "abort"`) and drops the module's `name` section. That section holds Rust function names and takes 62% of the raw bytes. `MINIP2P_WASM_NAMES=1` keeps it, for readable stack traces or `twiggy` profiling. `just check-wasm` lints the crate for wasm32.

Sizes of `minip2p_web_bg.wasm` (gzip `-9`, brotli `11`):

| Build                           | Raw       | gzip    | brotli  |
| ------------------------------- | --------- | ------- | ------- |
| default (`pubsub`)              | 1,438,574 | 409,111 | 308,935 |
| `--no-default-features`         | 1,242,962 | 361,525 | 274,749 |
| default, `MINIP2P_WASM_NAMES=1` | 3,813,658 | 585,219 | 404,338 |

The default `pubsub` feature compiles in Gossipsub. Without it (`cargo build -p minip2p-web --no-default-features …`, then `wasm-bindgen` as `bindings/ts/web/scripts/build-wasm.mjs` runs it), the generated JavaScript glue is the same, `subscribe`, `unsubscribe` and `publish` refuse with `NotPermitted`, and `allowUnsigned` is rejected as `InvalidConfig`. That build suits apps that use only streams and relays. The published `@minip2p/web` package keeps `pubsub`.

Most of the remaining code is generic collection code specialised for each key and value type (`BTreeMap`/`BTreeSet`, about 600 KB raw). Running `wasm-opt -Oz` (binaryen 132) cuts the raw size by 12% but grows the brotli size by 12%, so the build does not run it.
