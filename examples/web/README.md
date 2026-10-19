# Browser example

A Vite page running `@minip2p/web`: it dials a native minip2p node over libp2p WebTransport, waits for Identify, pings it, and echoes a message over a custom protocol stream.

## Setup

From the repository root, with the repository's pnpm and Rust toolchains:

```bash
pnpm install --frozen-lockfile
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.128
pnpm --filter @minip2p/web wasm:build
```

## The native peer

Run [`minip2p-peer`](../peer/README.md) listening on WebTransport. It serves the `/minip2p/echo/1` protocol this page uses:

```console
$ cargo run -p minip2p-peer -- listen --listen /ip4/127.0.0.1/udp/4001/quic-v1/webtransport
[listen] bound=/ip4/127.0.0.1/udp/4001/quic-v1/webtransport/certhash/uEi…/certhash/uEi…/p2p/12D3KooW…
```

The address carries the hashes of the node's self-signed certificates, which the browser trusts instead of a CA. They derive from the node's key and the current 13-day certificate period, so pass `--key <path>` to keep the address across restarts.

## The page

```bash
cd examples/web
pnpm dev
```

Open the printed `http://localhost:5173/`, paste the whole `bound=` address, and press the button:

```text
browser peer 12D3KooW…
connected to 12D3KooW… (direct)
identified: /ipfs/id/1.0.0, /ipfs/ping/1.0.0, /minip2p/echo/1, …
ping 1 ms
echo: hello from the browser
```

Serve the page from `localhost` (or HTTPS): WebTransport needs a secure context. A page on a public origin that dials a private address may trigger Chrome's Local Network Access prompt.

`vite.config.ts` shows the two settings a Vite app needs: `build.target: "es2022"` for the package's top-level `await`, and `optimizeDeps.exclude` so pre-bundling keeps the package next to its `.wasm`.
