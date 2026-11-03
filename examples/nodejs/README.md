# Node.js ping example

Run two peers locally with `@minip2p/node`. The listener accepts QUIC and TCP connections. The client connects using the supplied address, waits for Identify, measures a Ping round-trip time, and closes.

## Setup

Use Node.js 24 or newer and the repository's pnpm version. From the repository root:

```bash
pnpm install --frozen-lockfile
pnpm --filter @minip2p/node native:build
pnpm exec turbo run build --filter=@minip2p/node
cd examples/nodejs
```

The native build requires the repository's Rust toolchain and C/C++ build tools for QUIC.

## Run

Start the listener:

```bash
pnpm start
```

It prints two complete multiaddresses, including the peer ID. Ports are assigned automatically:

```text
/ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooW...
/ip4/127.0.0.1/tcp/54322/p2p/12D3KooW...
```

In another terminal, change to `examples/nodejs` and pass one of the printed addresses:

```bash
pnpm run ping /ip4/127.0.0.1/udp/54321/quic-v1/p2p/12D3KooW...
```

Replace the entire address above with the listener's output. Use its TCP address to try TCP. The client prints the connected peer and Ping time, then exits. The connection wait times out after 10 seconds; the Identify wait uses `waitPeerReady`'s default, which allows the full Identify deadline (30 seconds by default); Ping times out after 5 seconds.

Press Ctrl+C in the listener terminal to close its endpoint and exit.

Both peers generate a fresh identity on every run. The listener binds to loopback, so only peers on the same machine can connect.
