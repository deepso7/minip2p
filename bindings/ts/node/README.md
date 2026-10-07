# @minip2p/node

The Node.js package for [minip2p](https://minip2p.com). It is ESM-only and requires Node.js 24 or newer.

```ts
import { Minip2p, generateSecretKey } from "@minip2p/node";

const endpoint = Minip2p.create({
  secretKey: generateSecretKey(),
  listen: ["/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"],
});

console.log(endpoint.peerId(), endpoint.listenAddrs());
endpoint.close();
```

`Minip2p.create()` starts the endpoint. A running endpoint keeps the Node.js process alive until `close()` shuts it down. Promise-returning operations such as `connect()` and `openStream()` resolve as their network work completes.

The Node binding accepts the same TCP, QUIC, circuit-relay, signed-discovery, and mDNS configuration as `@minip2p/react-native`.

For a runnable two-peer example, see the [Node.js ping example](https://github.com/deepso7/minip2p/tree/main/examples/nodejs).

## Development

Build the package from this repository and run its test suite with:

```bash
pnpm native:build
pnpm test
```

`native:build` also regenerates `src/addon.d.ts`, the checked-in declarations of the native addon. Its header (`addon-header.d.ts.txt`) imports the value types from `src/native-shape.ts`, which derives each one from the SDK's backend types. Commit the regenerated file; CI fails when it is stale.
