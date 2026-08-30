# @minip2p/node

The Node.js package for [minip2p](https://minip2p.com). It is ESM-only and requires Node.js 24 or newer.

```ts
import { Minip2p, generateSecretKey } from "@minip2p/node";

const endpoint = Minip2p.create({
  secretKey: generateSecretKey(),
  transports: {
    quic: { listen: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
    tcp: { listen: ["/ip4/127.0.0.1/tcp/0"] },
  },
});

console.log(endpoint.peerId(), endpoint.listenAddrs());
endpoint.close();
```

`Minip2p.create()` starts the endpoint. A running endpoint keeps the Node.js process alive until `close()` shuts it down. Promise-returning operations such as `connectAddr()` and `openStream()` resolve as their network work completes.

The Node binding accepts the same TCP, QUIC, circuit-relay, signed-discovery, and mDNS configuration as `@minip2p/react-native`.

## Development

Build the package from this repository and run its test suite with:

```bash
pnpm native:build
pnpm test
```
