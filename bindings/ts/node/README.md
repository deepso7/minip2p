# @minip2p/node

Node.js bindings for [minip2p](https://minip2p.com), backed by a native [napi-rs](https://napi.rs/) addon. The package is ESM-only and requires Node.js 24 or newer.

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

`Minip2p.create()` binds and starts the endpoint synchronously. A started endpoint keeps the Node.js process alive until `close()` requests shutdown. Calls into the backend are synchronous; promise-returning operations such as `connectAddr()` and `openStream()` resolve from native events.

The Node binding accepts the same TCP, QUIC, circuit-relay, signed-discovery, and mDNS configuration as `@minip2p/react-native`.

The package is private until the platform-package publishing work lands. Build the local addon and run its suite with:

```bash
pnpm native:build
pnpm test
```
