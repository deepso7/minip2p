# @minip2p/core

Promise-first, platform-neutral TypeScript SDK behavior for minip2p.

Applications normally install a platform package such as `@minip2p/react-native` or `@minip2p/node`; those packages bind the SDK to a native backend and re-export the public core types.

Adapter authors implement the deliberately small contract exported from `@minip2p/core/backend`. The core package never imports React Native, Node.js, UniFFI, napi-rs, or generated native code.

The public API uses named typed events, cancellable Promise operations, and `Stream` handles:

```ts
const path = await endpoint.connectAddr(remoteAddress);
await endpoint.waitPeerReady(path.peerId);
const rttMs = await endpoint.ping(path.peerId);
const stream = await endpoint.openStream(path.peerId, "/example/files/1");
stream.write(new Uint8Array([1, 2, 3]));
stream.closeWrite();
```

Use `endpoint.on("stream", handler)` to claim inbound streams. Catch-all event handlers receive only safe `inboundStream` metadata, never a live handle. Operations accept `{ timeoutMs, signal }`; the default timeout is 65 seconds and `timeoutMs: 0` disables it.

Raw native `{ tag, inner }` unions and the `Minip2pBackend` adapter contract are available only from `@minip2p/core/backend`.
