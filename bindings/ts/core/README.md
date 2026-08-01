# @minip2p/core

Platform-neutral TypeScript SDK for [minip2p](https://minip2p.com).

Applications normally install a platform package such as `@minip2p/react-native`, which provides the native backend and re-exports these public types. Adapter authors can implement the small contract from `@minip2p/core/backend`.

The API provides typed events, cancellable Promise operations, and `Stream` handles:

```ts
const path = await endpoint.connectAddr(remoteAddress);
await endpoint.waitPeerReady(path.peerId);
const rttMs = await endpoint.ping(path.peerId);

const stream = await endpoint.openStream(path.peerId, "/example/files/1");
stream.write(new Uint8Array([1, 2, 3]));
stream.closeWrite();
```

Use `endpoint.on("stream", handler)` to claim inbound streams. Operations accept `{ timeoutMs, signal }`; the default timeout is 65 seconds and `timeoutMs: 0` disables it.

Raw native unions and the `Minip2pBackend` adapter contract are available from `@minip2p/core/backend`.
