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

Streams are async iterables. Iteration preserves chunk order. A remote write half-close or local shutdown ends the loop quietly. A remote reset, peer disconnect, or driver failure rejects the iterator with its terminal error:

```ts
for await (const chunk of stream) {
  process(chunk);
}
```

`endpoint.events()` returns an async iterable of endpoint events. Each iterator has a bounded, drop-oldest buffer. It reports dropped events in-band as `queueOverflow` events. The default cap is 4096; pass `bufferCap` to change it or `signal` to end iteration on abort.

```ts
for await (const event of endpoint.events({ signal })) {
  if (event.type === "peerReady") {
    console.log(event.peerId);
  }
}
```

Use `endpoint.on("stream", handler)` to claim inbound streams. Operations accept `{ timeoutMs, signal }`; the default timeout is 65 seconds and `timeoutMs: 0` disables it. Both endpoints and streams implement `Symbol.dispose`, including the fallback used by `await using`; neither implements `Symbol.asyncDispose`.

Raw native unions and the `Minip2pBackend` adapter contract are available from `@minip2p/core/backend`.
